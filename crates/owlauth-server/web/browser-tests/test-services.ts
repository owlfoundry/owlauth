import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { resolve, sep } from "node:path";

import { chromium, firefox } from "@playwright/test";

import { BrowserEvidence, type BrowserEvidenceSnapshot } from "./browser-evidence";

const PROVIDER_CLIENT_ID = "owlauth-browser-e2e";
const PROVIDER_CLIENT_SECRET = "controlled-provider-secret";
const PROVIDER_KID = "controlled-rsa-1";
const MAX_BODY_BYTES = 64 * 1024;

interface AuthorizationGrant {
  readonly challenge: string;
  readonly clientId: string;
  readonly nonce: string;
  readonly redirectUri: string;
}

interface PendingBackendLogin {
  readonly applicationId: string;
  readonly expectedClaimsRevision: number;
  readonly otherProjectId: string;
  readonly projectId: string;
  readonly publishableKey: string;
  readonly redirectUri: string;
  readonly runtimeBase: string;
  readonly verifier: string;
}

interface CredentialDocument {
  readonly access_token: string;
  readonly application_id: string;
  readonly project_id: string;
  readonly projection_revision: number;
  readonly refresh_generation: number;
  readonly refresh_token: string;
  readonly session_id: string;
  readonly user_id: string;
}

interface BackendSession {
  credentials: CredentialDocument;
  readonly applicationId: string;
  readonly claimsVerified: boolean;
  readonly crossProjectRejected: boolean;
  readonly malformedRejected: boolean;
  readonly projectId: string;
  readonly publishableKey: string;
  readonly runtimeBase: string;
}

interface BrowserDriverResult {
  readonly callbackUrl: string;
  readonly evidence: BrowserEvidenceSnapshot;
  readonly runId: string;
}

export async function typescriptSdkArtifactDigest(repository: string): Promise<string> {
  const root = resolve(repository, "sdks/typescript/dist");
  const hash = createHash("sha256");

  async function visit(directory: string, prefix: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const relative = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isDirectory()) {
        await visit(resolve(directory, entry.name), relative);
      } else if (entry.isFile()) {
        const content = await readFile(resolve(directory, entry.name));
        hash.update(`${relative}\0${String(content.byteLength)}\0`);
        hash.update(content);
      } else {
        throw new Error(`unsupported TypeScript SDK artifact entry: ${relative}`);
      }
    }
  }

  await visit(root, "");
  return hash.digest("hex");
}

export interface ControlledServices {
  readonly applicationOrigin: string;
  readonly browserDriverToken: string;
  readonly browserDriverUrl: string;
  readonly providerClientId: string;
  readonly providerClientSecret: string;
  readonly providerOrigin: string;
  close(): Promise<void>;
}

export async function startControlledServices(
  repository: string,
  providerPort: number,
  applicationPort: number,
  runtimePort: number,
): Promise<ControlledServices> {
  // Keep browser cookie sites distinct from Runtime's 127.0.0.1 host. Cookies do not
  // honor port boundaries, so reusing that host would leak Runtime cookies to the
  // controlled provider and Application despite their different origins.
  const providerBase = `http://[::1]:${String(providerPort)}`;
  const providerIssuer = `${providerBase}/`;
  const applicationOrigin = `http://localhost:${String(applicationPort)}`;
  const runtimeOrigin = `http://127.0.0.1:${String(runtimePort)}`;
  const browserDriverToken = opaque(32);
  const provider = createControlledProvider(providerBase, providerIssuer);
  const application = createApplicationServer(
    repository,
    applicationOrigin,
    browserDriverToken,
    runtimeOrigin,
  );
  await Promise.all([
    listen(provider, providerPort, "::1"),
    listen(application, applicationPort, "localhost"),
  ]);
  return {
    applicationOrigin,
    browserDriverToken,
    browserDriverUrl: `${applicationOrigin}/sdk/browser-driver`,
    providerClientId: PROVIDER_CLIENT_ID,
    providerClientSecret: PROVIDER_CLIENT_SECRET,
    providerOrigin: providerIssuer,
    async close() {
      await Promise.all([close(provider), close(application)]);
    },
  };
}

function createControlledProvider(origin: string, issuer: string) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const publicJwk = publicKey.export({ format: "jwk" });
  const grants = new Map<string, AuthorizationGrant>();
  let authorizationRequests = 0;
  let tokenRequests = 0;

  return createServer((request, response) => {
    void (async () => {
      try {
        const url = requestUrl(request, origin);
        if (request.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
          json(response, 200, {
            issuer,
            authorization_endpoint: `${origin}/authorize`,
            token_endpoint: `${origin}/token`,
            jwks_uri: `${origin}/jwks`,
            response_types_supported: ["code"],
            response_modes_supported: ["query"],
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: ["RS256"],
            scopes_supported: ["openid", "profile"],
            code_challenge_methods_supported: ["S256"],
          });
          return;
        }
        if (request.method === "GET" && url.pathname === "/jwks") {
          json(response, 200, {
            keys: [
              {
                alg: "RS256",
                e: publicJwk.e,
                kid: PROVIDER_KID,
                kty: "RSA",
                n: publicJwk.n,
                use: "sig",
              },
            ],
          });
          return;
        }
        if (request.method === "GET" && url.pathname === "/__e2e/request-counts") {
          json(response, 200, {
            authorization_requests: authorizationRequests,
            token_requests: tokenRequests,
          });
          return;
        }
        if (request.method === "GET" && url.pathname === "/authorize") {
          authorizationRequests += 1;
          const parameters = requiredParameters(url, [
            "client_id",
            "code_challenge",
            "code_challenge_method",
            "nonce",
            "redirect_uri",
            "response_mode",
            "response_type",
            "scope",
            "state",
          ]);
          const clientId = stringField(parameters, "client_id");
          const challenge = stringField(parameters, "code_challenge");
          const nonce = stringField(parameters, "nonce");
          const redirectUri = stringField(parameters, "redirect_uri");
          const state = stringField(parameters, "state");
          if (
            clientId !== PROVIDER_CLIENT_ID ||
            parameters["code_challenge_method"] !== "S256" ||
            parameters["response_mode"] !== "query" ||
            parameters["response_type"] !== "code" ||
            parameters["scope"] !== "openid profile"
          ) {
            text(response, 400, "Invalid authorization request");
            return;
          }
          const code = opaque(24);
          grants.set(code, { challenge, clientId, nonce, redirectUri });
          const callback = new URL(redirectUri);
          callback.searchParams.set("code", code);
          callback.searchParams.set("state", state);
          redirect(response, callback.href);
          return;
        }
        if (request.method === "POST" && url.pathname === "/token") {
          tokenRequests += 1;
          const form = new URLSearchParams(await body(request));
          const code = form.get("code") ?? "";
          const grant = grants.get(code);
          grants.delete(code);
          const verifier = form.get("code_verifier") ?? "";
          const valid =
            grant !== undefined &&
            form.get("grant_type") === "authorization_code" &&
            form.get("client_id") === grant.clientId &&
            form.get("client_secret") === PROVIDER_CLIENT_SECRET &&
            form.get("redirect_uri") === grant.redirectUri &&
            base64Url(createHash("sha256").update(verifier).digest()) === grant.challenge;
          if (!valid) {
            json(response, 400, { error: "invalid_grant" });
            return;
          }
          const now = Math.floor(Date.now() / 1000);
          const idToken = jwt(
            privateKey,
            { alg: "RS256", kid: PROVIDER_KID, typ: "JWT" },
            {
              aud: grant.clientId,
              exp: now + 600,
              iat: now,
              iss: issuer,
              name: "Ada Integration",
              nbf: now - 1,
              nonce: grant.nonce,
              picture: "https://images.example/ada.png",
              sub: "controlled-subject-1",
            },
          );
          json(response, 200, {
            access_token: "provider-material-must-be-discarded",
            id_token: idToken,
            token_type: "Bearer",
          });
          return;
        }
        text(response, 404, "Not found");
      } catch {
        text(response, 400, "Invalid request");
      }
    })();
  });
}

function createApplicationServer(
  repository: string,
  origin: string,
  browserDriverToken: string,
  runtimeOrigin: string,
) {
  const pending = new Map<string, PendingBackendLogin>();
  const sessions = new Map<string, BackendSession>();
  const sdkBrowserEvidence = new Map<string, BrowserEvidenceSnapshot[]>();
  const sdkRoot = resolve(repository, "sdks/typescript/dist");

  return createServer((request, response) => {
    void (async () => {
      try {
        const url = requestUrl(request, origin);
        if (
          request.method === "GET" &&
          url.pathname.startsWith("/sdk/") &&
          url.pathname.endsWith(".js")
        ) {
          const relative = url.pathname.slice("/sdk/".length);
          const file = resolve(sdkRoot, relative);
          if (!file.startsWith(`${sdkRoot}${sep}`) || !relative.endsWith(".js")) {
            text(response, 404, "Not found");
            return;
          }
          const source = await readFile(file);
          response.writeHead(200, {
            "cache-control": "no-store",
            "content-type": "text/javascript; charset=utf-8",
            "x-content-type-options": "nosniff",
          });
          response.end(source);
          return;
        }
        if (request.method === "GET" && url.pathname === "/browser/") {
          html(response, browserApplication());
          return;
        }
        if (request.method === "GET" && url.pathname === "/browser/callback") {
          html(response, browserCallback(origin));
          return;
        }
        if (request.method === "GET" && url.pathname === "/sdk/callback") {
          html(response, safePage("SDK callback received", "The browser journey is complete."));
          return;
        }
        if (request.method === "POST" && url.pathname === "/sdk/browser-driver") {
          if (request.headers.authorization !== `Bearer ${browserDriverToken}`) {
            json(response, 401, { error: "unauthorized" });
            return;
          }
          const driven = await driveBrowserJourney(await body(request), origin, runtimeOrigin);
          const runEvidence = sdkBrowserEvidence.get(driven.runId) ?? [];
          if (runEvidence.length >= 8) throw new Error("browser-driver evidence run is full");
          runEvidence.push(driven.evidence);
          sdkBrowserEvidence.set(driven.runId, runEvidence);
          // Keep the SDK driver's public response contract deliberately unchanged.
          json(response, 200, { callbackUrl: driven.callbackUrl });
          return;
        }
        if (request.method === "POST" && url.pathname === "/sdk/browser-evidence/drain") {
          if (request.headers.authorization !== `Bearer ${browserDriverToken}`) {
            json(response, 401, { error: "unauthorized" });
            return;
          }
          const document = parseObject(await body(request));
          const runId = evidenceRunId(document["runId"]);
          const evidence = sdkBrowserEvidence.get(runId) ?? [];
          sdkBrowserEvidence.delete(runId);
          json(response, 200, { evidence });
          return;
        }
        if (request.method === "GET" && url.pathname === "/backend/start") {
          const runtimeBase = exactBase(url.searchParams.get("runtime"), runtimeOrigin);
          const projectId = required(url.searchParams.get("project"));
          const applicationId = required(url.searchParams.get("application"));
          const expectedClaimsRevision = positiveInteger(url.searchParams.get("claims_revision"));
          const publishableKey = required(url.searchParams.get("key"));
          const otherProjectId = required(url.searchParams.get("other_project"));
          const redirectUri = `${origin}/backend/callback`;
          const verifier = opaque(32);
          const state = opaque(24);
          const start = await runtimeJson(
            `${runtimeBase}v1/projects/${encodeURIComponent(projectId)}/auth/login/start`,
            {
              application_id: applicationId,
              pkce_challenge: base64Url(createHash("sha256").update(verifier).digest()),
              presentation_hint: "controlled-provider",
              publishable_key: publishableKey,
              redirect_uri: redirectUri,
              state,
            },
            201,
          );
          pending.set(state, {
            applicationId,
            expectedClaimsRevision,
            otherProjectId,
            projectId,
            publishableKey,
            redirectUri,
            runtimeBase,
            verifier,
          });
          redirect(response, stringField(start, "hosted_url"));
          return;
        }
        if (request.method === "GET" && url.pathname === "/backend/callback") {
          const state = required(url.searchParams.get("state"));
          const handoff = required(url.searchParams.get("handoff"));
          const login = pending.get(state);
          pending.delete(state);
          if (login?.redirectUri !== url.origin + url.pathname) {
            throw new Error("invalid backend callback");
          }
          let credentials = (await runtimeJson(
            `${login.runtimeBase}v1/projects/${encodeURIComponent(login.projectId)}/auth/handoff/exchange`,
            {
              application_id: login.applicationId,
              handoff,
              pkce_verifier: login.verifier,
              publishable_key: login.publishableKey,
            },
            200,
          )) as unknown as CredentialDocument;
          const verification = await verifyProjectAccessToken(
            credentials.access_token,
            login.runtimeBase,
            login.projectId,
            login.applicationId,
            login.expectedClaimsRevision,
            credentials,
          );
          const malformedRejected = await rejects(() =>
            verifyProjectAccessToken(
              `${credentials.access_token}.unexpected`,
              login.runtimeBase,
              login.projectId,
              login.applicationId,
              login.expectedClaimsRevision,
              credentials,
            ),
          );
          const crossProjectRejected = await rejects(() =>
            verifyProjectAccessToken(
              credentials.access_token,
              login.runtimeBase,
              login.otherProjectId,
              login.applicationId,
              login.expectedClaimsRevision,
              credentials,
            ),
          );
          await bearerJson(
            `${login.runtimeBase}v1/projects/${encodeURIComponent(login.projectId)}/auth/users/me`,
            "GET",
            credentials.access_token,
            200,
          );
          const wrongProject = await fetch(
            `${login.runtimeBase}v1/projects/${encodeURIComponent(login.otherProjectId)}/auth/users/me`,
            { headers: { authorization: `Bearer ${credentials.access_token}` }, redirect: "error" },
          );
          if (wrongProject.ok) throw new Error("cross-project token was accepted");
          credentials = (await runtimeJson(
            `${login.runtimeBase}v1/projects/${encodeURIComponent(login.projectId)}/auth/sessions/refresh`,
            {
              application_id: login.applicationId,
              publishable_key: login.publishableKey,
              refresh_token: credentials.refresh_token,
            },
            200,
          )) as unknown as CredentialDocument;
          if (credentials.refresh_generation <= 1) throw new Error("refresh did not rotate");
          await verifyProjectAccessToken(
            credentials.access_token,
            login.runtimeBase,
            login.projectId,
            login.applicationId,
            login.expectedClaimsRevision,
            credentials,
          );
          const session = opaque(24);
          sessions.set(session, {
            applicationId: login.applicationId,
            claimsVerified: verification,
            credentials,
            crossProjectRejected,
            malformedRejected,
            projectId: login.projectId,
            publishableKey: login.publishableKey,
            runtimeBase: login.runtimeBase,
          });
          response.setHeader(
            "set-cookie",
            `owlauth_e2e_backend=${session}; HttpOnly; SameSite=Lax; Path=/backend; Max-Age=600`,
          );
          response.setHeader("location", `${origin}/backend/`);
          response.writeHead(303);
          response.end();
          return;
        }
        if (request.method === "GET" && url.pathname === "/backend/") {
          const session = backendSession(request, sessions);
          html(response, backendApplication(session));
          return;
        }
        if (request.method === "POST" && url.pathname === "/backend/logout") {
          const [sessionId, session] = backendSessionEntry(request, sessions);
          await bearerJson(
            `${session.runtimeBase}v1/projects/${encodeURIComponent(session.projectId)}/auth/sessions/logout`,
            "POST",
            session.credentials.access_token,
            200,
          );
          const after = await fetch(
            `${session.runtimeBase}v1/projects/${encodeURIComponent(session.projectId)}/auth/users/me`,
            {
              headers: { authorization: `Bearer ${session.credentials.access_token}` },
              redirect: "error",
            },
          );
          if (after.ok) throw new Error("logged-out access token remained authoritative");
          sessions.delete(sessionId);
          response.setHeader(
            "set-cookie",
            "owlauth_e2e_backend=; HttpOnly; SameSite=Lax; Path=/backend; Max-Age=0",
          );
          html(response, safePage("Backend session ended", "Application logout was confirmed."));
          return;
        }
        text(response, 404, "Not found");
      } catch {
        html(response, safePage("Application request failed", "Start a new sign-in attempt."), 400);
      }
    })();
  });
}

async function driveBrowserJourney(
  document: string,
  applicationOrigin: string,
  runtimeOrigin: string,
): Promise<BrowserDriverResult> {
  const request = parseObject(document);
  const runId = evidenceRunId(request["evidenceRunId"]);
  const hostedUrl = boundedUrl(request["hostedUrl"]);
  const redirectUri = boundedUrl(request["redirectUri"]);
  const providerKey = request["providerKey"];
  const browserName = request["browserName"];
  if (
    hostedUrl.origin !== runtimeOrigin ||
    redirectUri.href !== `${applicationOrigin}/sdk/callback` ||
    (providerKey !== null && providerKey !== "controlled-provider") ||
    (browserName !== "chromium" && browserName !== "firefox")
  ) {
    throw new Error("browser-driver request escaped the controlled topology");
  }

  const browserTypes = { chromium, firefox } as const;
  const browser = await browserTypes[browserName].launch({ headless: true });
  try {
    const context = await browser.newContext();
    const evidence = await BrowserEvidence.create(context);
    const page = await context.newPage();
    await page.goto(hostedUrl.href, { waitUntil: "networkidle" });
    const providerButton = page.getByRole("button", {
      name: "Continue with Controlled Provider",
      exact: true,
    });
    await providerButton.waitFor({ state: "visible" });
    await page.waitForTimeout(250);
    await Promise.all([
      page.waitForURL(
        (candidate) =>
          candidate.origin === redirectUri.origin && candidate.pathname === redirectUri.pathname,
        { timeout: 30_000, waitUntil: "domcontentloaded" },
      ),
      providerButton.click(),
    ]);
    const finalUrl = new URL(page.url());
    if (
      finalUrl.origin !== redirectUri.origin ||
      finalUrl.pathname !== redirectUri.pathname ||
      finalUrl.hash !== "" ||
      finalUrl.username !== "" ||
      finalUrl.password !== "" ||
      finalUrl.searchParams.getAll("handoff").length !== 1 ||
      finalUrl.searchParams.getAll("state").length !== 1 ||
      [...finalUrl.searchParams.keys()].some((name) => name !== "handoff" && name !== "state")
    ) {
      throw new Error("invalid Application callback");
    }
    return { callbackUrl: finalUrl.href, evidence: await evidence.snapshot(), runId };
  } finally {
    await browser.close();
  }
}

function parseObject(document: string): Record<string, unknown> {
  const parsed = JSON.parse(document) as unknown;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("invalid JSON object");
  }
  return parsed as Record<string, unknown>;
}

function evidenceRunId(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{16,128}$/u.test(value)) {
    throw new Error("invalid browser evidence run ID");
  }
  return value;
}

function boundedUrl(value: unknown): URL {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096) {
    throw new Error("invalid URL");
  }
  const url = new URL(value);
  if (url.username !== "" || url.password !== "" || url.hash !== "") throw new Error("invalid URL");
  return url;
}

async function verifyProjectAccessToken(
  token: string,
  runtimeBase: string,
  projectId: string,
  applicationId: string,
  expectedClaimsRevision: number,
  credentials: CredentialDocument,
): Promise<boolean> {
  const parts = token.split(".");
  const encodedHeader = parts[0];
  const encodedClaims = parts[1];
  const encodedSignature = parts[2];
  if (
    parts.length !== 3 ||
    encodedHeader === undefined ||
    encodedClaims === undefined ||
    encodedSignature === undefined
  ) {
    throw new Error("malformed token");
  }
  const header = parsePart(encodedHeader);
  const claims = parsePart(encodedClaims);
  if (header["alg"] !== "EdDSA" || header["typ"] !== "at+jwt") throw new Error("wrong token type");
  const kid = stringField(header, "kid");
  const jwksResponse = await fetch(
    `${runtimeBase}projects/${encodeURIComponent(projectId)}/.well-known/jwks.json`,
    { redirect: "error" },
  );
  if (!jwksResponse.ok) throw new Error("JWKS unavailable");
  const jwks = (await jwksResponse.json()) as { keys?: Record<string, unknown>[] };
  const jwk = jwks.keys?.find((candidate) => candidate["kid"] === kid);
  if (
    jwk?.["kty"] !== "OKP" ||
    jwk["crv"] !== "Ed25519" ||
    jwk["alg"] !== "EdDSA" ||
    jwk["use"] !== "sig"
  ) {
    throw new Error("untrusted signing key");
  }
  const signature = Buffer.from(encodedSignature, "base64url");
  const key = createPublicKey({ format: "jwk", key: jwk });
  if (!verify(null, Buffer.from(`${encodedHeader}.${encodedClaims}`), key, signature)) {
    throw new Error("invalid signature");
  }
  const now = Math.floor(Date.now() / 1000);
  const expectedIssuer = `${runtimeBase}projects/${projectId}/`;
  if (
    claims["iss"] !== expectedIssuer ||
    claims["aud"] !== projectId ||
    claims["sub"] !== credentials.user_id ||
    claims["app_id"] !== applicationId ||
    claims["sid"] !== credentials.session_id ||
    claims["claims_rev"] !== expectedClaimsRevision ||
    typeof claims["jti"] !== "string" ||
    claims["jti"].length === 0 ||
    !positive(claims["claims_rev"]) ||
    !positive(claims["iat"]) ||
    !positive(claims["nbf"]) ||
    !positive(claims["exp"]) ||
    !positive(claims["auth_time"]) ||
    Number(claims["iat"]) > Number(claims["nbf"]) ||
    Number(claims["nbf"]) > Number(claims["exp"]) ||
    Number(claims["iat"]) > now + 60 ||
    Number(claims["nbf"]) > now + 60 ||
    Number(claims["exp"]) <= now - 60 ||
    Number(claims["auth_time"]) > Number(claims["iat"])
  ) {
    throw new Error("invalid trust namespace");
  }
  const allowed = new Set([
    "app_id",
    "aud",
    "auth_time",
    "claims_rev",
    "exp",
    "iat",
    "iss",
    "jti",
    "nbf",
    "sid",
    "sub",
  ]);
  if (Object.keys(claims).some((name) => !allowed.has(name))) throw new Error("unexpected claim");
  return true;
}

function browserApplication(): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Browser Application</title></head>
<body><main><h1>Browser-direct Application</h1><p id="status" role="status">Ready</p>
<button id="start">Start browser sign-in</button><button id="current" disabled>Read current user</button>
<button id="refresh" disabled>Refresh session</button><button id="logout" disabled>Application logout</button>
<button id="browser-logout" disabled>Project browser logout</button>
<button id="verify-browser-logout" disabled>Verify browser logout</button>
<output id="result"></output></main>
<script type="module">
import { Client, OwlAuthError } from "/sdk/index.js";
const parameters = new URL(location.href).searchParams;
const client = new Client({
  baseUrl: parameters.get("runtime"), projectId: parameters.get("project"),
  applicationId: parameters.get("application"), publishableKey: parameters.get("key"),
  allowInsecureLoopback: true,
});
let pending;
let credentials;
const callbackChannel = new BroadcastChannel("owlauth-e2e-callback");
const status = document.querySelector("#status");
const result = document.querySelector("#result");
const setSessionEnabled = (enabled) => {
  for (const id of ["current", "refresh", "logout", "browser-logout"])
    document.querySelector("#" + id).disabled = !enabled;
};
const assertCredentialsAreMemoryOnly = async (candidate) => {
  const surfaces = [location.href, document.documentElement.outerHTML, localStorage, sessionStorage];
  for (const storage of surfaces.slice(2)) {
    for (let index = 0; index < storage.length; index += 1) {
      const key = storage.key(index);
      surfaces.push(key ?? "", key === null ? "" : storage.getItem(key) ?? "");
    }
  }
  const serialized = surfaces.slice(0, 2).join("\\n") + surfaces.slice(4).join("\\n");
  for (const secret of [candidate.accessToken.expose(), candidate.refreshToken.expose()]) {
    if (serialized.includes(secret)) throw new Error("credential escaped caller memory");
  }
  if ((await caches.keys()).length !== 0) throw new Error("credential cache is not empty");
  if (typeof indexedDB.databases === "function" && (await indexedDB.databases()).length !== 0)
    throw new Error("credential database is not empty");
};
document.querySelector("#start").addEventListener("click", async () => {
  const popup = window.open("about:blank", "owlauth-hosted", "popup,width=720,height=700");
  if (popup === null) throw new Error("popup unavailable");
  try {
    const configuration = await client.getPublicConfiguration();
    if (!configuration.loginAvailable || configuration.providers.length !== 1) throw new Error("login unavailable");
    const started = await client.beginLogin({ redirectUri: location.origin + "/browser/callback" });
    pending = started.pending;
    status.textContent = "Waiting for Hosted Authentication";
    popup.location.replace(started.hostedUrl);
  } catch (error) {
    popup.close();
    throw error;
  }
});
callbackChannel.addEventListener("message", async (event) => {
  if (event.data?.type !== "owlauth-e2e-callback" || pending === undefined) return;
  credentials = await client.completeLogin(event.data.url, pending);
  pending = undefined;
  history.replaceState({}, "", location.pathname + location.search);
  await assertCredentialsAreMemoryOnly(credentials);
  status.textContent = "Browser session ready";
  result.textContent = "generation " + credentials.refreshGeneration;
  setSessionEnabled(true);
});
document.querySelector("#current").addEventListener("click", async () => {
  const user = await client.currentUser(credentials.accessToken);
  status.textContent = "Current user verified";
  result.textContent = user.projection.displayName;
});
document.querySelector("#refresh").addEventListener("click", async () => {
  const successor = await client.refresh(credentials);
  if (successor.refreshGeneration <= credentials.refreshGeneration) throw new Error("refresh did not advance");
  credentials = successor;
  await assertCredentialsAreMemoryOnly(credentials);
  status.textContent = "Credentials replaced atomically";
  result.textContent = "generation " + credentials.refreshGeneration;
});
document.querySelector("#logout").addEventListener("click", async () => {
  await client.logoutApplication(credentials.accessToken);
  credentials = undefined;
  setSessionEnabled(false);
  status.textContent = "Application session ended";
  result.textContent = "";
});
document.querySelector("#browser-logout").addEventListener("click", async () => {
  const popup = window.open("about:blank", "owlauth-browser-logout", "popup,width=720,height=700");
  if (popup === null) throw new Error("popup unavailable");
  try {
    const prepared = await client.prepareBrowserLogout(credentials.accessToken);
    await assertCredentialsAreMemoryOnly(credentials);
    setSessionEnabled(false);
    document.querySelector("#verify-browser-logout").disabled = false;
    status.textContent = "Waiting for browser logout confirmation";
    popup.location.replace(prepared.hostedUrl);
  } catch (error) {
    popup.close();
    throw error;
  }
});
document.querySelector("#verify-browser-logout").addEventListener("click", async () => {
  if (credentials === undefined) throw new Error("caller credential state unavailable");
  try {
    await client.refresh(credentials);
    throw new Error("refresh unexpectedly succeeded after browser logout");
  } catch (error) {
    if (!(error instanceof OwlAuthError) || error.operation !== "refresh" ||
        error.category !== "Refresh" || error.action !== "invalidate_credentials") throw error;
  }
  credentials = undefined;
  document.querySelector("#verify-browser-logout").disabled = true;
  status.textContent = "Browser logout confirmed; refresh rejected; caller state cleared";
  result.textContent = "";
});
</script></body></html>`;
}

function browserCallback(origin: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Returning</title></head><body><p>Returning to the Application.</p><script>
if (location.origin === ${JSON.stringify(origin)}) {
  const channel = new BroadcastChannel("owlauth-e2e-callback");
  channel.postMessage({ type: "owlauth-e2e-callback", url: location.href });
  history.replaceState({}, "", "/browser/callback");
  setTimeout(() => { channel.close(); window.close(); }, 0);
}
</script></body></html>`;
}

function backendApplication(session: BackendSession): string {
  if (!session.claimsVerified || !session.crossProjectRejected || !session.malformedRejected) {
    throw new Error("backend verification incomplete");
  }
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Backend Application</title></head><body><main>
<h1>Backend-custody Application</h1><p role="status">Session verified</p>
<dl><dt>JWT signature and namespace</dt><dd>verified</dd><dt>Malformed token</dt><dd>rejected</dd><dt>Cross-Project token</dt><dd>rejected</dd><dt>Refresh generation</dt><dd>${String(session.credentials.refresh_generation)}</dd></dl>
<form method="post" action="/backend/logout"><button>Application logout</button></form>
</main></body></html>`;
}

function safePage(title: string, message: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>${title}</title></head><body><main><h1>${title}</h1><p role="status">${message}</p></main></body></html>`;
}

async function runtimeJson(
  url: string,
  document: unknown,
  expected: number,
): Promise<Record<string, unknown>> {
  const response = await fetch(url, {
    body: JSON.stringify(document),
    headers: { accept: "application/json", "content-type": "application/json" },
    method: "POST",
    redirect: "error",
  });
  if (response.status !== expected) throw new Error("Runtime request failed");
  return (await response.json()) as Record<string, unknown>;
}

async function bearerJson(
  url: string,
  method: "GET" | "POST",
  token: string,
  expected: number,
): Promise<Record<string, unknown>> {
  const response = await fetch(url, {
    headers: { accept: "application/json", authorization: `Bearer ${token}` },
    method,
    redirect: "error",
  });
  if (response.status !== expected) throw new Error("Authenticated Runtime request failed");
  return (await response.json()) as Record<string, unknown>;
}

function backendSession(
  request: IncomingMessage,
  sessions: Map<string, BackendSession>,
): BackendSession {
  return backendSessionEntry(request, sessions)[1];
}

function backendSessionEntry(
  request: IncomingMessage,
  sessions: Map<string, BackendSession>,
): [string, BackendSession] {
  const sessionId = cookie(request, "owlauth_e2e_backend");
  const session = sessionId === null ? undefined : sessions.get(sessionId);
  if (sessionId === null || session === undefined) throw new Error("backend session unavailable");
  return [sessionId, session];
}

function cookie(request: IncomingMessage, name: string): string | null {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const [candidate, ...value] = part.trim().split("=");
    if (candidate === name) return value.join("=");
  }
  return null;
}

async function rejects(operation: () => Promise<unknown>): Promise<boolean> {
  try {
    await operation();
    return false;
  } catch {
    return true;
  }
}

function parsePart(value: string): Record<string, unknown> {
  const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as unknown;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
    throw new Error("invalid JWT JSON");
  return parsed as Record<string, unknown>;
}

function positive(value: unknown): boolean {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function exactBase(value: string | null, expectedOrigin: string): string {
  const url = new URL(required(value));
  if (
    url.origin !== expectedOrigin ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error("invalid Runtime base");
  }
  return url.href;
}

function positiveInteger(value: string | null): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error("invalid positive integer");
  return parsed;
}

function required(value: string | null): string {
  if (value === null || value.length === 0 || value.length > 2048) throw new Error("missing value");
  return value;
}

function stringField(value: Record<string, unknown>, field: string): string {
  const candidate = value[field];
  if (typeof candidate !== "string" || candidate.length === 0) throw new Error("missing field");
  return candidate;
}

function requestUrl(request: IncomingMessage, origin: string): URL {
  return new URL(request.url ?? "/", origin);
}

function requiredParameters(url: URL, names: readonly string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (const name of names) {
    const values = url.searchParams.getAll(name);
    if (values.length !== 1 || values[0] === undefined || values[0].length === 0) {
      throw new Error("invalid parameters");
    }
    result[name] = values[0];
  }
  if ([...url.searchParams.keys()].some((name) => !names.includes(name))) {
    throw new Error("unexpected parameter");
  }
  return result;
}

function jwt(privateKey: KeyObject, header: object, claims: object): string {
  const signingInput = `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(claims))}`;
  return `${signingInput}.${base64Url(sign("RSA-SHA256", Buffer.from(signingInput), privateKey))}`;
}

function base64Url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

function opaque(bytes: number): string {
  return randomBytes(bytes).toString("base64url");
}

async function body(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    length += buffer.length;
    if (length > MAX_BODY_BYTES) throw new Error("request too large");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function json(response: ServerResponse, status: number, document: unknown): void {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json",
    "x-content-type-options": "nosniff",
  });
  response.end(JSON.stringify(document));
}

function html(response: ServerResponse, document: string, status = 200): void {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-security-policy":
      "default-src 'none'; script-src 'unsafe-inline' 'self'; connect-src http://127.0.0.1:*; style-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "content-type": "text/html; charset=utf-8",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
  });
  response.end(document);
}

function text(response: ServerResponse, status: number, document: string): void {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "text/plain; charset=utf-8",
  });
  response.end(document);
}

function redirect(response: ServerResponse, location: string): void {
  response.writeHead(303, {
    "cache-control": "no-store",
    location,
    "referrer-policy": "no-referrer",
  });
  response.end();
}

function listen(
  server: ReturnType<typeof createServer>,
  port: number,
  host: string,
): Promise<void> {
  return new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolveListen);
  });
}

function close(server: ReturnType<typeof createServer>): Promise<void> {
  return new Promise((resolveClose, reject) => {
    server.close((error) => {
      if (error === undefined) resolveClose();
      else reject(error);
    });
  });
}
