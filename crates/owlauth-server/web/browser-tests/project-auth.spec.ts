import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";

import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

import {
  BrowserEvidence,
  type BrowserEvidenceSnapshot,
  type LifecycleSample,
  type NetworkRecord,
} from "./browser-evidence";
import { typescriptSdkArtifactDigest } from "./test-services";

const controlBase = requiredEnvironment("OWLAUTH_E2E_CONTROL_BASE");
const runtimeBase = requiredEnvironment("OWLAUTH_E2E_RUNTIME_BASE");
const operatorKey = requiredEnvironment("OWLAUTH_E2E_OPERATOR_KEY");
const providerOrigin = requiredEnvironment("OWLAUTH_E2E_PROVIDER_ORIGIN");
const providerClientId = requiredEnvironment("OWLAUTH_E2E_PROVIDER_CLIENT_ID");
const providerClientSecret = requiredEnvironment("OWLAUTH_E2E_PROVIDER_CLIENT_SECRET");
const applicationOrigin = requiredEnvironment("OWLAUTH_E2E_APPLICATION_ORIGIN");
const browserDriverUrl = requiredEnvironment("OWLAUTH_E2E_BROWSER_DRIVER_URL");
const browserDriverToken = requiredEnvironment("OWLAUTH_E2E_BROWSER_DRIVER_TOKEN");
const frozenTypescriptSdkDigest = requiredEnvironment("OWLAUTH_E2E_TYPESCRIPT_SDK_DIGEST");

interface Project {
  readonly id: string;
  readonly metadata_revision: number;
  readonly public_id: string;
}

interface Application {
  readonly configuration: { readonly publishable_keys: readonly string[] };
  readonly id: string;
  readonly public_id: string;
  readonly security_revision: number;
}

interface ProjectPolicy {
  readonly access_token_lifetime_seconds: number;
  readonly browser_session_reuse: boolean;
  readonly claims_revision: number;
  readonly session_revision: number;
}

interface SigningKey {
  readonly id: string;
  readonly ring_revision: number;
}

interface Provider {
  readonly id: string;
}

interface ProvisionedContext {
  readonly application: Application;
  readonly claimsRevision: number;
  readonly otherApplication: Application;
  readonly otherProject: Project;
  readonly project: Project;
}

type SecretKind = "access" | "csrf" | "handoff" | "preparation" | "refresh";

interface SecretValue {
  readonly kind: SecretKind;
  readonly value: string;
}

type RuntimeCookieKind = "interaction" | "project";

interface RuntimeCookieSecret {
  readonly kind: RuntimeCookieKind;
  readonly name: string;
  readonly path: string;
  readonly value: string;
}

interface RuntimeCookieEvent {
  readonly disposition: "deletion" | "issuance";
  readonly kind: RuntimeCookieKind;
  readonly name: string;
  readonly value: string;
}

interface ParsedSetCookie {
  readonly attributes: ReadonlyMap<string, string>;
  readonly name: string;
  readonly value: string;
}

interface HostedBootstrap {
  readonly csrf: string;
  readonly project_id: string;
  readonly revision: number;
}

interface MutationResult {
  readonly body: unknown;
  readonly status: number;
}

interface ProviderRequestCounts {
  readonly authorization_requests: number;
  readonly token_requests: number;
}

test("same SDK artifact completes browser-direct and backend-custody Project Auth", async ({
  browser,
  context: browserContext,
  page,
  browserName,
}) => {
  test.setTimeout(360_000);
  if (browserName !== "chromium" && browserName !== "firefox") {
    throw new Error("browser project is outside the declared support matrix");
  }
  const repository = resolve(import.meta.dirname, "../../../..");
  expect(await typescriptSdkArtifactDigest(repository)).toBe(frozenTypescriptSdkDigest);
  const evidence = await BrowserEvidence.create(browserContext);
  const context = await provision(page.request, `${browserName}-${Date.now().toString(36)}`);
  const publishableKey = context.application.configuration.publishable_keys[0];
  expect(publishableKey).toBeDefined();

  const startInteraction = async (state: string): Promise<string> => {
    const response = await page.request.post(
      `${runtimeBase}v1/projects/${encodeURIComponent(context.project.public_id)}/auth/login/start`,
      {
        data: {
          application_id: context.application.public_id,
          pkce_challenge: "A".repeat(43),
          presentation_hint: null,
          publishable_key: publishableKey ?? "",
          redirect_uri: `${applicationOrigin}/sdk/callback`,
          state,
        },
        headers: { origin: applicationOrigin },
      },
    );
    expect(response.status()).toBe(201);
    const body = (await response.json()) as { hosted_url?: unknown };
    expect(typeof body.hosted_url).toBe("string");
    return body.hosted_url as string;
  };

  const countsBeforeSelectionRace = await providerRequestCounts(page.request);
  const selectionRaceContext = await browser.newContext();
  const selectionEvidence = await BrowserEvidence.create(selectionRaceContext);
  const selectionPage = await selectionRaceContext.newPage();
  await selectionPage.goto(await startInteraction(`selection-race-${browserName}`));
  await expect(selectionPage.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  const selectionBootstrap = await observedBootstrap(selectionEvidence, selectionPage.url());
  const selectionResults = await raceHostedMutation(
    selectionPage,
    `${runtimeBase}v1/projects/${encodeURIComponent(context.project.public_id)}/auth/interactions/${encodeURIComponent(interactionHandle(selectionPage.url()))}/method`,
    {
      csrf: selectionBootstrap.csrf,
      expected_revision: selectionBootstrap.revision,
      provider_key: "controlled-provider",
    },
  );
  expect(selectionResults.filter(({ status }) => status === 200)).toHaveLength(1);
  expect(selectionResults.filter(({ status }) => status !== 200)).toHaveLength(1);
  expect(await providerRequestCounts(page.request)).toEqual(countsBeforeSelectionRace);
  await selectionEvidence.settle();
  await assertEvidenceConfinement([selectionEvidence]);
  await selectionRaceContext.close();

  const browserParameters = new URLSearchParams({
    application: context.application.public_id,
    key: publishableKey ?? "",
    project: context.project.public_id,
    runtime: runtimeBase,
  });
  const observedUrls: string[] = [];
  const browserErrors: string[] = [];
  const requestFailures: string[] = [];
  page.on("request", (request) => observedUrls.push(request.url()));
  page.on("requestfailed", (request) =>
    requestFailures.push(`${request.url()}: ${request.failure()?.errorText ?? "unknown"}`),
  );
  page.on("pageerror", (error) => browserErrors.push(error.message));
  await page.goto(`${applicationOrigin}/browser/?${browserParameters.toString()}`);
  const popupReady = page.waitForEvent("popup", { timeout: 30_000 });
  await page.getByRole("button", { name: "Start browser sign-in" }).click();
  const popup = await popupReady;
  await page.waitForTimeout(500);
  if (browserErrors.length > 0) {
    throw new Error(
      `browser Application failed: ${browserErrors.join("; ")}; requests: ${observedUrls.join(", ")}; failures: ${requestFailures.join(", ")}`,
    );
  }
  await expect(popup.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  await expect(
    popup.getByRole("button", { name: "Continue with Controlled Provider", exact: true }),
  ).toBeVisible();
  await expect(
    popup.getByRole("button", { name: "Continue with current session", exact: true }),
  ).toHaveCount(0);
  await observedBootstrap(evidence, popup.url());
  await assertPageSecretFree(popup, await currentSecrets(evidence));
  await popup
    .getByRole("button", { name: "Continue with Controlled Provider", exact: true })
    .click();
  await expect(page.locator("#status")).toHaveText("Browser session ready");

  await page.getByRole("button", { name: "Read current user" }).click();
  await expect(page.locator("#status")).toHaveText("Current user verified");
  await expect(page.locator("output")).toHaveText("Ada Integration");
  await page.getByRole("button", { name: "Refresh session" }).click();
  await expect(page.locator("#status")).toHaveText("Credentials replaced atomically");
  await expect(page.locator("output")).toHaveText("generation 2");

  await evidence.settle();
  await assertPageSecretFree(page, await currentSecrets(evidence));

  await page.getByRole("button", { name: "Application logout" }).click();
  await expect(page.locator("#status")).toHaveText("Application session ended");

  const countsBeforeReuse = await providerRequestCounts(page.request);
  const reusePopupReady = page.waitForEvent("popup", { timeout: 30_000 });
  await page.getByRole("button", { name: "Start browser sign-in" }).click();
  const reusePopup = await reusePopupReady;
  await expect(reusePopup.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  await expect(
    reusePopup.getByRole("button", {
      name: "Continue with Controlled Provider",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    reusePopup.getByRole("button", { name: "Continue with current session", exact: true }),
  ).toBeVisible();
  const reuseBootstrap = await observedBootstrap(evidence, reusePopup.url());
  await assertPageSecretFree(reusePopup, await currentSecrets(evidence));
  const reuseResults = await raceHostedMutation(
    reusePopup,
    `${runtimeBase}v1/projects/${encodeURIComponent(context.project.public_id)}/auth/interactions/${encodeURIComponent(interactionHandle(reusePopup.url()))}/session/reuse`,
    { csrf: reuseBootstrap.csrf, expected_revision: reuseBootstrap.revision },
  );
  const successfulReuse = reuseResults.filter(({ status }) => status === 200);
  expect(successfulReuse).toHaveLength(1);
  expect(reuseResults.filter(({ status }) => status !== 200)).toHaveLength(1);
  const reuseNavigation = parseNavigationUrl(successfulReuse[0]?.body);
  await reusePopup.evaluate((target) => {
    location.replace(target);
  }, reuseNavigation);
  await expect(page.locator("#status")).toHaveText("Browser session ready");
  await expect(page.locator("output")).toHaveText("generation 1");
  expect(await providerRequestCounts(page.request)).toEqual(countsBeforeReuse);

  const browserLogoutPopupReady = page.waitForEvent("popup", { timeout: 30_000 });
  await page.getByRole("button", { name: "Project browser logout" }).click();
  const browserLogoutPopup = await browserLogoutPopupReady;
  await expect(
    browserLogoutPopup.getByRole("heading", { name: "Sign out", exact: true }),
  ).toBeVisible();
  await expect(
    browserLogoutPopup.getByRole("heading", { name: "Sign out of this Project?" }),
  ).toBeVisible();
  await observedBootstrap(evidence, browserLogoutPopup.url());
  await evidence.settle();
  await assertPageSecretFree(browserLogoutPopup, await currentSecrets(evidence));
  await browserLogoutPopup.getByRole("button", { name: "Confirm sign out" }).click();
  await expect(browserLogoutPopup.getByRole("heading", { name: "Signed out" })).toBeVisible();
  await expect(
    browserLogoutPopup.getByText("Your Project browser session has ended."),
  ).toBeVisible();
  await evidence.settle();
  await assertPageSecretFree(browserLogoutPopup, await currentSecrets(evidence));

  await page.getByRole("button", { name: "Verify browser logout" }).click();
  await expect(page.locator("#status")).toHaveText(
    "Browser logout confirmed; refresh rejected; caller state cleared",
  );

  const countsAfterLogout = await providerRequestCounts(page.request);
  expect(countsAfterLogout).toEqual(countsBeforeReuse);
  const afterLogoutPopupReady = page.waitForEvent("popup", { timeout: 30_000 });
  await page.getByRole("button", { name: "Start browser sign-in" }).click();
  const afterLogoutPopup = await afterLogoutPopupReady;
  await expect(afterLogoutPopup.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  await expect(
    afterLogoutPopup.getByRole("button", {
      name: "Continue with Controlled Provider",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    afterLogoutPopup.getByRole("button", {
      name: "Continue with current session",
      exact: true,
    }),
  ).toHaveCount(0);
  const afterLogoutBootstrap = await observedBootstrap(evidence, afterLogoutPopup.url());
  const rejectedReuse = await hostedMutation(
    afterLogoutPopup,
    `${runtimeBase}v1/projects/${encodeURIComponent(context.project.public_id)}/auth/interactions/${encodeURIComponent(interactionHandle(afterLogoutPopup.url()))}/session/reuse`,
    { csrf: afterLogoutBootstrap.csrf, expected_revision: afterLogoutBootstrap.revision },
  );
  expect(rejectedReuse.status).not.toBe(200);
  expect(await providerRequestCounts(page.request)).toEqual(countsAfterLogout);
  await evidence.settle();
  const browserSnapshots = await assertEvidenceConfinement([evidence]);
  expect(new Set(evidenceSecrets(browserSnapshots).map(({ kind }) => kind))).toEqual(
    new Set<SecretKind>(["access", "csrf", "handoff", "preparation", "refresh"]),
  );
  expect(new Set(runtimeCookieSecrets(browserSnapshots).map(({ kind }) => kind))).toEqual(
    new Set<RuntimeCookieKind>(["interaction", "project"]),
  );
  await afterLogoutPopup.close();

  const forbidden = await page.request.get(
    `${runtimeBase}v1/projects/${encodeURIComponent(context.project.public_id)}/auth/config?application_id=${encodeURIComponent(context.application.public_id)}`,
    { headers: { origin: "https://attacker.example" } },
  );
  expect(forbidden.status()).toBe(403);
  expect(forbidden.headers()["access-control-allow-origin"]).toBeUndefined();

  const crossApplication = await page.request.get(
    `${runtimeBase}v1/projects/${encodeURIComponent(context.project.public_id)}/auth/config?application_id=${encodeURIComponent(context.otherApplication.public_id)}`,
    { headers: { origin: applicationOrigin } },
  );
  expect(crossApplication.status()).toBe(403);
  expect(crossApplication.headers()["access-control-allow-origin"]).toBeUndefined();

  const backendParameters = new URLSearchParams({
    application: context.application.public_id,
    claims_revision: String(context.claimsRevision),
    key: publishableKey ?? "",
    other_project: context.otherProject.public_id,
    project: context.project.public_id,
    runtime: runtimeBase,
  });
  await page.goto(`${applicationOrigin}/backend/start?${backendParameters.toString()}`);
  await expect(page.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  await page.getByRole("button", { name: "Controlled Provider" }).click();
  await expect(page.getByRole("heading", { name: "Backend-custody Application" })).toBeVisible();
  await expect(page.getByText("Session verified")).toBeVisible();
  await expect(page.getByText("verified", { exact: true })).toBeVisible();
  await expect(page.getByText("rejected", { exact: true })).toHaveCount(2);
  await expect(page.getByText("2", { exact: true })).toBeVisible();
  expect(page.url()).not.toMatch(/handoff|access_token|refresh_token/u);
  await expect(page.locator("body")).not.toContainText(/eyJ[A-Za-z0-9_-]+\./u);

  await page.getByRole("button", { name: "Application logout" }).click();
  await expect(page.getByRole("heading", { name: "Backend session ended" })).toBeVisible();
  await expect(page.getByRole("status")).toHaveText("Application logout was confirmed.");
  await assertEvidenceConfinement([evidence]);

  const sdkBrowserSnapshots = await runSdkE2Es(context, publishableKey ?? "", browserName);
  expect(sdkBrowserSnapshots).toHaveLength(2);
  await assertEvidenceConfinement([evidence], sdkBrowserSnapshots);
  expect(await typescriptSdkArtifactDigest(repository)).toBe(frozenTypescriptSdkDigest);
});

test("browser evidence rejects unreviewed secret and cookie placements", async ({ browser }) => {
  const handoff: SecretValue = {
    kind: "handoff",
    value: "handoff-negative-fixture-value",
  };
  const refresh: SecretValue = {
    kind: "refresh",
    value: "refresh-negative-fixture-value",
  };
  const access: SecretValue = {
    kind: "access",
    value: "access-negative-fixture-value",
  };
  const wrongOrigin = "https://attacker.example/v1/projects/project/auth/handoff/exchange";
  expect(() => {
    assertRequestConfinement(
      {
        body: JSON.stringify({ handoff: handoff.value }),
        headers: [],
        method: "POST",
        url: wrongOrigin,
      },
      [handoff],
    );
  }).toThrow();
  expect(() => {
    assertResponseConfinement(
      {
        body: JSON.stringify({ refresh_token: refresh.value }),
        headers: [],
        method: "POST",
        status: 200,
        url: "https://attacker.example/v1/projects/project/auth/sessions/refresh",
      },
      [refresh],
    );
  }).toThrow();
  expect(() => {
    assertRequestConfinement(
      {
        body: "",
        headers: [{ name: "authorization", value: `Bearer ${access.value}` }],
        method: "GET",
        url: runtimeFixtureUrl("v1/projects/project/auth/config"),
      },
      [access],
    );
  }).toThrow();

  const interactionName = `owl_runtime_${"a".repeat(24)}`;
  const projectName = `owl_project_${"b".repeat(24)}`;
  const interactionRoute = runtimeFixtureUrl("auth/interactions/interaction-fixture");
  const projectRouteUrl = runtimeFixtureUrl("projects/project/auth/callback/provider");
  const validAttributes = `Path=${runtimeCookiePath()}; Secure; HttpOnly; SameSite=Lax`;
  const invalidCookieLines = [
    `${interactionName}=interaction-cookie-value; Path=${runtimeCookiePath()}; Max-Age=600; Secure; HttpOnly; SameSite=Lax; Domain=${runtimeUrl().hostname}`,
    `${interactionName}=interaction-cookie-value; Path=${runtimeCookiePath()}; Max-Age=86400; Secure; HttpOnly; SameSite=Lax`,
    `${projectName}=project-cookie-value; Path=${runtimeCookiePath()}; Max-Age=600; Secure; HttpOnly; SameSite=Lax`,
    `${interactionName}=interaction-cookie-value; Path=${runtimeCookiePath()}; Max-Age=600; Secure; HttpOnly; SameSite=Lax; Priority=High`,
  ] as const;
  for (const [index, line] of invalidCookieLines.entries()) {
    const url = index === 2 ? projectRouteUrl : interactionRoute;
    expect(() => runtimeCookieSecrets([cookieFixtureSnapshot(url, line)])).toThrow();
  }
  expect(() =>
    runtimeCookieSecrets([
      cookieFixtureSnapshot(
        runtimeFixtureUrl("v1/projects/project/auth/interactions/interaction/session/reuse"),
        `${interactionName}=deleted; Max-Age=0; ${validAttributes}`,
        "POST",
      ),
    ]),
  ).toThrow();

  const context = await browser.newContext();
  try {
    const evidence = await BrowserEvidence.create(context);
    const page = await context.newPage();
    await page.goto(`${applicationOrigin}/sdk/callback`);
    const transient: SecretValue = {
      kind: "access",
      value: "same-task-transient-dom-secret",
    };
    await page.evaluate((value) => {
      const node = document.createElement("span");
      node.textContent = value;
      document.body.appendChild(node);
      node.remove();
    }, transient.value);
    await expect
      .poll(() =>
        evidence.lifecycle.some(
          ({ body, html }) => body.includes(transient.value) || html.includes(transient.value),
        ),
      )
      .toBe(true);
    const snapshot = await evidence.snapshot();
    expect(() => {
      for (const sample of snapshot.lifecycle) assertLifecycleConfinement(sample, [transient]);
    }).toThrow();
  } finally {
    await context.close();
  }
});

function runtimeFixtureUrl(path: string): string {
  return new URL(
    path,
    runtimeCookiePath() === "/" ? runtimeBase : `${runtimeUrl().origin}${runtimeCookiePath()}`,
  ).href;
}

function cookieFixtureSnapshot(
  url: string,
  setCookie: string,
  method = "GET",
): BrowserEvidenceSnapshot {
  return {
    consoleMessages: [],
    lifecycle: [],
    pageCount: 1,
    requests: [],
    responses: [
      {
        body: "",
        headers: [{ name: "set-cookie", value: setCookie }],
        method,
        status: 200,
        url,
      },
    ],
    storageState: '{"cookies":[],"origins":[]}',
  };
}

async function providerRequestCounts(request: APIRequestContext): Promise<ProviderRequestCounts> {
  const response = await request.get(`${providerOrigin}__e2e/request-counts`);
  expect(response.ok()).toBe(true);
  const document = (await response.json()) as Partial<ProviderRequestCounts>;
  expect(typeof document.authorization_requests).toBe("number");
  expect(typeof document.token_requests).toBe("number");
  return document as ProviderRequestCounts;
}

function parseJsonObject(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function parseHostedBootstrap(document: string): HostedBootstrap | null {
  const tag = /<meta\s+[^>]*name="owlauth-runtime-bootstrap"[^>]*>/iu.exec(document)?.[0];
  const encoded = tag === undefined ? undefined : /\scontent="([^"]*)"/iu.exec(tag)?.[1];
  if (encoded === undefined) return null;
  const decoded = encoded
    .replaceAll("&quot;", '"')
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");
  const parsed = parseJsonObject(decoded);
  if (
    typeof parsed?.["csrf"] !== "string" ||
    parsed["csrf"].length < 16 ||
    typeof parsed["project_id"] !== "string" ||
    typeof parsed["revision"] !== "number" ||
    !Number.isSafeInteger(parsed["revision"])
  ) {
    return null;
  }
  return {
    csrf: parsed["csrf"],
    project_id: parsed["project_id"],
    revision: parsed["revision"],
  };
}

function interactionHandle(value: string): string {
  const segment = new URL(value).pathname.split("/").at(-1);
  if (segment === undefined || !/^[A-Za-z0-9._-]{16,256}$/u.test(segment)) {
    throw new Error("Hosted interaction URL did not contain a bounded opaque handle");
  }
  return segment;
}

async function hostedMutation(
  page: Page,
  url: string,
  body: Readonly<Record<string, unknown>>,
): Promise<MutationResult> {
  return page.evaluate(
    async ({ target, document }) => {
      const response = await fetch(target, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(document),
      });
      const text = await response.text();
      let parsed: unknown = null;
      try {
        parsed = JSON.parse(text) as unknown;
      } catch {
        parsed = text;
      }
      return { body: parsed, status: response.status };
    },
    { target: url, document: body },
  );
}

async function raceHostedMutation(
  page: Page,
  url: string,
  body: Readonly<Record<string, unknown>>,
): Promise<readonly [MutationResult, MutationResult]> {
  return page.evaluate(
    async ({ target, document }) => {
      const submit = async () => {
        const response = await fetch(target, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(document),
        });
        const text = await response.text();
        let parsed: unknown = null;
        try {
          parsed = JSON.parse(text) as unknown;
        } catch {
          parsed = text;
        }
        return { body: parsed, status: response.status };
      };
      return Promise.all([submit(), submit()]);
    },
    { target: url, document: body },
  );
}

function parseNavigationUrl(value: unknown): string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("successful Hosted mutation omitted its navigation document");
  }
  const target = (value as Record<string, unknown>)["url"];
  if (typeof target !== "string" || target.length > 4096) {
    throw new Error("successful Hosted mutation returned an invalid navigation URL");
  }
  const parsed = new URL(target);
  if (parsed.origin !== applicationOrigin || parsed.pathname !== "/browser/callback") {
    throw new Error("successful reuse escaped the controlled Application callback");
  }
  return parsed.href;
}

async function observedBootstrap(evidence: BrowserEvidence, url: string): Promise<HostedBootstrap> {
  await expect
    .poll(
      async () => {
        await evidence.settle();
        return evidence.responses
          .filter((record) => record.url === url)
          .map((record) => parseHostedBootstrap(record.body))
          .find((bootstrap) => bootstrap !== null);
      },
      { timeout: 10_000 },
    )
    .toBeDefined();
  const bootstrap = evidence.responses
    .filter((record) => record.url === url)
    .map((record) => parseHostedBootstrap(record.body))
    .find((candidate) => candidate !== null);
  if (bootstrap === undefined) throw new Error("Hosted bootstrap observation disappeared");
  return bootstrap;
}

async function assertEvidenceConfinement(
  evidences: readonly BrowserEvidence[],
  additionalSnapshots: readonly BrowserEvidenceSnapshot[] = [],
): Promise<readonly BrowserEvidenceSnapshot[]> {
  const snapshots = [
    ...(await Promise.all(evidences.map(async (evidence) => evidence.snapshot()))),
    ...additionalSnapshots,
  ];
  const secrets = evidenceSecrets(snapshots);
  const runtimeCookies = runtimeCookieSecrets(snapshots);
  expect(runtimeCookies.length, "no Runtime browser cookie evidence was captured").toBeGreaterThan(
    0,
  );

  for (const snapshot of snapshots) {
    expect(snapshot.pageCount, "browser context evidence did not own any page").toBeGreaterThan(0);
    const consoleDocument = snapshot.consoleMessages.join("\n");
    for (const secret of secrets) {
      expect(
        !consoleDocument.includes(secret.value),
        `${secret.kind} escaped into a browser console message`,
      ).toBe(true);
      expect(
        !snapshot.storageState.includes(secret.value),
        `${secret.kind} escaped into final browser-context storage state`,
      ).toBe(true);
    }
    for (const record of snapshot.requests) assertRequestConfinement(record, secrets);
    for (const record of snapshot.responses) assertResponseConfinement(record, secrets);
    for (const sample of snapshot.lifecycle) assertLifecycleConfinement(sample, secrets);
    assertRuntimeCookieConfinement(snapshot, runtimeCookies);
    const initializedPages = new Set(
      snapshot.lifecycle
        .filter(({ reason }) => reason !== "navigation")
        .map(({ pageId }) => pageId),
    );
    expect(
      initializedPages.size,
      "init-script lifecycle observation did not cover every browser page",
    ).toBe(snapshot.pageCount);
  }
  return snapshots;
}

function evidenceSecrets(snapshots: readonly BrowserEvidenceSnapshot[]): readonly SecretValue[] {
  const remembered = new Map<string, SecretValue>();
  const remember = (kind: SecretKind, value: unknown): void => {
    if (typeof value !== "string" || value.length < 16) return;
    remembered.set(`${kind}:${value}`, { kind, value });
  };
  const captureHandoff = (value: string): void => {
    try {
      remember("handoff", new URL(value).searchParams.get("handoff"));
    } catch {
      // Only absolute observed URLs are relevant.
    }
  };

  for (const snapshot of snapshots) {
    for (const record of [...snapshot.requests, ...snapshot.responses]) {
      captureHandoff(record.url);
      let url: URL;
      try {
        url = new URL(record.url);
      } catch {
        continue;
      }
      const document = parseJsonObject(record.body);
      if (
        isRuntimeRecord(record, url, "POST", projectRoute("auth/handoff/exchange")) ||
        isRuntimeRecord(record, url, "POST", projectRoute("auth/sessions/refresh"))
      ) {
        remember("access", document?.["access_token"]);
        remember("refresh", document?.["refresh_token"]);
      }
      if (isRuntimeRecord(record, url, "POST", projectRoute("auth/browser-logout/prepare"))) {
        const hostedUrl = document?.["hosted_url"];
        if (typeof hostedUrl === "string") {
          try {
            const parsed = new URL(hostedUrl);
            const preparation = runtimeRouteMatch(parsed, /^auth\/browser-logout\/([^/]+)$/u)?.[1];
            remember("preparation", preparation);
          } catch {
            // Invalid navigation is rejected by the SDK; evidence collection remains passive.
          }
        }
      }
      if (
        isRuntimeRecord(
          record,
          url,
          "POST",
          projectRoute("auth/interactions/[^/]+/session/reuse"),
        ) &&
        typeof document?.["url"] === "string"
      ) {
        captureHandoff(document["url"]);
      }
      if (isRuntimeRecord(record, url, "GET", /^auth\/(?:interactions|browser-logout)\/[^/]+$/u)) {
        const bootstrap = parseHostedBootstrap(record.body);
        if (bootstrap !== null) remember("csrf", bootstrap.csrf);
      }
    }
  }
  return [...remembered.values()];
}

function runtimeCookieSecrets(
  snapshots: readonly BrowserEvidenceSnapshot[],
): readonly RuntimeCookieSecret[] {
  const expectedPath = runtimeCookiePath();
  const secrets = new Map<string, RuntimeCookieSecret>();
  const events: RuntimeCookieEvent[] = [];
  for (const snapshot of snapshots) {
    for (const response of snapshot.responses) {
      for (const header of response.headers) {
        if (header.name.toLowerCase() !== "set-cookie") continue;
        const parsed = parseSetCookie(header.value);
        const kind = runtimeCookieKind(parsed.name);
        if (runtimeCookieCandidate(parsed.name)) {
          expect(kind, `${parsed.name} did not use an exact Runtime cookie name`).not.toBeNull();
        }
        if (kind === null) continue;
        const disposition = parsed.value === "deleted" ? "deletion" : "issuance";
        assertRuntimeCookieLine(response, parsed, kind, disposition, expectedPath);
        events.push({ disposition, kind, name: parsed.name, value: parsed.value });
        if (disposition === "issuance") {
          secrets.set(`${parsed.name}:${parsed.value}`, {
            kind,
            name: parsed.name,
            path: expectedPath,
            value: parsed.value,
          });
        }
      }
    }
  }

  const issuedNames = new Set(
    events.filter(({ disposition }) => disposition === "issuance").map(({ name }) => name),
  );
  for (const event of events) {
    if (event.disposition === "deletion") {
      expect(
        issuedNames.has(event.name),
        `${event.kind} cookie deletion was not correlated with an observed issuance`,
      ).toBe(true);
    }
  }
  return [...secrets.values()];
}

function assertRuntimeCookieLine(
  response: NetworkRecord,
  parsed: ParsedSetCookie,
  kind: RuntimeCookieKind,
  disposition: RuntimeCookieEvent["disposition"],
  expectedPath: string,
): void {
  const expectedAttributes = new Set(["httponly", "max-age", "path", "samesite", "secure"]);
  expect(
    new Set(parsed.attributes.keys()),
    `${parsed.name} used missing, Domain, or unexpected cookie attributes`,
  ).toEqual(expectedAttributes);
  expect(parsed.attributes.get("path"), `${parsed.name} used the wrong Path`).toBe(expectedPath);
  expect(parsed.attributes.get("secure"), `${parsed.name} omitted Secure`).toBe("");
  expect(parsed.attributes.get("httponly"), `${parsed.name} omitted HttpOnly`).toBe("");
  expect(parsed.attributes.get("samesite"), `${parsed.name} used the wrong SameSite`).toBe("Lax");

  const expectedMaxAge =
    disposition === "deletion" ? "0" : kind === "interaction" ? "600" : "86400";
  expect(
    parsed.attributes.get("max-age"),
    `${parsed.name} used the wrong kind-specific Max-Age`,
  ).toBe(expectedMaxAge);
  if (disposition === "issuance") {
    expect(
      parsed.value.length,
      `${parsed.name} had a short credential value`,
    ).toBeGreaterThanOrEqual(16);
  }

  let url: URL;
  try {
    url = new URL(response.url);
  } catch {
    throw new Error(`${parsed.name} was set on a malformed response URL`);
  }
  expect(
    isRuntimeCookieRoute(response, url, kind, disposition),
    `${parsed.name} ${disposition} used an unreviewed Runtime origin, route, or method`,
  ).toBe(true);
}

function isRuntimeCookieRoute(
  record: NetworkRecord,
  url: URL,
  kind: RuntimeCookieKind,
  disposition: RuntimeCookieEvent["disposition"],
): boolean {
  const providerCallback = /^projects\/[^/]+\/auth\/callback\/[^/]+$/u;
  if (kind === "interaction" && disposition === "issuance") {
    return isRuntimeRecord(record, url, "GET", /^auth\/interactions\/[^/]+$/u);
  }
  if (kind === "interaction") {
    return (
      isRuntimeRecord(record, url, "GET", providerCallback) ||
      isRuntimeRecord(record, url, "POST", projectRoute("auth/interactions/[^/]+/session/reuse"))
    );
  }
  if (disposition === "issuance") {
    return isRuntimeRecord(record, url, "GET", providerCallback);
  }
  return isRuntimeRecord(record, url, "POST", projectRoute("auth/browser-logout/[^/]+/confirm"));
}

function assertRuntimeCookieConfinement(
  snapshot: BrowserEvidenceSnapshot,
  secrets: readonly RuntimeCookieSecret[],
): void {
  const runtimeOrigin = runtimeUrl().origin;
  for (const secret of secrets) {
    const consoleDocument = snapshot.consoleMessages.join("\n");
    expect(consoleDocument, `${secret.kind} cookie escaped into browser console`).not.toContain(
      secret.value,
    );
    for (const request of snapshot.requests) {
      expect(request.url, `${secret.kind} cookie escaped into a request URL`).not.toContain(
        secret.value,
      );
      expect(request.body, `${secret.kind} cookie escaped into a request body`).not.toContain(
        secret.value,
      );
      for (const header of request.headers) {
        if (!header.value.includes(secret.value)) continue;
        expect(header.name.toLowerCase(), `${secret.kind} cookie used a non-Cookie header`).toBe(
          "cookie",
        );
        expect(
          parseCookieHeader(header.value).get(secret.name),
          `${secret.kind} cookie header did not preserve its exact name/value pair`,
        ).toBe(secret.value);
        const requestUrl = new URL(request.url);
        expect(requestUrl.origin, `${secret.kind} cookie escaped the Runtime origin`).toBe(
          runtimeOrigin,
        );
        expect(
          pathContains(secret.path, requestUrl.pathname),
          `${secret.kind} cookie escaped its Runtime Path`,
        ).toBe(true);
      }
    }
    for (const response of snapshot.responses) {
      expect(response.url, `${secret.kind} cookie escaped into a response URL`).not.toContain(
        secret.value,
      );
      expect(response.body, `${secret.kind} cookie escaped into a response body`).not.toContain(
        secret.value,
      );
      for (const header of response.headers) {
        if (!header.value.includes(secret.value)) continue;
        expect(
          header.name.toLowerCase(),
          `${secret.kind} cookie used a non-Set-Cookie response header`,
        ).toBe("set-cookie");
        const parsed = parseSetCookie(header.value);
        expect(parsed.name).toBe(secret.name);
        expect(parsed.value).toBe(secret.value);
        expect(new URL(response.url).origin, `${secret.kind} cookie was set outside Runtime`).toBe(
          runtimeOrigin,
        );
      }
    }
    for (const sample of snapshot.lifecycle) {
      for (const [surface, document] of [
        ["page URL", sample.url],
        ["DOM", sample.html],
        ["page text", sample.body],
        ["history.state", sample.history],
        ["document.cookie", sample.cookies],
        ["localStorage", JSON.stringify(sample.local)],
        ["sessionStorage", JSON.stringify(sample.session)],
      ] as const) {
        expect(document, `${secret.kind} HttpOnly cookie escaped into ${surface}`).not.toContain(
          secret.value,
        );
      }
    }
  }

  const stored = parseStorageCookies(snapshot.storageState);
  for (const cookie of stored) {
    const kind = runtimeCookieKind(cookie.name);
    if (runtimeCookieCandidate(cookie.name)) {
      expect(kind, `${cookie.name} did not use an exact Runtime cookie name`).not.toBeNull();
    }
    if (kind === null) continue;
    const issued = secrets.find(
      ({ name, value }) => name === cookie.name && value === cookie.value,
    );
    expect(issued, `${kind} cookie in storage was not observed in a Set-Cookie line`).toBeDefined();
    expect(cookie.domain).toBe(runtimeUrl().hostname);
    expect(cookie.path).toBe(runtimeCookiePath());
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.secure).toBe(true);
    expect(cookie.sameSite).toBe("Lax");
  }

  for (const request of snapshot.requests) {
    for (const header of request.headers) {
      if (header.name.toLowerCase() !== "cookie") continue;
      for (const [name, value] of parseCookieHeader(header.value)) {
        const kind = runtimeCookieKind(name);
        if (runtimeCookieCandidate(name)) {
          expect(kind, `${name} did not use an exact Runtime cookie name`).not.toBeNull();
        }
        if (kind === null) continue;
        const issued = secrets.find((secret) => secret.name === name && secret.value === value);
        expect(
          issued,
          `${kind} request cookie was not observed in Set-Cookie evidence`,
        ).toBeDefined();
        const requestUrl = new URL(request.url);
        expect(requestUrl.origin, `${kind} cookie reached a non-Runtime plane`).toBe(runtimeOrigin);
        expect(
          issued === undefined ? false : pathContains(issued.path, requestUrl.pathname),
          `${kind} request cookie escaped its Runtime Path`,
        ).toBe(true);
      }
    }
  }
}

function runtimeCookieKind(name: string): RuntimeCookieKind | null {
  if (/^owl_runtime_[A-Za-z0-9_-]{24}$/u.test(name)) return "interaction";
  if (/^owl_project_[A-Za-z0-9_-]{24}$/u.test(name)) return "project";
  return null;
}

function runtimeCookieCandidate(name: string): boolean {
  return name.startsWith("owl_runtime_") || name.startsWith("owl_project_");
}

function parseSetCookie(value: string): ParsedSetCookie {
  const [pair, ...attributeParts] = value.split(";");
  const separator = pair?.indexOf("=") ?? -1;
  if (pair === undefined || separator <= 0) throw new Error("malformed Set-Cookie evidence");
  const attributes = new Map<string, string>();
  for (const part of attributeParts) {
    const trimmed = part.trim();
    const attributeSeparator = trimmed.indexOf("=");
    const name = (
      attributeSeparator === -1 ? trimmed : trimmed.slice(0, attributeSeparator)
    ).toLowerCase();
    if (name === "" || attributes.has(name)) {
      throw new Error("malformed or duplicate Set-Cookie attribute evidence");
    }
    attributes.set(name, attributeSeparator === -1 ? "" : trimmed.slice(attributeSeparator + 1));
  }
  return {
    attributes,
    name: pair.slice(0, separator).trim(),
    value: pair.slice(separator + 1),
  };
}

function parseCookieHeader(value: string): ReadonlyMap<string, string> {
  const cookies = new Map<string, string>();
  for (const part of value.split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) throw new Error("malformed Cookie evidence");
    const name = part.slice(0, separator).trim();
    if (cookies.has(name)) throw new Error("duplicate Cookie name evidence");
    cookies.set(name, part.slice(separator + 1));
  }
  return cookies;
}

function parseStorageCookies(storageState: string): readonly {
  readonly domain: string;
  readonly httpOnly: boolean;
  readonly name: string;
  readonly path: string;
  readonly sameSite: string;
  readonly secure: boolean;
  readonly value: string;
}[] {
  const parsed = JSON.parse(storageState) as unknown;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("malformed browser storage-state evidence");
  }
  const cookies = (parsed as Record<string, unknown>)["cookies"];
  if (!Array.isArray(cookies)) throw new Error("browser storage-state omitted cookies");
  return cookies as ReturnType<typeof parseStorageCookies>;
}

function pathContains(cookiePath: string, requestPath: string): boolean {
  return (
    requestPath === cookiePath ||
    requestPath.startsWith(cookiePath.endsWith("/") ? cookiePath : `${cookiePath}/`)
  );
}

function assertRequestConfinement(record: NetworkRecord, secrets: readonly SecretValue[]): void {
  const url = new URL(record.url);
  for (const secret of secrets) {
    if (record.url.includes(secret.value)) {
      expect(
        (secret.kind === "handoff" && record.method === "GET" && isCallbackUrl(url)) ||
          (secret.kind === "preparation" && isPreparationNetworkRoute(record, url, secret.value)),
        `${secret.kind} appeared in an unrelated request URL: ${url.pathname}`,
      ).toBe(true);
    }
    for (const header of record.headers) {
      if (!header.value.includes(secret.value)) continue;
      const name = header.name.toLowerCase();
      expect(
        secret.kind === "access" &&
          name === "authorization" &&
          header.value === `Bearer ${secret.value}` &&
          isReviewedAccessTokenRoute(record, url),
        `${secret.kind} appeared in unrelated request header ${header.name}: ${url.pathname}`,
      ).toBe(true);
    }
    if (record.body.includes(secret.value)) {
      expect(
        (secret.kind === "refresh" &&
          isRuntimeRecord(record, url, "POST", projectRoute("auth/sessions/refresh"))) ||
          (secret.kind === "handoff" &&
            isRuntimeRecord(record, url, "POST", projectRoute("auth/handoff/exchange"))) ||
          (secret.kind === "csrf" && isReviewedCsrfMutation(record, url)),
        `${secret.kind} appeared in an unrelated request body: ${url.pathname}`,
      ).toBe(true);
    }
  }
}

function assertResponseConfinement(record: NetworkRecord, secrets: readonly SecretValue[]): void {
  const url = new URL(record.url);
  for (const secret of secrets) {
    if (record.url.includes(secret.value)) {
      expect(
        (secret.kind === "handoff" && record.method === "GET" && isCallbackUrl(url)) ||
          (secret.kind === "preparation" && isPreparationNetworkRoute(record, url, secret.value)),
        `${secret.kind} appeared in an unrelated response URL: ${url.pathname}`,
      ).toBe(true);
    }
    for (const header of record.headers) {
      if (!header.value.includes(secret.value)) continue;
      const name = header.name.toLowerCase();
      let location: URL | null = null;
      if (name === "location") {
        try {
          location = new URL(header.value, record.url);
        } catch {
          // The assertion below rejects the malformed sensitive location.
        }
      }
      expect(
        secret.kind === "handoff" &&
          location !== null &&
          isCallbackUrl(location) &&
          isRuntimeRecord(record, url, "GET", /^projects\/[^/]+\/auth\/callback\/[^/]+$/u),
        `${secret.kind} appeared in unrelated response header ${header.name}: ${url.pathname}`,
      ).toBe(true);
    }
    if (record.body.includes(secret.value)) {
      const credentialResponse =
        isRuntimeRecord(record, url, "POST", projectRoute("auth/handoff/exchange")) ||
        isRuntimeRecord(record, url, "POST", projectRoute("auth/sessions/refresh"));
      expect(
        ((secret.kind === "access" || secret.kind === "refresh") && credentialResponse) ||
          (secret.kind === "preparation" &&
            isRuntimeRecord(record, url, "POST", projectRoute("auth/browser-logout/prepare"))) ||
          (secret.kind === "csrf" &&
            isRuntimeRecord(
              record,
              url,
              "GET",
              /^auth\/(?:interactions|browser-logout)\/[^/]+$/u,
            )) ||
          (secret.kind === "handoff" &&
            isRuntimeRecord(
              record,
              url,
              "POST",
              projectRoute("auth/interactions/[^/]+/session/reuse"),
            )),
        `${secret.kind} appeared in an unrelated response body: ${url.pathname}`,
      ).toBe(true);
    }
  }
}

function assertLifecycleConfinement(
  sample: LifecycleSample,
  secrets: readonly SecretValue[],
): void {
  let url: URL | null = null;
  try {
    url = new URL(sample.url);
  } catch {
    // about:blank and incomplete navigation samples contain no sensitive material.
  }
  expect(sample.local, `page ${String(sample.pageId)} wrote localStorage`).toEqual([]);
  expect(sample.session, `page ${String(sample.pageId)} wrote sessionStorage`).toEqual([]);

  for (const secret of secrets) {
    const allowedUrl =
      url !== null &&
      ((secret.kind === "handoff" && isCallbackUrl(url)) ||
        (secret.kind === "preparation" && isLogoutPreparationUrl(url, secret.value)));
    expect(
      !sample.url.includes(secret.value) || allowedUrl,
      `${secret.kind} escaped into ${sample.reason} page URL`,
    ).toBe(true);

    const bootstrapDom =
      secret.kind === "csrf" &&
      url !== null &&
      isHostedBootstrapUrl(url) &&
      sample.html.includes('name="owlauth-runtime-bootstrap"');
    expect(
      !sample.body.includes(secret.value) || bootstrapDom,
      `${secret.kind} escaped into ${sample.reason} page text`,
    ).toBe(true);
    expect(
      !sample.html.includes(secret.value) || bootstrapDom,
      `${secret.kind} escaped into ${sample.reason} page DOM`,
    ).toBe(true);
    expect(
      !sample.history.includes(secret.value),
      `${secret.kind} escaped into ${sample.reason} history.state`,
    ).toBe(true);
    expect(
      !sample.cookies.includes(secret.value),
      `${secret.kind} escaped into ${sample.reason} document.cookie`,
    ).toBe(true);
  }
}

function isCallbackUrl(url: URL): boolean {
  return (
    url.origin === applicationOrigin &&
    ["/backend/callback", "/browser/callback", "/sdk/callback"].includes(url.pathname)
  );
}

function isHostedBootstrapUrl(url: URL): boolean {
  return runtimeRouteMatch(url, /^auth\/(?:interactions|browser-logout)\/[^/]+$/u) !== null;
}

function isLogoutPreparationUrl(url: URL, preparation: string): boolean {
  const match = runtimeRouteMatch(url, /^auth\/browser-logout\/([^/]+)$/u);
  return match?.[1] === preparation;
}

function isPreparationNetworkRoute(record: NetworkRecord, url: URL, preparation: string): boolean {
  return (
    (record.method === "GET" && isLogoutPreparationUrl(url, preparation)) ||
    (record.method === "POST" &&
      runtimeRouteMatch(url, projectRoute("auth/browser-logout/([^/]+)/confirm"))?.[1] ===
        preparation)
  );
}

function isReviewedAccessTokenRoute(record: NetworkRecord, url: URL): boolean {
  return (
    isRuntimeRecord(record, url, "GET", projectRoute("auth/users/me")) ||
    isRuntimeRecord(record, url, "POST", projectRoute("auth/sessions/logout")) ||
    isRuntimeRecord(record, url, "POST", projectRoute("auth/browser-logout/prepare"))
  );
}

function isReviewedCsrfMutation(record: NetworkRecord, url: URL): boolean {
  return (
    isRuntimeRecord(record, url, "POST", projectRoute("auth/interactions/[^/]+/method")) ||
    isRuntimeRecord(record, url, "POST", projectRoute("auth/interactions/[^/]+/session/reuse")) ||
    isRuntimeRecord(record, url, "POST", projectRoute("auth/browser-logout/[^/]+/confirm"))
  );
}

function runtimeUrl(): URL {
  return new URL(runtimeBase);
}

function runtimeCookiePath(): string {
  const path = runtimeUrl().pathname;
  return path.endsWith("/") ? path : `${path}/`;
}

function runtimeRouteMatch(url: URL, route: RegExp): RegExpExecArray | null {
  const runtime = runtimeUrl();
  if (url.origin !== runtime.origin) return null;
  const basePath = runtimeCookiePath();
  if (!url.pathname.startsWith(basePath)) return null;
  const relative = url.pathname.slice(basePath.length);
  return route.exec(relative);
}

function isRuntimeRecord(
  record: NetworkRecord,
  url: URL,
  method: "GET" | "POST",
  route: RegExp,
): boolean {
  return record.method === method && runtimeRouteMatch(url, route) !== null;
}

function projectRoute(suffix: string): RegExp {
  return new RegExp(`^v1/projects/[^/]+/${suffix}$`, "u");
}

async function currentSecrets(evidence: BrowserEvidence): Promise<readonly SecretValue[]> {
  await evidence.settle();
  return evidenceSecrets([
    {
      consoleMessages: evidence.consoleMessages,
      lifecycle: evidence.lifecycle,
      pageCount: evidence.pages().length,
      requests: evidence.requests,
      responses: evidence.responses,
      storageState: "",
    },
  ]);
}

async function assertPageSecretFree(page: Page, secrets: readonly SecretValue[]): Promise<void> {
  const state = await page.evaluate(async () => ({
    body: document.body.textContent,
    html: document.documentElement.outerHTML,
    url: location.href,
    history: JSON.stringify(history.state),
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
    cookies: document.cookie,
    caches: await caches.keys(),
    databases:
      typeof indexedDB.databases === "function"
        ? (await indexedDB.databases()).map((database) => database.name)
        : [],
  }));
  expect(state.caches).toEqual([]);
  expect(state.databases).toEqual([]);
  assertLifecycleConfinement(
    {
      body: state.body,
      cookies: state.cookies,
      history: state.history,
      html: state.html,
      local: state.local,
      pageId: 0,
      reason: "explicit assertion",
      session: state.session,
      url: state.url,
    },
    secrets,
  );
}
async function runSdkE2Es(
  context: ProvisionedContext,
  publishableKey: string,
  browserName: "chromium" | "firefox",
): Promise<readonly BrowserEvidenceSnapshot[]> {
  const repository = resolve(import.meta.dirname, "../../../..");
  const evidenceRunId = `${browserName}-${randomBytes(18).toString("base64url")}`;
  const sharedEnvironment = {
    ...process.env,
    OWLAUTH_E2E_ALLOW_INSECURE_LOOPBACK: "1",
    OWLAUTH_E2E_APPLICATION_ID: context.application.public_id,
    OWLAUTH_E2E_PROJECT_ID: context.project.public_id,
    OWLAUTH_E2E_PUBLISHABLE_KEY: publishableKey,
    OWLAUTH_E2E_REDIRECT_URI: `${applicationOrigin}/sdk/callback`,
  };
  await runSdkCommand(
    repository,
    "TypeScript",
    "pnpm",
    ["--filter", "@owlauth/client", "test:e2e:built"],
    {
      ...sharedEnvironment,
      OWLAUTH_E2E_BROWSER_DRIVER_TOKEN: browserDriverToken,
      OWLAUTH_E2E_BROWSER_DRIVER_URL: browserDriverUrl,
      OWLAUTH_E2E_BROWSER_EVIDENCE_RUN_ID: evidenceRunId,
      OWLAUTH_E2E_BROWSER_NAME: browserName,
      OWLAUTH_E2E_PROVIDER_KEY: "controlled-provider",
      OWLAUTH_E2E_RUNTIME_BASE_URL: runtimeBase,
    },
    "TypeScript real-server Project Auth E2E passed.",
  );
  const unauthorizedDrain = await fetch(new URL("/sdk/browser-evidence/drain", browserDriverUrl), {
    body: JSON.stringify({ runId: evidenceRunId }),
    headers: { "content-type": "application/json" },
    method: "POST",
    redirect: "error",
  });
  expect(unauthorizedDrain.status).toBe(401);
  expect(await drainSdkBrowserEvidence(`${evidenceRunId}-isolated`)).toEqual([]);
  const browserEvidence = await drainSdkBrowserEvidence(evidenceRunId);
  expect(
    browserEvidence,
    "TypeScript SDK must drive and report both browser journeys",
  ).toHaveLength(2);
  if (browserName !== "chromium") return browserEvidence;

  // Python and Rust exercise raw HTTP SDK transports; they are deliberately not
  // represented as browser contexts in the confinement evidence union.
  await runSdkCommand(
    repository,
    "Python",
    "uv",
    ["run", "--project", "sdks/python", "python", "sdks/python/tests/runtime_e2e.py"],
    { ...sharedEnvironment, OWLAUTH_E2E_RUNTIME_URL: runtimeBase },
    "Python SDK real-Runtime Project Auth E2E passed",
  );
  await runSdkCommand(
    repository,
    "Rust",
    "cargo",
    [
      "test",
      "-p",
      "owlauth-client",
      "--test",
      "server_e2e",
      "--",
      "--ignored",
      "--exact",
      "real_runtime_project_auth_lifecycle",
    ],
    {
      ...sharedEnvironment,
      OWLAUTH_E2E_PROVIDER_KEY: "controlled-provider",
      OWLAUTH_E2E_RUNTIME_URL: runtimeBase,
    },
    "test real_runtime_project_auth_lifecycle ... ok",
  );
  return browserEvidence;
}

async function drainSdkBrowserEvidence(runId: string): Promise<readonly BrowserEvidenceSnapshot[]> {
  const drainUrl = new URL("/sdk/browser-evidence/drain", browserDriverUrl);
  const response = await fetch(drainUrl, {
    body: JSON.stringify({ runId }),
    headers: {
      accept: "application/json",
      authorization: `Bearer ${browserDriverToken}`,
      "content-type": "application/json",
    },
    method: "POST",
    redirect: "error",
  });
  expect(response.status).toBe(200);
  const document = (await response.json()) as { evidence?: unknown };
  if (!Array.isArray(document.evidence)) throw new Error("browser evidence drain was malformed");
  return document.evidence as BrowserEvidenceSnapshot[];
}

async function runSdkCommand(
  repository: string,
  sdk: string,
  executable: string,
  arguments_: string[],
  environment: NodeJS.ProcessEnv,
  successMarker: string,
): Promise<void> {
  await new Promise<void>((resolveRun, reject) => {
    execFile(
      executable,
      arguments_,
      { cwd: repository, env: environment, maxBuffer: 1024 * 1024, timeout: 180_000 },
      (error, stdout, stderr) => {
        if (error === null) {
          expect(stdout).toContain(successMarker);
          resolveRun();
          return;
        }
        reject(
          new Error(
            `${sdk} SDK real-server command failed: ${error.message}\n${stdout}\n${stderr}`,
          ),
        );
      },
    );
  });
}

async function provision(request: APIRequestContext, suffix: string): Promise<ProvisionedContext> {
  const project = await control<Project>(
    request,
    "POST",
    "projects",
    {
      display_name: `E2E Project ${suffix}`,
      belongs_to: null,
    },
    `project-${suffix}`,
  );
  let policy = await controlGet<ProjectPolicy>(request, `projects/${project.id}/policy`);
  policy = await control<ProjectPolicy>(request, "PUT", `projects/${project.id}/policy`, {
    access_token_lifetime_seconds: policy.access_token_lifetime_seconds,
    browser_session_reuse: true,
    expected_claims_revision: policy.claims_revision,
    expected_session_revision: policy.session_revision,
  });
  expect(policy.browser_session_reuse).toBe(true);
  const otherProject = await control<Project>(
    request,
    "POST",
    "projects",
    {
      display_name: `Isolated Project ${suffix}`,
      belongs_to: null,
    },
    `other-project-${suffix}`,
  );
  let application = await control<Application>(
    request,
    "POST",
    `projects/${project.id}/applications`,
    { application_type: "web", display_name: "E2E Application" },
    `application-${suffix}`,
  );
  application = await control<Application>(
    request,
    "PUT",
    `projects/${project.id}/applications/${application.id}/configuration`,
    {
      allowed_origins: [applicationOrigin],
      expected_security_revision: application.security_revision,
      redirect_uris: [
        `${applicationOrigin}/browser/callback`,
        `${applicationOrigin}/backend/callback`,
        `${applicationOrigin}/sdk/callback`,
      ],
    },
  );
  let otherApplication = await control<Application>(
    request,
    "POST",
    `projects/${project.id}/applications`,
    { application_type: "web", display_name: "Other Application" },
    `other-application-${suffix}`,
  );
  otherApplication = await control<Application>(
    request,
    "PUT",
    `projects/${project.id}/applications/${otherApplication.id}/configuration`,
    {
      allowed_origins: ["https://other-application.example"],
      expected_security_revision: otherApplication.security_revision,
      redirect_uris: ["https://other-application.example/callback"],
    },
  );

  const signingKey = await control<SigningKey>(
    request,
    "POST",
    `projects/${project.id}/signing-keys`,
    { expected_project_revision: project.metadata_revision },
    `signing-key-${suffix}`,
  );
  const jwks = await request.get(
    `${runtimeBase}projects/${encodeURIComponent(project.public_id)}/.well-known/jwks.json`,
  );
  expect(jwks.ok()).toBe(true);
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 150));
  await control<SigningKey>(
    request,
    "POST",
    `projects/${project.id}/signing-keys/${signingKey.id}/activate`,
    { expected_ring_revision: signingKey.ring_revision },
  );

  const provider = await control<Provider>(
    request,
    "POST",
    `projects/${project.id}/providers`,
    {
      client_id: providerClientId,
      client_secret: providerClientSecret,
      display_name: "Controlled Provider",
      expected_project_revision: project.metadata_revision,
      issuer: providerOrigin,
      provider_key: "controlled-provider",
    },
    `provider-${suffix}`,
  );
  await control<Provider>(
    request,
    "PUT",
    `projects/${project.id}/providers/${provider.id}/assignments/${application.id}`,
    { expected_application_revision: application.security_revision },
  );
  return {
    application,
    claimsRevision: policy.claims_revision,
    otherApplication,
    otherProject,
    project,
  };
}

async function controlGet<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(`${controlBase}v1/${path}`, {
    headers: { authorization: `Bearer ${operatorKey}` },
  });
  expect(response.ok(), `GET ${path}: ${await response.text()}`).toBe(true);
  return (await response.json()) as T;
}

async function control<T>(
  request: APIRequestContext,
  method: "POST" | "PUT",
  path: string,
  data: unknown,
  idempotencyKey?: string,
): Promise<T> {
  const response = await request.fetch(`${controlBase}v1/${path}`, {
    data,
    headers: {
      authorization: `Bearer ${operatorKey}`,
      ...(idempotencyKey === undefined ? {} : { "idempotency-key": idempotencyKey }),
    },
    method,
  });
  expect(response.ok(), `${method} ${path}: ${await response.text()}`).toBe(true);
  return (await response.json()) as T;
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}
