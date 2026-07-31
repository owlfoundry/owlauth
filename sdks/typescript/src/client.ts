import { OwlAuthError, configurationError, type CallerAction, type ErrorCategory } from "./errors.js";
import {
  AccessToken,
  type BrowserLogoutPreparation,
  CredentialPair,
  type CurrentUser,
  type LoginStartResult,
  type OperationOptions,
  PendingLogin,
  PkceVerifier,
  type ProjectJwks,
  type PublicApplicationConfiguration,
  type PublicJwk,
  type PublicProvider,
  type UserProjection,
  ValidatedCallback,
} from "./types.js";

const MAX_RESPONSE_BYTES = 65_536;
const MAX_ID_LENGTH = 96;
const MAX_PUBLISHABLE_KEY_LENGTH = 128;
const MAX_REDIRECT_LENGTH = 2_048;
const MAX_STATE_LENGTH = 1_024;
const MAX_HINT_LENGTH = 64;
const MAX_HANDOFF_LENGTH = 256;
const DEFAULT_TIMEOUT_MS = 10_000;
const TOKEN_PATTERN = /^[A-Za-z0-9._~-]+$/u;

export interface CryptoProvider {
  getRandomValues<T extends ArrayBufferView | null>(array: T): T;
  readonly subtle: SubtleCrypto;
}

export interface ClientOptions {
  readonly baseUrl: string;
  readonly projectId: string;
  readonly applicationId: string;
  readonly publishableKey: string;
  readonly fetch?: typeof globalThis.fetch;
  readonly crypto?: CryptoProvider;
  readonly now?: () => number;
  readonly timeoutMs?: number;
  readonly allowInsecureLoopback?: boolean;
}

export interface BeginLoginOptions extends OperationOptions {
  readonly redirectUri: string;
  readonly state?: string;
  readonly presentationHint?: string;
}

interface RequestPolicy {
  readonly operation: string;
  readonly category: ErrorCategory;
  readonly sensitive: boolean;
  readonly action: CallerAction;
  readonly success: readonly number[];
}

interface RuntimeProblem {
  readonly code: string;
  readonly message: string;
  readonly requestId?: string;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedString(value: unknown, maximum: number, allowEmpty = false): value is string {
  return typeof value === "string" && value.length <= maximum && (allowEmpty || value.length > 0);
}

function positiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function validDate(value: unknown): value is string {
  return boundedString(value, 64) && Number.isFinite(Date.parse(value));
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function exactState(left: string, right: string): boolean {
  const encoder = new TextEncoder();
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return difference === 0;
}

function loopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function parseBaseUrl(value: string, allowInsecureLoopback: boolean): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw configurationError("invalid_base_url", "Runtime base URL must be absolute.");
  }
  if (
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    (url.protocol !== "https:" &&
      !(allowInsecureLoopback && url.protocol === "http:" && loopback(url.hostname)))
  ) {
    throw configurationError(
      "invalid_base_url",
      "Runtime base URL must use HTTPS and contain no credentials, query, or fragment.",
    );
  }
  if (!url.pathname.endsWith("/")) url.pathname += "/";
  return url;
}

function requireIdentifier(value: string, field: string, maximum = MAX_ID_LENGTH): string {
  if (!boundedString(value, maximum) || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw configurationError("invalid_configuration", `${field} is invalid.`);
  }
  return value;
}

function parseProblem(value: unknown): RuntimeProblem | null {
  if (!isObject(value)) return null;
  if (!boundedString(value["code"], 64) || !boundedString(value["message"], 256)) return null;
  const requestId = value["request_id"];
  if (requestId !== undefined && !boundedString(requestId, 128)) return null;
  return {
    code: value["code"],
    message: value["message"],
    ...(typeof requestId === "string" ? { requestId } : {}),
  };
}

function mapRuntimeError(
  problem: RuntimeProblem,
  status: number,
  policy: RequestPolicy,
): OwlAuthError {
  const rateLimited = status === 429 || problem.code === "rate_limited";
  const authentication = status === 401;
  let category: ErrorCategory = rateLimited
    ? "RateLimited"
    : authentication
      ? policy.operation === "refresh"
        ? "Refresh"
        : "Authentication"
      : policy.category;
  if (policy.operation === "refresh" && status >= 400 && status < 500) category = "Refresh";
  if (policy.operation === "exchange_handoff" && status >= 400 && status < 500) category = "Handoff";
  const action: CallerAction =
    category === "Refresh"
      ? "invalidate_credentials"
      : category === "Handoff"
        ? "discard_pending"
        : authentication
          ? "reauthenticate"
          : policy.action;
  return new OwlAuthError({
    category,
    code: problem.code,
    message: "OwlAuth Runtime rejected the request.",
    operation: policy.operation,
    retry: rateLimited ? "safe_after_delay" : "never",
    action,
    ...(problem.requestId === undefined ? {} : { requestId: problem.requestId }),
    status,
  });
}

async function readBounded(response: Response): Promise<unknown> {
  const declared = response.headers.get("content-length");
  if (declared !== null && Number(declared) > MAX_RESPONSE_BYTES) {
    throw new Error("response_too_large");
  }
  if (response.body === null) return null;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("response_too_large");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  if (length === 0) return null;
  return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
}

function parseProjection(value: unknown): UserProjection {
  if (!isObject(value)) throw new Error("invalid_projection");
  const displayName = value["display_name"];
  const pictureUrl = value["picture_url"];
  if (
    !boundedString(value["user_id"], 96) ||
    !positiveInteger(value["user_revision"]) ||
    !boundedString(value["projection_schema"], 64) ||
    !positiveInteger(value["projection_revision"]) ||
    !(displayName === null || boundedString(displayName, 128)) ||
    !(pictureUrl === null || boundedString(pictureUrl, 2_048)) ||
    !boundedString(value["status"], 32) ||
    !validDate(value["created_at"]) ||
    !validDate(value["updated_at"])
  ) {
    throw new Error("invalid_projection");
  }
  return {
    userId: value["user_id"],
    userRevision: value["user_revision"],
    projectionSchema: value["projection_schema"],
    projectionRevision: value["projection_revision"],
    displayName,
    pictureUrl,
    status: value["status"],
    createdAt: value["created_at"],
    updatedAt: value["updated_at"],
  };
}

/** Stateless, Project/Application-bound OwlAuth Runtime protocol client. */
export class Client {
  readonly baseUrl: string;
  readonly projectId: string;
  readonly applicationId: string;
  readonly publishableKey: string;
  readonly #base: URL;
  readonly #fetch: typeof globalThis.fetch;
  readonly #crypto: CryptoProvider;
  readonly #now: () => number;
  readonly #timeoutMs: number;

  constructor(options: ClientOptions) {
    this.#base = parseBaseUrl(options.baseUrl, options.allowInsecureLoopback ?? false);
    this.baseUrl = this.#base.href;
    this.projectId = requireIdentifier(options.projectId, "projectId");
    this.applicationId = requireIdentifier(options.applicationId, "applicationId");
    this.publishableKey = requireIdentifier(
      options.publishableKey,
      "publishableKey",
      MAX_PUBLISHABLE_KEY_LENGTH,
    );
    const fetchImplementation =
      options.fetch === undefined ? globalThis.fetch?.bind(globalThis) : options.fetch;
    const cryptoImplementation = options.crypto ?? globalThis.crypto;
    if (typeof fetchImplementation !== "function" || cryptoImplementation?.subtle === undefined) {
      throw configurationError("platform_unavailable", "Web fetch and Web Crypto are required.");
    }
    const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > 120_000) {
      throw configurationError("invalid_timeout", "timeoutMs must be between 1 and 120000.");
    }
    this.#fetch = fetchImplementation;
    this.#crypto = cryptoImplementation;
    this.#now = options.now ?? Date.now;
    this.#timeoutMs = timeout;
  }

  async getPublicConfiguration(options: OperationOptions = {}): Promise<PublicApplicationConfiguration> {
    const path = `v1/projects/${encodeURIComponent(this.projectId)}/auth/config`;
    const url = this.#url(path);
    url.searchParams.set("application_id", this.applicationId);
    const value = await this.#request(url, { method: "GET" }, options, {
      operation: "get_public_configuration",
      category: "Protocol",
      sensitive: false,
      action: "none",
      success: [200],
    });
    if (!isObject(value)) throw this.#protocol("invalid_response", "get_public_configuration");
    const providers = value["providers"];
    const keys = value["publishable_keys"];
    if (
      value["project_public_id"] !== this.projectId ||
      value["application_public_id"] !== this.applicationId ||
      !boundedString(value["project_display_name"], 128) ||
      !boundedString(value["application_display_name"], 128) ||
      !Array.isArray(keys) ||
      keys.length > 50 ||
      !keys.every((key) => boundedString(key, 128)) ||
      !keys.includes(this.publishableKey) ||
      !Array.isArray(providers) ||
      providers.length > 50 ||
      typeof value["login_available"] !== "boolean"
    ) {
      throw this.#protocol("context_mismatch", "get_public_configuration");
    }
    const mappedProviders: PublicProvider[] = providers.map((provider) => {
      if (
        !isObject(provider) ||
        !boundedString(provider["key"], 64) ||
        !boundedString(provider["display_name"], 128) ||
        !boundedString(provider["kind"], 32)
      ) {
        throw this.#protocol("invalid_response", "get_public_configuration");
      }
      return { key: provider["key"], displayName: provider["display_name"], kind: provider["kind"] };
    });
    return {
      projectId: this.projectId,
      projectDisplayName: value["project_display_name"],
      applicationId: this.applicationId,
      applicationDisplayName: value["application_display_name"],
      publishableKeys: [...keys],
      providers: mappedProviders,
      loginAvailable: value["login_available"],
    };
  }

  async getProjectJwks(options: OperationOptions = {}): Promise<ProjectJwks> {
    const value = await this.#request(
      this.#url(`projects/${encodeURIComponent(this.projectId)}/.well-known/jwks.json`),
      { method: "GET" },
      options,
      {
        operation: "get_project_jwks",
        category: "Protocol",
        sensitive: false,
        action: "none",
        success: [200],
      },
    );
    if (!isObject(value) || !positiveInteger(value["revision"]) || !positiveInteger(value["signing_epoch"])) {
      throw this.#protocol("invalid_response", "get_project_jwks");
    }
    const keys = value["keys"];
    if (!Array.isArray(keys) || keys.length > 100) throw this.#protocol("invalid_response", "get_project_jwks");
    const mapped: PublicJwk[] = keys.map((key) => {
      if (
        !isObject(key) ||
        key["kty"] !== "OKP" ||
        key["crv"] !== "Ed25519" ||
        key["alg"] !== "EdDSA" ||
        key["use"] !== "sig" ||
        !boundedString(key["kid"], 128) ||
        !boundedString(key["x"], 64)
      ) {
        throw this.#protocol("invalid_response", "get_project_jwks");
      }
      return { kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig", kid: key["kid"], x: key["x"] };
    });
    return { keys: mapped, revision: value["revision"], signingEpoch: value["signing_epoch"] };
  }

  async beginLogin(input: BeginLoginOptions): Promise<LoginStartResult> {
    const redirect = this.#redirect(input.redirectUri);
    const state = input.state ?? this.#random(24);
    if (!boundedString(state, MAX_STATE_LENGTH) || !TOKEN_PATTERN.test(state)) {
      throw configurationError("invalid_state", "Application state is invalid.");
    }
    if (input.presentationHint !== undefined && !boundedString(input.presentationHint, MAX_HINT_LENGTH)) {
      throw configurationError("invalid_presentation_hint", "Presentation hint is invalid.");
    }
    const verifier = new PkceVerifier(this.#random(32));
    const challenge = base64Url(
      new Uint8Array(await this.#crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier.expose()))),
    );
    const createdAt = this.#now();
    const value = await this.#request(
      this.#url(`v1/projects/${encodeURIComponent(this.projectId)}/auth/login/start`),
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          application_id: this.applicationId,
          publishable_key: this.publishableKey,
          redirect_uri: redirect.href,
          pkce_challenge: challenge,
          state,
          ...(input.presentationHint === undefined ? {} : { presentation_hint: input.presentationHint }),
        }),
      },
      input,
      { operation: "begin_login", category: "Login", sensitive: false, action: "discard_pending", success: [201] },
    );
    if (!isObject(value) || !boundedString(value["hosted_url"], 512) || !validDate(value["expires_at"])) {
      throw this.#protocol("invalid_response", "begin_login");
    }
    const hosted = this.#serverUrl(value["hosted_url"], "begin_login");
    const expiresAt = Date.parse(value["expires_at"]);
    if (expiresAt <= createdAt) throw this.#protocol("invalid_response", "begin_login");
    return {
      hostedUrl: hosted.href,
      pending: new PendingLogin({
        runtimeOrigin: this.#base.origin,
        runtimeBasePath: this.#base.pathname,
        projectId: this.projectId,
        applicationId: this.applicationId,
        redirectUri: redirect.href,
        state,
        createdAt,
        expiresAt,
        verifier,
      }),
    };
  }

  validateCallback(callbackUrl: string, pending: PendingLogin): ValidatedCallback {
    const verifier = pending.consume();
    if (verifier === null) throw this.#handoff("pending_consumed");
    if (
      pending.runtimeOrigin !== this.#base.origin ||
      pending.runtimeBasePath !== this.#base.pathname ||
      pending.projectId !== this.projectId ||
      pending.applicationId !== this.applicationId ||
      this.#now() >= pending.expiresAt
    ) {
      throw this.#handoff("pending_context_mismatch");
    }
    let callback: URL;
    try {
      callback = new URL(callbackUrl);
    } catch {
      throw this.#handoff("invalid_callback");
    }
    const handoffs = callback.searchParams.getAll("handoff");
    const states = callback.searchParams.getAll("state");
    if (
      callback.hash !== "" ||
      handoffs.length !== 1 ||
      states.length !== 1 ||
      !boundedString(handoffs[0], MAX_HANDOFF_LENGTH) ||
      !exactState(states[0] ?? "", pending.state)
    ) {
      throw this.#handoff("invalid_callback");
    }
    callback.searchParams.delete("handoff");
    callback.searchParams.delete("state");
    if (callback.href !== pending.redirectUri) throw this.#handoff("redirect_mismatch");
    return new ValidatedCallback(handoffs[0], verifier);
  }

  async exchangeHandoff(
    callback: ValidatedCallback,
    options: OperationOptions = {},
  ): Promise<CredentialPair> {
    const material = callback.consume();
    if (material === null) throw this.#handoff("handoff_already_attempted");
    const value = await this.#request(
      this.#url(`v1/projects/${encodeURIComponent(this.projectId)}/auth/handoff/exchange`),
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          application_id: this.applicationId,
          publishable_key: this.publishableKey,
          handoff: material.handoff,
          pkce_verifier: material.verifier.expose(),
        }),
      },
      options,
      { operation: "exchange_handoff", category: "Handoff", sensitive: true, action: "quarantine_pending", success: [200] },
    );
    return this.#credentials(value, "exchange_handoff", "quarantine_pending");
  }

  async completeLogin(
    callbackUrl: string,
    pending: PendingLogin,
    options: OperationOptions = {},
  ): Promise<CredentialPair> {
    return this.exchangeHandoff(this.validateCallback(callbackUrl, pending), options);
  }

  async refresh(credentials: CredentialPair, options: OperationOptions = {}): Promise<CredentialPair> {
    this.#credentialContext(credentials, "refresh");
    const value = await this.#request(
      this.#url(`v1/projects/${encodeURIComponent(this.projectId)}/auth/sessions/refresh`),
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          application_id: this.applicationId,
          publishable_key: this.publishableKey,
          refresh_token: credentials.refreshToken.expose(),
        }),
      },
      options,
      { operation: "refresh", category: "Refresh", sensitive: true, action: "quarantine_credentials", success: [200] },
    );
    const successor = this.#credentials(value, "refresh", "quarantine_credentials");
    if (
      successor.sessionId !== credentials.sessionId ||
      successor.userId !== credentials.userId ||
      successor.refreshGeneration <= credentials.refreshGeneration
    ) {
      throw this.#protocol("credential_generation_mismatch", "refresh", 200, "quarantine_credentials");
    }
    return successor;
  }

  async currentUser(accessToken: AccessToken, options: OperationOptions = {}): Promise<CurrentUser> {
    const value = await this.#request(
      this.#url(`v1/projects/${encodeURIComponent(this.projectId)}/auth/users/me`),
      { method: "GET", headers: { authorization: `Bearer ${accessToken.expose()}` } },
      options,
      { operation: "current_user", category: "Authentication", sensitive: false, action: "reauthenticate", success: [200] },
    );
    if (!isObject(value)) throw this.#protocol("invalid_response", "current_user");
    if (
      value["project_id"] !== this.projectId ||
      value["application_id"] !== this.applicationId ||
      !boundedString(value["user_id"], 96) ||
      !positiveInteger(value["projection_revision"]) ||
      !validDate(value["authenticated_at"]) ||
      !validDate(value["session_expires_at"])
    ) {
      throw this.#protocol("context_mismatch", "current_user");
    }
    let projection: UserProjection;
    try {
      projection = parseProjection(value["projection"]);
    } catch {
      throw this.#protocol("invalid_response", "current_user");
    }
    if (projection.userId !== value["user_id"] || projection.projectionRevision !== value["projection_revision"]) {
      throw this.#protocol("context_mismatch", "current_user");
    }
    return {
      projectId: this.projectId,
      applicationId: this.applicationId,
      userId: value["user_id"],
      projection,
      projectionRevision: value["projection_revision"],
      authenticatedAt: value["authenticated_at"],
      sessionExpiresAt: value["session_expires_at"],
    };
  }

  async logoutApplication(accessToken: AccessToken, options: OperationOptions = {}): Promise<void> {
    const value = await this.#request(
      this.#url(`v1/projects/${encodeURIComponent(this.projectId)}/auth/sessions/logout`),
      { method: "POST", headers: { authorization: `Bearer ${accessToken.expose()}` } },
      options,
      { operation: "logout_application", category: "Session", sensitive: true, action: "quarantine_credentials", success: [200] },
    );
    if (!isObject(value) || value["completed"] !== true) throw this.#protocol("invalid_response", "logout_application");
  }

  async prepareBrowserLogout(
    accessToken: AccessToken,
    options: OperationOptions = {},
  ): Promise<BrowserLogoutPreparation> {
    const value = await this.#request(
      this.#url(`v1/projects/${encodeURIComponent(this.projectId)}/auth/browser-logout/prepare`),
      { method: "POST", headers: { authorization: `Bearer ${accessToken.expose()}` } },
      options,
      { operation: "prepare_browser_logout", category: "Session", sensitive: true, action: "quarantine_credentials", success: [201] },
    );
    if (!isObject(value) || !boundedString(value["hosted_url"], 512) || !validDate(value["expires_at"])) {
      throw this.#protocol("invalid_response", "prepare_browser_logout");
    }
    return { hostedUrl: this.#serverUrl(value["hosted_url"], "prepare_browser_logout").href, expiresAt: value["expires_at"] };
  }

  #url(relative: string): URL {
    const url = new URL(relative, this.#base);
    if (url.origin !== this.#base.origin || !url.pathname.startsWith(this.#base.pathname)) {
      throw this.#protocol("url_boundary_violation", "construct_request");
    }
    return url;
  }

  #serverUrl(value: string, operation: string): URL {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw this.#protocol("invalid_navigation_target", operation);
    }
    if (
      url.origin !== this.#base.origin ||
      !url.pathname.startsWith(this.#base.pathname) ||
      url.username !== "" ||
      url.password !== "" ||
      url.hash !== ""
    ) {
      throw this.#protocol("invalid_navigation_target", operation);
    }
    return url;
  }

  #redirect(value: string): URL {
    if (!boundedString(value, MAX_REDIRECT_LENGTH)) {
      throw configurationError("invalid_redirect_uri", "redirectUri is invalid.");
    }
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw configurationError("invalid_redirect_uri", "redirectUri must be absolute.");
    }
    if (
      ["javascript:", "data:", "file:", "blob:"].includes(url.protocol) ||
      (url.protocol === "http:" && !loopback(url.hostname)) ||
      url.username !== "" ||
      url.password !== "" ||
      url.hash !== "" ||
      url.searchParams.has("handoff") ||
      url.searchParams.has("state")
    ) {
      throw configurationError("invalid_redirect_uri", "redirectUri contains reserved or unsafe components.");
    }
    return url;
  }

  #random(bytes: number): string {
    return base64Url(this.#crypto.getRandomValues(new Uint8Array(bytes)));
  }

  #credentials(value: unknown, operation: string, action: CallerAction): CredentialPair {
    if (!isObject(value)) throw this.#protocol("invalid_response", operation, 200, action);
    if (
      value["project_id"] !== this.projectId ||
      value["application_id"] !== this.applicationId ||
      !boundedString(value["user_id"], 96) ||
      !boundedString(value["session_id"], 64) ||
      !positiveInteger(value["refresh_generation"]) ||
      !boundedString(value["access_token"], 16_384) ||
      !boundedString(value["refresh_token"], 256) ||
      value["token_type"] !== "Bearer" ||
      !positiveInteger(value["expires_in"]) ||
      !positiveInteger(value["projection_revision"]) ||
      !validDate(value["session_expires_at"])
    ) {
      throw this.#protocol("context_mismatch", operation, 200, action);
    }
    let projection: UserProjection;
    try {
      projection = parseProjection(value["projection"]);
    } catch {
      throw this.#protocol("invalid_response", operation, 200, action);
    }
    if (projection.userId !== value["user_id"] || projection.projectionRevision !== value["projection_revision"]) {
      throw this.#protocol("context_mismatch", operation, 200, action);
    }
    return new CredentialPair({
      projectId: this.projectId,
      applicationId: this.applicationId,
      userId: value["user_id"],
      sessionId: value["session_id"],
      refreshGeneration: value["refresh_generation"],
      accessToken: value["access_token"],
      refreshToken: value["refresh_token"],
      expiresIn: value["expires_in"],
      projection,
      projectionRevision: value["projection_revision"],
      sessionExpiresAt: value["session_expires_at"],
    });
  }

  #credentialContext(credentials: CredentialPair, operation: string): void {
    if (credentials.projectId !== this.projectId || credentials.applicationId !== this.applicationId) {
      throw this.#protocol("credential_context_mismatch", operation);
    }
  }

  async #request(
    url: URL,
    init: RequestInit,
    options: OperationOptions,
    policy: RequestPolicy,
  ): Promise<unknown> {
    if (url.origin !== this.#base.origin || !url.pathname.startsWith(this.#base.pathname)) {
      throw this.#protocol("url_boundary_violation", policy.operation);
    }
    if (options.signal?.aborted === true) {
      throw new OwlAuthError({
        category: "Cancelled",
        code: "cancelled_before_dispatch",
        message: "The operation was cancelled before dispatch.",
        operation: policy.operation,
        retry: "never",
        action: policy.action,
      });
    }
    const timeoutMs = options.timeoutMs ?? this.#timeoutMs;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 120_000) {
      throw configurationError("invalid_timeout", "timeoutMs must be between 1 and 120000.");
    }
    const controller = new AbortController();
    let timedOut = false;
    const onAbort = () => controller.abort();
    options.signal?.addEventListener("abort", onAbort, { once: true });
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    let dispatched = false;
    try {
      dispatched = true;
      const response = await this.#fetch(url, {
        ...init,
        signal: controller.signal,
        redirect: "error",
        credentials: "omit",
        headers: { accept: "application/json", ...init.headers },
      });
      const quarantineAction =
        policy.sensitive && policy.success.includes(response.status) ? policy.action : "none";
      const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
      if (response.redirected || contentType !== "application/json") {
        throw this.#protocol("invalid_response", policy.operation, response.status, quarantineAction);
      }
      if (response.url !== "") {
        let responseUrl: URL;
        try {
          responseUrl = new URL(response.url);
        } catch {
          throw this.#protocol("invalid_response", policy.operation, response.status, quarantineAction);
        }
        if (
          responseUrl.origin !== this.#base.origin ||
          !responseUrl.pathname.startsWith(this.#base.pathname)
        ) {
          throw this.#protocol("response_origin_mismatch", policy.operation, response.status, quarantineAction);
        }
      }
      let value: unknown;
      try {
        value = await readBounded(response);
      } catch {
        throw this.#protocol("invalid_response", policy.operation, response.status, quarantineAction);
      }
      if (!policy.success.includes(response.status)) {
        const problem = parseProblem(value);
        if (problem === null) throw this.#protocol("invalid_error_response", policy.operation, response.status);
        throw mapRuntimeError(problem, response.status, policy);
      }
      return value;
    } catch (error) {
      if (error instanceof OwlAuthError) throw error;
      const cancelled = Boolean(options.signal?.aborted);
      if (policy.sensitive && dispatched) {
        throw new OwlAuthError({
          category: "Indeterminate",
          code: timedOut ? "timeout_after_dispatch" : cancelled ? "cancelled_after_dispatch" : "transport_after_dispatch",
          message: "Runtime may have committed the one-use operation; do not retry it.",
          operation: policy.operation,
          retry: "never",
          action: policy.action,
          cause: new Error("redacted transport failure"),
        });
      }
      throw new OwlAuthError({
        category: timedOut ? "Timeout" : cancelled ? "Cancelled" : "Transport",
        code: timedOut ? "timeout" : cancelled ? "cancelled" : "transport_failure",
        message: timedOut ? "The Runtime request timed out." : cancelled ? "The Runtime request was cancelled." : "The Runtime request failed.",
        operation: policy.operation,
        retry: policy.sensitive ? "never" : "application_decision",
        action: policy.action,
        cause: new Error("redacted transport failure"),
      });
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
    }
  }

  #protocol(
    code: string,
    operation: string,
    status?: number,
    action: CallerAction = "none",
  ): OwlAuthError {
    return new OwlAuthError({
      category: "Protocol",
      code,
      message: "Runtime returned an invalid or context-inconsistent response.",
      operation,
      retry: "never",
      action,
      ...(status === undefined ? {} : { status }),
    });
  }

  #handoff(code: string): OwlAuthError {
    return new OwlAuthError({
      category: "Handoff",
      code,
      message: "The login callback cannot be used.",
      operation: "validate_callback",
      retry: "never",
      action: "discard_pending",
    });
  }
}
