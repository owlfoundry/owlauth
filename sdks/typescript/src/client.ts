import { OwlAuthError, configurationError, type CallerAction, type ErrorCategory } from "./errors.js";
import {
  AccessToken,
  type BrowserLogoutPreparation,
  CredentialPair,
  type CredentialPairRecord,
  createCredentialPair,
  createPendingLogin,
  createPkceVerifier,
  createValidatedCallback,
  type CurrentUser,
  type LoginStartResult,
  type OperationOptions,
  PendingLogin,
  type PendingLoginRecord,
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
  getRandomValues<T extends ArrayBufferView>(array: T): T;
  readonly subtle: SubtleCrypto;
}

export type SdkDebugOutcome =
  | "success"
  | "runtime_error"
  | "transport_error"
  | "timeout"
  | "cancelled"
  | "invalid_response"
  | "indeterminate";

/** Closed, secret-free completion event emitted only when a debug hook is configured. */
export interface SdkDebugEvent {
  readonly operation: string;
  readonly method: "GET" | "POST";
  readonly outcome: SdkDebugOutcome;
  readonly elapsedMs: number;
  readonly dispatched: boolean;
  readonly status?: number;
  readonly category?: ErrorCategory;
  readonly code?: string;
  readonly requestId?: string;
}

export type SdkDebugHook = (event: Readonly<SdkDebugEvent>) => void;

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
  readonly debugHook?: SdkDebugHook;
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
  readonly errors: readonly number[];
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

function validBearerToken(value: unknown): value is string {
  return boundedString(value, 16_384) && /^[A-Za-z0-9\-._~+/=]+$/u.test(value);
}

function validOpaqueToken(value: unknown): value is string {
  return boundedString(value, 256) && /^[A-Za-z0-9\-._~]+$/u.test(value);
}

function positiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function exactFields(value: Record<string, unknown>, fields: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === fields.length && fields.every((field) => Object.hasOwn(value, field));
}

function validRetryAfter(value: string | null): number | null {
  if (value === null || !/^[0-9]{1,6}$/u.test(value)) return null;
  const seconds = Number(value);
  return Number.isSafeInteger(seconds) && seconds <= 86_400 ? seconds : null;
}

function validDate(value: unknown): value is string {
  return boundedString(value, 64) && Number.isFinite(Date.parse(value));
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function validEd25519Key(value: unknown): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) return false;
  try {
    const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=");
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return bytes.byteLength === 32 && base64Url(bytes) === value;
  } catch {
    return false;
  }
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

function validRedirectScheme(url: URL): boolean {
  if (url.protocol === "https:") return true;
  if (url.protocol === "http:") return loopback(url.hostname);
  const scheme = url.protocol.slice(0, -1);
  return (
    scheme.includes(".") &&
    url.hostname === "" &&
    ![
      "about",
      "blob",
      "data",
      "file",
      "ftp",
      "http",
      "https",
      "javascript",
      "mailto",
      "vbscript",
      "ws",
      "wss",
    ].includes(scheme)
  );
}

function hasAmbiguousUrlPath(value: string): boolean {
  const lower = value.toLowerCase();
  if (value.includes("\\") || lower.includes("%2f") || lower.includes("%5c") || lower.includes("%25")) {
    return true;
  }
  const authorityStart = value.indexOf("://");
  if (authorityStart < 0) return true;
  const pathStart = value.indexOf("/", authorityStart + 3);
  const rawPath = pathStart < 0 ? "" : value.slice(pathStart).split(/[?#]/u, 1)[0];
  try {
    return rawPath.split("/").some((segment) => {
      const decoded = decodeURIComponent(segment).toLowerCase();
      return decoded === "." || decoded === "..";
    });
  } catch {
    return true;
  }
}

function parseBaseUrl(value: string, allowInsecureLoopback: boolean): URL {
  let url: URL;
  try {
    if (hasAmbiguousUrlPath(value)) throw new Error("ambiguous Runtime path");
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
  const fields = Object.keys(value);
  if (
    fields.length !== 3 ||
    !fields.every((field) => ["code", "message", "request_id"].includes(field)) ||
    !Object.hasOwn(value, "code") ||
    !Object.hasOwn(value, "message") ||
    !Object.hasOwn(value, "request_id") ||
    !boundedString(value["code"], 64) ||
    !/^[a-z][a-z0-9_]*$/u.test(value["code"]) ||
    !boundedString(value["message"], 256)
  ) {
    return null;
  }
  const requestId = value["request_id"];
  if (!boundedString(requestId, 128)) return null;
  const allowedRequestId =
    boundedString(requestId, 128) &&
    /^[A-Za-z0-9._:-]+$/u.test(requestId)
      ? requestId
      : undefined;
  return {
    code: value["code"],
    message: value["message"],
    ...(allowedRequestId === undefined ? {} : { requestId: allowedRequestId }),
  };
}

function mapRuntimeError(
  problem: RuntimeProblem,
  status: number,
  policy: RequestPolicy,
  retryAfterSeconds?: number,
): OwlAuthError {
  if (status === 408 && problem.code === "request_timeout") {
    return new OwlAuthError({
      category: policy.sensitive ? "Indeterminate" : "Timeout",
      code: problem.code,
      message: policy.sensitive
        ? "Runtime may have committed the operation; do not replay it."
        : "The Runtime request exceeded its server-side deadline.",
      operation: policy.operation,
      retry: policy.sensitive ? "never" : "application_decision",
      action: policy.sensitive ? policy.action : "none",
      ...(problem.requestId === undefined ? {} : { requestId: problem.requestId }),
      status,
    });
  }
  if (status === 429 && problem.code === "rate_limited") {
    const handoff = policy.operation === "exchange_handoff";
    const callerDecision = [
      "refresh_session",
      "logout_application_session",
      "prepare_browser_logout",
    ].includes(policy.operation);
    return new OwlAuthError({
      category: "RateLimited",
      code: problem.code,
      message: "The optional SaaS or ingress traffic policy rejected the request.",
      operation: policy.operation,
      retry: handoff ? "never" : callerDecision ? "application_decision" : "safe_after_delay",
      action: handoff ? "discard_pending" : "none",
      ...(problem.requestId === undefined ? {} : { requestId: problem.requestId }),
      ...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds }),
      status,
    });
  }
  const authentication = status === 401;
  let category: ErrorCategory = authentication ? "Authentication" : policy.category;
  if (policy.operation === "refresh_session" && status >= 400 && status < 500) category = "Refresh";
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
    retry: "never",
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
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
}

function validProjectionLocale(value: unknown): value is string | null {
  return (
    value === null ||
    (typeof value === "string" &&
      new TextEncoder().encode(value).byteLength >= 2 &&
      new TextEncoder().encode(value).byteLength <= 35 &&
      /^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$/u.test(value))
  );
}

function validProjectionEmail(value: unknown): value is string | null {
  if (value === null) return true;
  if (typeof value !== "string" || /\p{Cc}/u.test(value)) return false;
  const length = new TextEncoder().encode(value).byteLength;
  return length >= 3 && length <= 320;
}

function parseProjection(value: unknown): UserProjection {
  if (!isObject(value)) throw new Error("invalid_projection");
  const fields = [
    "user_id",
    "user_revision",
    "projection_schema",
    "projection_revision",
    "display_name",
    "picture_url",
    "locale",
    "verified_email",
    "status",
    "created_at",
    "updated_at",
  ] as const;
  const displayName = value["display_name"];
  const pictureUrl = value["picture_url"];
  const locale = value["locale"];
  const verifiedEmail = value["verified_email"];
  if (
    Object.keys(value).length !== fields.length ||
    !fields.every((field) => Object.hasOwn(value, field)) ||
    !boundedString(value["user_id"], 96) ||
    !positiveInteger(value["user_revision"]) ||
    value["projection_schema"] !== "owlauth.user.v1" ||
    !positiveInteger(value["projection_revision"]) ||
    !(displayName === null || boundedString(displayName, 128)) ||
    !(pictureUrl === null || boundedString(pictureUrl, 2_048)) ||
    !validProjectionLocale(locale) ||
    !validProjectionEmail(verifiedEmail) ||
    value["status"] !== "active" ||
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
    locale,
    verifiedEmail,
    status: value["status"],
    createdAt: value["created_at"],
    updatedAt: value["updated_at"],
  };
}

function parseProjectionRecord(value: unknown): UserProjection {
  if (!isObject(value)) throw new Error("invalid_projection");
  const fields = [
    "userId",
    "userRevision",
    "projectionSchema",
    "projectionRevision",
    "displayName",
    "pictureUrl",
    "locale",
    "verifiedEmail",
    "status",
    "createdAt",
    "updatedAt",
  ] as const;
  const displayName = value["displayName"];
  const pictureUrl = value["pictureUrl"];
  const locale = value["locale"];
  const verifiedEmail = value["verifiedEmail"];
  if (
    !exactFields(value, fields) ||
    !boundedString(value["userId"], 96) ||
    !positiveInteger(value["userRevision"]) ||
    value["projectionSchema"] !== "owlauth.user.v1" ||
    !positiveInteger(value["projectionRevision"]) ||
    !(displayName === null || boundedString(displayName, 128)) ||
    !(pictureUrl === null || boundedString(pictureUrl, 2_048)) ||
    !validProjectionLocale(locale) ||
    !validProjectionEmail(verifiedEmail) ||
    value["status"] !== "active" ||
    !validDate(value["createdAt"]) ||
    !validDate(value["updatedAt"])
  ) {
    throw new Error("invalid_projection");
  }
  return {
    userId: value["userId"],
    userRevision: value["userRevision"],
    projectionSchema: value["projectionSchema"],
    projectionRevision: value["projectionRevision"],
    displayName,
    pictureUrl,
    locale,
    verifiedEmail,
    status: "active",
    createdAt: value["createdAt"],
    updatedAt: value["updatedAt"],
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
  readonly #debugHook: SdkDebugHook | undefined;

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
    this.#debugHook = options.debugHook;
  }

  /** Restores an explicitly exported pending-login record into this exact Client context. */
  restorePendingLogin(record: unknown): PendingLogin {
    const fields = [
      "schemaVersion",
      "runtimeOrigin",
      "runtimeBasePath",
      "projectId",
      "applicationId",
      "redirectUri",
      "state",
      "createdAt",
      "expiresAt",
      "verifier",
    ] as const;
    if (
      !isObject(record) ||
      !exactFields(record, fields) ||
      record["schemaVersion"] !== 1 ||
      record["runtimeOrigin"] !== this.#base.origin ||
      record["runtimeBasePath"] !== this.#base.pathname ||
      record["projectId"] !== this.projectId ||
      record["applicationId"] !== this.applicationId ||
      !boundedString(record["redirectUri"], MAX_REDIRECT_LENGTH) ||
      !boundedString(record["state"], MAX_STATE_LENGTH) ||
      !TOKEN_PATTERN.test(record["state"]) ||
      typeof record["createdAt"] !== "number" ||
      !Number.isSafeInteger(record["createdAt"]) ||
      typeof record["expiresAt"] !== "number" ||
      !Number.isSafeInteger(record["expiresAt"]) ||
      record["expiresAt"] < record["createdAt"] - 60_000 ||
      record["expiresAt"] > record["createdAt"] + 660_000 ||
      this.#now() > record["expiresAt"] + 60_000 ||
      !boundedString(record["verifier"], 128) ||
      !/^[A-Za-z0-9_-]{43,128}$/u.test(record["verifier"])
    ) {
      throw configurationError("invalid_pending_record", "The pending-login record is invalid or belongs to another client.");
    }
    const redirect = this.#redirect(record["redirectUri"]);
    return createPendingLogin({
      runtimeOrigin: this.#base.origin,
      runtimeBasePath: this.#base.pathname,
      projectId: this.projectId,
      applicationId: this.applicationId,
      redirectUri: redirect.href,
      state: record["state"],
      createdAt: record["createdAt"],
      expiresAt: record["expiresAt"],
      verifier: createPkceVerifier(record["verifier"]),
    });
  }

  /** Restores an explicitly exported credential pair into this exact Client context. */
  restoreCredentialPair(record: unknown): CredentialPair {
    const fields = [
      "schemaVersion",
      "runtimeOrigin",
      "runtimeBasePath",
      "projectId",
      "applicationId",
      "userId",
      "sessionId",
      "refreshGeneration",
      "accessToken",
      "refreshToken",
      "tokenType",
      "expiresIn",
      "projection",
      "projectionRevision",
      "sessionExpiresAt",
    ] as const;
    if (
      !isObject(record) ||
      !exactFields(record, fields) ||
      record["schemaVersion"] !== 1 ||
      record["runtimeOrigin"] !== this.#base.origin ||
      record["runtimeBasePath"] !== this.#base.pathname ||
      record["projectId"] !== this.projectId ||
      record["applicationId"] !== this.applicationId ||
      !boundedString(record["userId"], 96) ||
      !boundedString(record["sessionId"], 64) ||
      !positiveInteger(record["refreshGeneration"]) ||
      !validBearerToken(record["accessToken"]) ||
      !validOpaqueToken(record["refreshToken"]) ||
      record["tokenType"] !== "Bearer" ||
      !positiveInteger(record["expiresIn"]) ||
      record["expiresIn"] > 3_600 ||
      !positiveInteger(record["projectionRevision"]) ||
      !validDate(record["sessionExpiresAt"]) ||
      Date.parse(record["sessionExpiresAt"]) < this.#now() - 60_000
    ) {
      throw configurationError("invalid_credential_record", "The credential record is invalid or belongs to another client.");
    }
    let projection: UserProjection;
    try {
      projection = parseProjectionRecord(record["projection"]);
    } catch {
      throw configurationError("invalid_credential_record", "The credential record is invalid or belongs to another client.");
    }
    if (projection.userId !== record["userId"] || projection.projectionRevision !== record["projectionRevision"]) {
      throw configurationError("invalid_credential_record", "The credential record is invalid or belongs to another client.");
    }
    return createCredentialPair({
      runtimeOrigin: this.#base.origin,
      runtimeBasePath: this.#base.pathname,
      projectId: this.projectId,
      applicationId: this.applicationId,
      userId: record["userId"],
      sessionId: record["sessionId"],
      refreshGeneration: record["refreshGeneration"],
      accessToken: record["accessToken"],
      refreshToken: record["refreshToken"],
      expiresIn: record["expiresIn"],
      projection,
      projectionRevision: record["projectionRevision"],
      sessionExpiresAt: record["sessionExpiresAt"],
    });
  }

  async getPublicConfiguration(options: OperationOptions = {}): Promise<PublicApplicationConfiguration> {
    const path = `v1/projects/${encodeURIComponent(this.projectId)}/auth/config`;
    const url = this.#url(path);
    url.searchParams.set("application_id", this.applicationId);
    const value = await this.#request(url, { method: "GET" }, options, {
      operation: "get_public_application_config",
      category: "Protocol",
      sensitive: false,
      action: "none",
      success: [200],
      errors: [400, 404, 408, 429, 503],
    });
    if (!isObject(value)) throw this.#protocol("invalid_response", "get_public_application_config");
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
      typeof value["email_available"] !== "boolean" ||
      typeof value["email_otp_enabled"] !== "boolean" ||
      typeof value["email_magic_link_enabled"] !== "boolean" ||
      typeof value["login_available"] !== "boolean"
    ) {
      throw this.#protocol("context_mismatch", "get_public_application_config");
    }
    const providerKeys = new Set<string>();
    const mappedProviders: PublicProvider[] = providers.map((provider) => {
      if (
        !isObject(provider) ||
        !boundedString(provider["key"], 64) ||
        providerKeys.has(provider["key"]) ||
        !boundedString(provider["display_name"], 128) ||
        typeof provider["kind"] !== "string" ||
        !["oidc", "google", "github"].includes(provider["kind"])
      ) {
        throw this.#protocol("invalid_response", "get_public_application_config");
      }
      providerKeys.add(provider["key"]);
      return {
        key: provider["key"],
        displayName: provider["display_name"],
        kind: provider["kind"] as PublicProvider["kind"],
      };
    });
    return {
      projectId: this.projectId,
      projectDisplayName: value["project_display_name"],
      applicationId: this.applicationId,
      applicationDisplayName: value["application_display_name"],
      publishableKeys: [...keys],
      providers: mappedProviders,
      emailAvailable: value["email_available"],
      emailOtpEnabled: value["email_otp_enabled"],
      emailMagicLinkEnabled: value["email_magic_link_enabled"],
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
        errors: [404, 408, 429, 503],
      },
    );
    if (!isObject(value) || !positiveInteger(value["revision"]) || !positiveInteger(value["signing_epoch"])) {
      throw this.#protocol("invalid_response", "get_project_jwks");
    }
    const keys = value["keys"];
    if (!Array.isArray(keys) || keys.length > 100) throw this.#protocol("invalid_response", "get_project_jwks");
    const keyIds = new Set<string>();
    const mapped: PublicJwk[] = keys.map((key) => {
      if (
        !isObject(key) ||
        Object.keys(key).length !== 6 ||
        !["kty", "crv", "alg", "use", "kid", "x"].every((field) => Object.hasOwn(key, field)) ||
        key["kty"] !== "OKP" ||
        key["crv"] !== "Ed25519" ||
        key["alg"] !== "EdDSA" ||
        key["use"] !== "sig" ||
        !boundedString(key["kid"], 128) ||
        keyIds.has(key["kid"]) ||
        !validEd25519Key(key["x"])
      ) {
        throw this.#protocol("invalid_response", "get_project_jwks");
      }
      keyIds.add(key["kid"]);
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
    const verifier = createPkceVerifier(this.#random(32));
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
      {
        operation: "start_login",
        category: "Login",
        sensitive: false,
        action: "discard_pending",
        success: [201],
        errors: [400, 404, 408, 429, 503],
      },
    );
    if (!isObject(value) || !boundedString(value["hosted_url"], 512) || !validDate(value["expires_at"])) {
      throw this.#protocol("invalid_response", "start_login");
    }
    const hosted = this.#serverUrl(value["hosted_url"], "start_login");
    const expiresAt = Date.parse(value["expires_at"]);
    if (expiresAt < createdAt - 60_000 || expiresAt > createdAt + 660_000) {
      throw this.#protocol("invalid_response", "start_login");
    }
    return {
      hostedUrl: hosted.href,
      pending: createPendingLogin({
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
    if (pending.consumed) throw this.#handoff("pending_consumed");
    if (
      pending.runtimeOrigin !== this.#base.origin ||
      pending.runtimeBasePath !== this.#base.pathname ||
      pending.projectId !== this.projectId ||
      pending.applicationId !== this.applicationId ||
      this.#now() > pending.expiresAt + 60_000
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
    const errors = callback.searchParams.getAll("error");
    const states = callback.searchParams.getAll("state");
    if (
      callback.hash !== "" ||
      states.length !== 1 ||
      !exactState(states[0] ?? "", pending.state) ||
      (handoffs.length === 1) === (errors.length === 1) ||
      handoffs.length > 1 ||
      errors.length > 1 ||
      (handoffs.length === 1 && !boundedString(handoffs[0], MAX_HANDOFF_LENGTH)) ||
      (errors.length === 1 && !boundedString(errors[0], 64))
    ) {
      throw this.#handoff("invalid_callback");
    }
    callback.searchParams.delete("handoff");
    callback.searchParams.delete("error");
    callback.searchParams.delete("state");
    if (callback.href !== pending.redirectUri) throw this.#handoff("redirect_mismatch");
    if (errors.length === 1) throw this.#handoff("login_failed");
    return createValidatedCallback(handoffs[0]!, pending);
  }

  async exchangeHandoff(
    callback: ValidatedCallback,
    options: OperationOptions = {},
  ): Promise<CredentialPair> {
    this.#validateOperationOptions(options, "exchange_handoff");
    const material = callback.reserve();
    if (material === null) throw this.#handoff("handoff_already_attempted");
    const url = this.#url(`v1/projects/${encodeURIComponent(this.projectId)}/auth/handoff/exchange`);
    const init: RequestInit = {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        application_id: this.applicationId,
        publishable_key: this.publishableKey,
        handoff: material.handoff,
        pkce_verifier: material.verifier.expose(),
      }),
    };
    callback.commit();
    const value = await this.#request(
      url,
      init,
      options,
      {
        operation: "exchange_handoff",
        category: "Handoff",
        sensitive: true,
        action: "quarantine_pending",
        success: [200],
        errors: [400, 408, 409, 429, 503],
      },
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
    this.#credentialContext(credentials, "refresh_session");
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
      {
        operation: "refresh_session",
        category: "Refresh",
        sensitive: true,
        action: "quarantine_credentials",
        success: [200],
        errors: [400, 408, 409, 429, 503],
      },
    );
    const successor = this.#credentials(value, "refresh_session", "quarantine_credentials");
    if (
      successor.sessionId !== credentials.sessionId ||
      successor.userId !== credentials.userId ||
      successor.refreshGeneration !== credentials.refreshGeneration + 1
    ) {
      throw this.#indeterminate("invalid_response_after_dispatch", "refresh_session", "quarantine_credentials", 200);
    }
    return successor;
  }

  async currentUser(accessToken: AccessToken, options: OperationOptions = {}): Promise<CurrentUser> {
    this.#accessTokenContext(accessToken, "get_current_user");
    const value = await this.#request(
      this.#url(`v1/projects/${encodeURIComponent(this.projectId)}/auth/users/me`),
      { method: "GET", headers: { authorization: `Bearer ${accessToken.expose()}` } },
      options,
      {
        operation: "get_current_user",
        category: "Authentication",
        sensitive: false,
        action: "reauthenticate",
        success: [200],
        errors: [401, 408, 429, 503],
      },
    );
    const fields = [
      "project_id",
      "application_id",
      "user_id",
      "projection",
      "projection_revision",
      "authenticated_at",
      "session_expires_at",
    ] as const;
    if (!isObject(value) || !exactFields(value, fields)) {
      throw this.#protocol("invalid_response", "get_current_user");
    }
    if (
      value["project_id"] !== this.projectId ||
      value["application_id"] !== this.applicationId ||
      !boundedString(value["user_id"], 96) ||
      !positiveInteger(value["projection_revision"]) ||
      !validDate(value["authenticated_at"]) ||
      !validDate(value["session_expires_at"]) ||
      Date.parse(value["session_expires_at"]) < this.#now() - 60_000
    ) {
      throw this.#protocol("context_mismatch", "get_current_user");
    }
    let projection: UserProjection;
    try {
      projection = parseProjection(value["projection"]);
    } catch {
      throw this.#protocol("invalid_response", "get_current_user");
    }
    if (projection.userId !== value["user_id"] || projection.projectionRevision !== value["projection_revision"]) {
      throw this.#protocol("context_mismatch", "get_current_user");
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
    this.#accessTokenContext(accessToken, "logout_application_session");
    const value = await this.#request(
      this.#url(`v1/projects/${encodeURIComponent(this.projectId)}/auth/sessions/logout`),
      { method: "POST", headers: { authorization: `Bearer ${accessToken.expose()}` } },
      options,
      {
        operation: "logout_application_session",
        category: "Session",
        sensitive: true,
        action: "quarantine_credentials",
        success: [200],
        errors: [401, 408, 429, 503],
      },
    );
    if (!isObject(value) || value["completed"] !== true) {
      throw this.#indeterminate("invalid_response_after_dispatch", "logout_application_session", "quarantine_credentials", 200);
    }
  }

  async prepareBrowserLogout(
    accessToken: AccessToken,
    options: OperationOptions = {},
  ): Promise<BrowserLogoutPreparation> {
    this.#accessTokenContext(accessToken, "prepare_browser_logout");
    const value = await this.#request(
      this.#url(`v1/projects/${encodeURIComponent(this.projectId)}/auth/browser-logout/prepare`),
      { method: "POST", headers: { authorization: `Bearer ${accessToken.expose()}` } },
      options,
      {
        operation: "prepare_browser_logout",
        category: "Session",
        sensitive: true,
        action: "quarantine_credentials",
        success: [201],
        errors: [401, 408, 429, 503],
      },
    );
    if (!isObject(value) || !boundedString(value["hosted_url"], 512) || !validDate(value["expires_at"])) {
      throw this.#indeterminate("invalid_response_after_dispatch", "prepare_browser_logout", "quarantine_credentials", 201);
    }
    const expiresAt = Date.parse(value["expires_at"]);
    const receivedAt = this.#now();
    if (expiresAt < receivedAt - 60_000 || expiresAt > receivedAt + 120_000) {
      throw this.#indeterminate("invalid_response_after_dispatch", "prepare_browser_logout", "quarantine_credentials", 201);
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
      if (hasAmbiguousUrlPath(value)) throw new Error("ambiguous Runtime path");
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
    const lower = value.toLowerCase();
    if (
      url.href !== value ||
      value.includes("\\") ||
      /\s/u.test(value) ||
      lower.includes("%2f") ||
      lower.includes("%5c") ||
      !validRedirectScheme(url) ||
      url.username !== "" ||
      url.password !== "" ||
      url.hash !== "" ||
      url.searchParams.has("handoff") ||
      url.searchParams.has("error") ||
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
    const fields = [
      "project_id",
      "application_id",
      "user_id",
      "session_id",
      "refresh_generation",
      "access_token",
      "refresh_token",
      "token_type",
      "expires_in",
      "projection",
      "projection_revision",
      "session_expires_at",
    ] as const;
    if (!isObject(value) || !exactFields(value, fields)) {
      throw this.#indeterminate("invalid_response_after_dispatch", operation, action, 200);
    }
    if (
      value["project_id"] !== this.projectId ||
      value["application_id"] !== this.applicationId ||
      !boundedString(value["user_id"], 96) ||
      !boundedString(value["session_id"], 64) ||
      !positiveInteger(value["refresh_generation"]) ||
      !validBearerToken(value["access_token"]) ||
      !validOpaqueToken(value["refresh_token"]) ||
      value["token_type"] !== "Bearer" ||
      !positiveInteger(value["expires_in"]) ||
      value["expires_in"] > 3_600 ||
      !positiveInteger(value["projection_revision"]) ||
      !validDate(value["session_expires_at"])
    ) {
      throw this.#indeterminate("invalid_response_after_dispatch", operation, action, 200);
    }
    let projection: UserProjection;
    try {
      projection = parseProjection(value["projection"]);
    } catch {
      throw this.#indeterminate("invalid_response_after_dispatch", operation, action, 200);
    }
    if (projection.userId !== value["user_id"] || projection.projectionRevision !== value["projection_revision"]) {
      throw this.#indeterminate("invalid_response_after_dispatch", operation, action, 200);
    }
    const sessionExpiresAt = Date.parse(value["session_expires_at"]);
    if (sessionExpiresAt < this.#now() - 60_000) {
      throw this.#indeterminate("invalid_response_after_dispatch", operation, action, 200);
    }
    return createCredentialPair({
      runtimeOrigin: this.#base.origin,
      runtimeBasePath: this.#base.pathname,
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
    if (
      credentials.runtimeOrigin !== this.#base.origin ||
      credentials.runtimeBasePath !== this.#base.pathname ||
      credentials.projectId !== this.projectId ||
      credentials.applicationId !== this.applicationId
    ) {
      throw this.#protocol("credential_context_mismatch", operation);
    }
  }

  #accessTokenContext(accessToken: AccessToken, operation: string): void {
    if (
      accessToken.runtimeOrigin !== this.#base.origin ||
      accessToken.runtimeBasePath !== this.#base.pathname ||
      accessToken.projectId !== this.projectId ||
      accessToken.applicationId !== this.applicationId
    ) {
      throw this.#protocol("credential_context_mismatch", operation);
    }
  }

  #validateOperationOptions(options: OperationOptions, operation: string): number {
    const timeoutMs = options.timeoutMs ?? this.#timeoutMs;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 120_000) {
      throw configurationError("invalid_timeout", "timeoutMs must be between 1 and 120000.");
    }
    if (options.signal?.aborted === true) {
      const timedOut = options.signal.reason instanceof DOMException && options.signal.reason.name === "TimeoutError";
      throw new OwlAuthError({
        category: timedOut ? "Timeout" : "Cancelled",
        code: timedOut ? "timeout" : "cancelled_before_dispatch",
        message: timedOut
          ? "The operation timed out before dispatch."
          : "The operation was cancelled before dispatch.",
        operation,
        retry: "application_decision",
        action: "none",
      });
    }
    return timeoutMs;
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
    const timeoutMs = this.#validateOperationOptions(options, policy.operation);
    const method = init.method === "POST" ? "POST" : "GET";
    const startedAt = this.#now();
    let responseStatus: number | undefined;
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
      responseStatus = response.status;
      const invalidAction = policy.sensitive ? policy.action : "none";
      const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
      if (response.redirected || contentType !== "application/json") {
        throw this.#invalidResponse(policy, response.status, invalidAction);
      }
      if (response.url !== "") {
        let responseUrl: URL;
        try {
          responseUrl = new URL(response.url);
        } catch {
          throw this.#invalidResponse(policy, response.status, invalidAction);
        }
        if (
          responseUrl.origin !== this.#base.origin ||
          !responseUrl.pathname.startsWith(this.#base.pathname)
        ) {
          throw this.#invalidResponse(policy, response.status, invalidAction);
        }
      }
      let value: unknown;
      try {
        value = await readBounded(response);
      } catch {
        throw this.#invalidResponse(policy, response.status, invalidAction);
      }
      if (!policy.success.includes(response.status)) {
        if (!policy.errors.includes(response.status)) {
          throw this.#invalidResponse(policy, response.status, invalidAction);
        }
        const problem = parseProblem(value);
        if (problem === null) throw this.#invalidResponse(policy, response.status, invalidAction);
        let retryAfterSeconds: number | undefined;
        if (response.status === 429) {
          const parsed = validRetryAfter(response.headers.get("retry-after"));
          if (problem.code !== "rate_limited" || parsed === null) {
            throw this.#invalidResponse(policy, response.status, invalidAction);
          }
          retryAfterSeconds = parsed;
        }
        if (response.status === 408 && problem.code !== "request_timeout") {
          throw this.#invalidResponse(policy, response.status, invalidAction);
        }
        if (policy.sensitive && response.status >= 500) {
          throw this.#indeterminate("runtime_5xx_after_dispatch", policy.operation, policy.action, response.status);
        }
        throw mapRuntimeError(problem, response.status, policy, retryAfterSeconds);
      }
      this.#emitDebug({
        operation: policy.operation,
        method,
        outcome: "success",
        elapsedMs: this.#elapsedMs(startedAt),
        dispatched,
        status: response.status,
      });
      return value;
    } catch (error) {
      if (error instanceof OwlAuthError) {
        const status = error.status ?? responseStatus;
        this.#emitDebug({
          operation: policy.operation,
          method,
          outcome: this.#debugOutcome(error.category),
          elapsedMs: this.#elapsedMs(startedAt),
          dispatched,
          ...(status === undefined ? {} : { status }),
          category: error.category,
          code: error.code,
          ...(error.requestId === undefined ? {} : { requestId: error.requestId }),
        });
        throw error;
      }
      if (error instanceof DOMException && error.name === "TimeoutError") timedOut = true;
      const cancelled = Boolean(options.signal?.aborted) ||
        (error instanceof DOMException && error.name === "AbortError");
      if (policy.sensitive && dispatched) {
        const mapped = new OwlAuthError({
          category: "Indeterminate",
          code: "outcome_indeterminate",
          message: "Runtime may have committed the one-use operation; do not retry it.",
          operation: policy.operation,
          retry: "never",
          action: policy.action,
          cause: new Error("redacted transport failure"),
        });
        this.#emitDebug({
          operation: policy.operation,
          method,
          outcome: "indeterminate",
          elapsedMs: this.#elapsedMs(startedAt),
          dispatched,
          ...(responseStatus === undefined ? {} : { status: responseStatus }),
          category: mapped.category,
          code: mapped.code,
        });
        throw mapped;
      }
      const mapped = new OwlAuthError({
        category: timedOut ? "Timeout" : cancelled ? "Cancelled" : "Transport",
        code: timedOut ? "timeout" : cancelled ? "cancelled" : "transport_failure",
        message: timedOut ? "The Runtime request timed out." : cancelled ? "The Runtime request was cancelled." : "The Runtime request failed.",
        operation: policy.operation,
        retry: policy.sensitive ? "never" : "application_decision",
        action: "none",
        cause: new Error("redacted transport failure"),
      });
      this.#emitDebug({
        operation: policy.operation,
        method,
        outcome: this.#debugOutcome(mapped.category),
        elapsedMs: this.#elapsedMs(startedAt),
        dispatched,
        ...(responseStatus === undefined ? {} : { status: responseStatus }),
        category: mapped.category,
        code: mapped.code,
      });
      throw mapped;
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
    }
  }

  #elapsedMs(startedAt: number): number {
    const elapsed = this.#now() - startedAt;
    return Number.isFinite(elapsed) ? Math.max(0, Math.round(elapsed)) : 0;
  }

  #debugOutcome(category: ErrorCategory): SdkDebugOutcome {
    switch (category) {
      case "Protocol":
        return "invalid_response";
      case "Timeout":
        return "timeout";
      case "Cancelled":
        return "cancelled";
      case "Transport":
        return "transport_error";
      case "Indeterminate":
        return "indeterminate";
      default:
        return "runtime_error";
    }
  }

  #emitDebug(event: SdkDebugEvent): void {
    try {
      this.#debugHook?.(Object.freeze({ ...event }));
    } catch {
      // Debug logging is observational and must never change protocol behavior.
    }
  }

  #invalidResponse(policy: RequestPolicy, status: number, action: CallerAction): OwlAuthError {
    return policy.sensitive
      ? this.#indeterminate("invalid_response_after_dispatch", policy.operation, action, status)
      : this.#protocol("invalid_response", policy.operation, status);
  }

  #indeterminate(code: string, operation: string, action: CallerAction, status?: number): OwlAuthError {
    return new OwlAuthError({
      category: "Indeterminate",
      code,
      message: "Runtime may have committed the operation; do not replay it.",
      operation,
      retry: "never",
      action,
      ...(status === undefined ? {} : { status }),
    });
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
      operation: "exchange_handoff",
      retry: "never",
      action: "discard_pending",
    });
  }
}
