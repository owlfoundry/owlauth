const REDACTED = "[REDACTED]";
const INTERNAL_CONSTRUCTOR = Symbol("owlauth.internal-constructor");

abstract class SecretValue {
  readonly #value: string;

  protected constructor(value: string) {
    this.#value = value;
  }

  /** Deliberately reveals protocol material for an explicit outbound request or record export. */
  expose(): string {
    return this.#value;
  }

  toString(): string {
    return REDACTED;
  }

  toJSON(): string {
    return REDACTED;
  }
}

interface RuntimeBinding {
  readonly runtimeOrigin: string;
  readonly runtimeBasePath: string;
  readonly projectId: string;
  readonly applicationId: string;
}

export class AccessToken extends SecretValue implements RuntimeBinding {
  readonly runtimeOrigin: string;
  readonly runtimeBasePath: string;
  readonly projectId: string;
  readonly applicationId: string;

  constructor(token: typeof INTERNAL_CONSTRUCTOR, value: string, binding: RuntimeBinding) {
    if (token !== INTERNAL_CONSTRUCTOR) throw new TypeError("AccessToken is created or restored by Client.");
    super(value);
    this.runtimeOrigin = binding.runtimeOrigin;
    this.runtimeBasePath = binding.runtimeBasePath;
    this.projectId = binding.projectId;
    this.applicationId = binding.applicationId;
  }
}

export class RefreshToken extends SecretValue implements RuntimeBinding {
  readonly runtimeOrigin: string;
  readonly runtimeBasePath: string;
  readonly projectId: string;
  readonly applicationId: string;

  constructor(token: typeof INTERNAL_CONSTRUCTOR, value: string, binding: RuntimeBinding) {
    if (token !== INTERNAL_CONSTRUCTOR) throw new TypeError("RefreshToken is created or restored by Client.");
    super(value);
    this.runtimeOrigin = binding.runtimeOrigin;
    this.runtimeBasePath = binding.runtimeBasePath;
    this.projectId = binding.projectId;
    this.applicationId = binding.applicationId;
  }
}

export class PkceVerifier extends SecretValue {
  constructor(token: typeof INTERNAL_CONSTRUCTOR, value: string) {
    if (token !== INTERNAL_CONSTRUCTOR) throw new TypeError("PkceVerifier is created or restored by Client.");
    super(value);
  }
}

export function createPkceVerifier(value: string): PkceVerifier {
  return new PkceVerifier(INTERNAL_CONSTRUCTOR, value);
}

export interface PublicProvider {
  readonly key: string;
  readonly displayName: string;
  readonly kind: "oidc" | "google" | "github";
}

export interface PublicApplicationConfiguration {
  readonly projectId: string;
  readonly projectDisplayName: string;
  readonly applicationId: string;
  readonly applicationDisplayName: string;
  readonly publishableKeys: readonly string[];
  readonly providers: readonly PublicProvider[];
  readonly emailAvailable: boolean;
  readonly emailOtpEnabled: boolean;
  readonly emailMagicLinkEnabled: boolean;
  readonly loginAvailable: boolean;
}

export interface PublicJwk {
  readonly kty: "OKP";
  readonly crv: "Ed25519";
  readonly alg: "EdDSA";
  readonly use: "sig";
  readonly kid: string;
  readonly x: string;
}

export interface ProjectJwks {
  readonly keys: readonly PublicJwk[];
  readonly revision: number;
  readonly signingEpoch: number;
}

export interface UserProjection {
  readonly userId: string;
  readonly userRevision: number;
  readonly projectionSchema: string;
  readonly projectionRevision: number;
  readonly displayName: string | null;
  readonly pictureUrl: string | null;
  readonly locale: string | null;
  readonly verifiedEmail: string | null;
  readonly status: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CurrentUser {
  readonly projectId: string;
  readonly applicationId: string;
  readonly userId: string;
  readonly projection: UserProjection;
  readonly projectionRevision: number;
  readonly authenticatedAt: string;
  readonly sessionExpiresAt: string;
}

export interface CredentialPairRecord extends RuntimeBinding {
  readonly schemaVersion: 1;
  readonly userId: string;
  readonly sessionId: string;
  readonly refreshGeneration: number;
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly tokenType: "Bearer";
  readonly expiresIn: number;
  readonly projection: UserProjection;
  readonly projectionRevision: number;
  readonly sessionExpiresAt: string;
}

export class CredentialPair implements RuntimeBinding {
  readonly runtimeOrigin: string;
  readonly runtimeBasePath: string;
  readonly projectId: string;
  readonly applicationId: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly refreshGeneration: number;
  readonly accessToken: AccessToken;
  readonly refreshToken: RefreshToken;
  readonly tokenType: "Bearer";
  readonly expiresIn: number;
  readonly projection: UserProjection;
  readonly projectionRevision: number;
  readonly sessionExpiresAt: string;

  constructor(token: typeof INTERNAL_CONSTRUCTOR, value: Omit<CredentialPairRecord, "schemaVersion" | "tokenType">) {
    if (token !== INTERNAL_CONSTRUCTOR) throw new TypeError("CredentialPair is created or restored by Client.");
    const binding: RuntimeBinding = {
      runtimeOrigin: value.runtimeOrigin,
      runtimeBasePath: value.runtimeBasePath,
      projectId: value.projectId,
      applicationId: value.applicationId,
    };
    this.runtimeOrigin = value.runtimeOrigin;
    this.runtimeBasePath = value.runtimeBasePath;
    this.projectId = value.projectId;
    this.applicationId = value.applicationId;
    this.userId = value.userId;
    this.sessionId = value.sessionId;
    this.refreshGeneration = value.refreshGeneration;
    this.accessToken = new AccessToken(INTERNAL_CONSTRUCTOR, value.accessToken, binding);
    this.refreshToken = new RefreshToken(INTERNAL_CONSTRUCTOR, value.refreshToken, binding);
    this.tokenType = "Bearer";
    this.expiresIn = value.expiresIn;
    this.projection = value.projection;
    this.projectionRevision = value.projectionRevision;
    this.sessionExpiresAt = value.sessionExpiresAt;
  }

  /** Explicitly exports secret-bearing state for Application-owned protected storage. */
  exportRecord(): CredentialPairRecord {
    return {
      schemaVersion: 1,
      runtimeOrigin: this.runtimeOrigin,
      runtimeBasePath: this.runtimeBasePath,
      projectId: this.projectId,
      applicationId: this.applicationId,
      userId: this.userId,
      sessionId: this.sessionId,
      refreshGeneration: this.refreshGeneration,
      accessToken: this.accessToken.expose(),
      refreshToken: this.refreshToken.expose(),
      tokenType: "Bearer",
      expiresIn: this.expiresIn,
      projection: this.projection,
      projectionRevision: this.projectionRevision,
      sessionExpiresAt: this.sessionExpiresAt,
    };
  }

  toString(): string {
    return `CredentialPair(project=${this.projectId}, application=${this.applicationId}, generation=${this.refreshGeneration}, tokens=${REDACTED})`;
  }

  toJSON(): Record<string, unknown> {
    return {
      runtimeOrigin: this.runtimeOrigin,
      runtimeBasePath: this.runtimeBasePath,
      projectId: this.projectId,
      applicationId: this.applicationId,
      userId: this.userId,
      sessionId: this.sessionId,
      refreshGeneration: this.refreshGeneration,
      accessToken: REDACTED,
      refreshToken: REDACTED,
      tokenType: this.tokenType,
      expiresIn: this.expiresIn,
      projectionRevision: this.projectionRevision,
      sessionExpiresAt: this.sessionExpiresAt,
    };
  }
}

export function createCredentialPair(
  value: Omit<CredentialPairRecord, "schemaVersion" | "tokenType">,
): CredentialPair {
  return new CredentialPair(INTERNAL_CONSTRUCTOR, value);
}

export interface PendingLoginRecord extends RuntimeBinding {
  readonly schemaVersion: 1;
  readonly redirectUri: string;
  readonly state: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly verifier: string;
}

type PendingState = "available" | "reserved" | "consumed";

export class PendingLogin implements RuntimeBinding {
  readonly runtimeOrigin: string;
  readonly runtimeBasePath: string;
  readonly projectId: string;
  readonly applicationId: string;
  readonly redirectUri: string;
  readonly state: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly #verifier: PkceVerifier;
  #state: PendingState = "available";

  constructor(
    token: typeof INTERNAL_CONSTRUCTOR,
    value: Omit<PendingLoginRecord, "schemaVersion" | "verifier"> & { readonly verifier: PkceVerifier },
  ) {
    if (token !== INTERNAL_CONSTRUCTOR) throw new TypeError("PendingLogin is created or restored by Client.");
    this.runtimeOrigin = value.runtimeOrigin;
    this.runtimeBasePath = value.runtimeBasePath;
    this.projectId = value.projectId;
    this.applicationId = value.applicationId;
    this.redirectUri = value.redirectUri;
    this.state = value.state;
    this.createdAt = value.createdAt;
    this.expiresAt = value.expiresAt;
    this.#verifier = value.verifier;
  }

  get consumed(): boolean {
    return this.#state === "consumed";
  }

  /** @internal */
  reserve(): PkceVerifier | null {
    if (this.#state !== "available") return null;
    this.#state = "reserved";
    return this.#verifier;
  }

  /** @internal */
  commit(): void {
    if (this.#state === "reserved") this.#state = "consumed";
  }

  /** @internal */
  release(): void {
    if (this.#state === "reserved") this.#state = "available";
  }

  /** Explicitly exports secret-bearing state for Application-owned protected storage. */
  exportRecord(): PendingLoginRecord {
    if (this.#state !== "available") throw new TypeError("Only available pending login state can be exported.");
    return {
      schemaVersion: 1,
      runtimeOrigin: this.runtimeOrigin,
      runtimeBasePath: this.runtimeBasePath,
      projectId: this.projectId,
      applicationId: this.applicationId,
      redirectUri: this.redirectUri,
      state: this.state,
      createdAt: this.createdAt,
      expiresAt: this.expiresAt,
      verifier: this.#verifier.expose(),
    };
  }

  toString(): string {
    return `PendingLogin(project=${this.projectId}, application=${this.applicationId}, verifier=${REDACTED})`;
  }

  toJSON(): Record<string, unknown> {
    return {
      schemaVersion: 1,
      runtimeOrigin: this.runtimeOrigin,
      runtimeBasePath: this.runtimeBasePath,
      projectId: this.projectId,
      applicationId: this.applicationId,
      redirectUri: this.redirectUri,
      state: REDACTED,
      createdAt: this.createdAt,
      expiresAt: this.expiresAt,
      verifier: REDACTED,
      consumed: this.consumed,
    };
  }
}

export function createPendingLogin(
  value: Omit<PendingLoginRecord, "schemaVersion" | "verifier"> & { readonly verifier: PkceVerifier },
): PendingLogin {
  return new PendingLogin(INTERNAL_CONSTRUCTOR, value);
}

export interface LoginStartResult {
  readonly hostedUrl: string;
  readonly pending: PendingLogin;
}

export class ValidatedCallback {
  readonly #handoff: string;
  readonly #pending: PendingLogin;
  #reserved = false;

  constructor(token: typeof INTERNAL_CONSTRUCTOR, handoff: string, pending: PendingLogin) {
    if (token !== INTERNAL_CONSTRUCTOR) throw new TypeError("ValidatedCallback is created by Client.");
    this.#handoff = handoff;
    this.#pending = pending;
  }

  /** @internal */
  reserve(): { handoff: string; verifier: PkceVerifier } | null {
    if (this.#reserved) return null;
    const verifier = this.#pending.reserve();
    if (verifier === null) return null;
    this.#reserved = true;
    return { handoff: this.#handoff, verifier };
  }

  /** @internal */
  commit(): void {
    if (!this.#reserved) return;
    this.#pending.commit();
  }

  /** @internal */
  release(): void {
    if (!this.#reserved) return;
    this.#pending.release();
    this.#reserved = false;
  }

  toString(): string {
    return `ValidatedCallback(handoff=${REDACTED})`;
  }

  toJSON(): Record<string, string> {
    return { handoff: REDACTED, verifier: REDACTED };
  }
}

export function createValidatedCallback(handoff: string, pending: PendingLogin): ValidatedCallback {
  return new ValidatedCallback(INTERNAL_CONSTRUCTOR, handoff, pending);
}

export interface BrowserLogoutPreparation {
  readonly hostedUrl: string;
  readonly expiresAt: string;
}

export interface OperationOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}
