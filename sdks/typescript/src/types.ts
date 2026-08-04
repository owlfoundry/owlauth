const REDACTED = "[REDACTED]";
const INTERNAL_CONSTRUCTOR = Symbol("owlauth.internal-constructor");

abstract class SecretValue {
  readonly #value: string;

  protected constructor(value: string) {
    this.#value = value;
  }

  /** Deliberately reveals protocol material for an explicit outbound request. */
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

export class AccessToken extends SecretValue {
  constructor(value: string) {
    super(value);
  }
}

export class RefreshToken extends SecretValue {
  constructor(value: string) {
    super(value);
  }
}

export class PkceVerifier extends SecretValue {
  constructor(value: string) {
    super(value);
  }
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

export class CredentialPair {
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

  constructor(
    token: typeof INTERNAL_CONSTRUCTOR,
    value: {
      projectId: string;
      applicationId: string;
      userId: string;
      sessionId: string;
      refreshGeneration: number;
      accessToken: string;
      refreshToken: string;
      expiresIn: number;
      projection: UserProjection;
      projectionRevision: number;
      sessionExpiresAt: string;
    },
  ) {
    if (token !== INTERNAL_CONSTRUCTOR) throw new TypeError("CredentialPair is created by Client.");
    this.projectId = value.projectId;
    this.applicationId = value.applicationId;
    this.userId = value.userId;
    this.sessionId = value.sessionId;
    this.refreshGeneration = value.refreshGeneration;
    this.accessToken = new AccessToken(value.accessToken);
    this.refreshToken = new RefreshToken(value.refreshToken);
    this.tokenType = "Bearer";
    this.expiresIn = value.expiresIn;
    this.projection = value.projection;
    this.projectionRevision = value.projectionRevision;
    this.sessionExpiresAt = value.sessionExpiresAt;
  }

  toString(): string {
    return `CredentialPair(project=${this.projectId}, application=${this.applicationId}, generation=${this.refreshGeneration}, tokens=${REDACTED})`;
  }

  toJSON(): Record<string, unknown> {
    return {
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

export function createCredentialPair(value: ConstructorParameters<typeof CredentialPair>[1]): CredentialPair {
  return new CredentialPair(INTERNAL_CONSTRUCTOR, value);
}

export class PendingLogin {
  readonly runtimeOrigin: string;
  readonly runtimeBasePath: string;
  readonly projectId: string;
  readonly applicationId: string;
  readonly redirectUri: string;
  readonly state: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly #verifier: PkceVerifier;
  #consumed = false;

  constructor(
    token: typeof INTERNAL_CONSTRUCTOR,
    value: {
      runtimeOrigin: string;
      runtimeBasePath: string;
      projectId: string;
      applicationId: string;
      redirectUri: string;
      state: string;
      createdAt: number;
      expiresAt: number;
      verifier: PkceVerifier;
    },
  ) {
    if (token !== INTERNAL_CONSTRUCTOR) throw new TypeError("PendingLogin is created by Client.");
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
    return this.#consumed;
  }

  /** @internal */
  consume(): PkceVerifier | null {
    if (this.#consumed) return null;
    this.#consumed = true;
    return this.#verifier;
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
      consumed: this.#consumed,
    };
  }
}

export function createPendingLogin(value: ConstructorParameters<typeof PendingLogin>[1]): PendingLogin {
  return new PendingLogin(INTERNAL_CONSTRUCTOR, value);
}

export interface LoginStartResult {
  readonly hostedUrl: string;
  readonly pending: PendingLogin;
}

export class ValidatedCallback {
  readonly #handoff: string;
  readonly #pending: PendingLogin;
  #consumed = false;

  constructor(token: typeof INTERNAL_CONSTRUCTOR, handoff: string, pending: PendingLogin) {
    if (token !== INTERNAL_CONSTRUCTOR) throw new TypeError("ValidatedCallback is created by Client.");
    this.#handoff = handoff;
    this.#pending = pending;
  }

  /** @internal */
  consume(): { handoff: string; verifier: PkceVerifier } | null {
    if (this.#consumed) return null;
    const verifier = this.#pending.consume();
    if (verifier === null) return null;
    this.#consumed = true;
    return { handoff: this.#handoff, verifier };
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
