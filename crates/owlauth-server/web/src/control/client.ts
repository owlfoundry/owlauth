import createClient from "openapi-fetch";

import type { components, paths } from "../generated/control-openapi";
import { assertSameOriginPlaneUrl } from "../shared/configured-base";

export type Project = components["schemas"]["Project"];
export type ProjectPolicy = components["schemas"]["ProjectPolicy"];
export type Application = components["schemas"]["Application"];
export type WebhookEndpoint = components["schemas"]["WebhookEndpoint"];
export type ApplicationUserEvent = components["schemas"]["ApplicationUserEvent"];
export type WebhookDelivery = components["schemas"]["WebhookDelivery"];
export type ApplicationUserEventType = components["schemas"]["ApplicationUserEventType"];
export type SigningKey = components["schemas"]["SigningKey"];
export type ProjectClientKey = components["schemas"]["ProjectClientKey"];
export type CreateProjectClientKeyResponse =
  components["schemas"]["CreateProjectClientKeyResponse"];
export type Provider = components["schemas"]["Provider"];
export type ProviderEgressPolicy = components["schemas"]["ProviderEgressPolicy"];
export type OidcPreflightResult = components["schemas"]["OidcPreflightResult"];
export type EmailMethodPolicy = components["schemas"]["EmailMethodPolicy"];
export type EmailAssignment = components["schemas"]["EmailAssignment"];
export type SmtpConfiguration = components["schemas"]["SmtpConfiguration"];
export type ProjectUser = components["schemas"]["ProjectUser"];
export type ProjectUserSessions = components["schemas"]["ProjectUserSessions"];
export type ApplicationSession = components["schemas"]["ApplicationSession"];
export type BrowserSession = components["schemas"]["BrowserSession"];
export type ManagedProviderConnection = components["schemas"]["ManagedProviderConnection"];
export type ProjectUserIdentity = components["schemas"]["ProjectUserIdentity"];
export type IdentityMutationIntent = components["schemas"]["IdentityMutationIntent"];
export type CreateIdentityMutationIntentRequest =
  components["schemas"]["CreateIdentityMutationIntentRequest"];
export type ConfirmIdentityMutationIntentRequest =
  components["schemas"]["ConfirmIdentityMutationIntentRequest"];
export type IdentityMutationProofAuthority =
  components["schemas"]["IdentityMutationProofAuthority"];
export type ProblemDetails = components["schemas"]["ProblemDetails"];

export interface DisposableControlClient {
  readonly client: ReturnType<typeof createClient<paths>>;
  dispose(): void;
}

export class ControlAuthenticationError extends Error {
  constructor() {
    super("Control authentication failed");
    this.name = "ControlAuthenticationError";
  }
}

export class ControlRequestError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(problem: ProblemDetails | undefined, status: number) {
    super(problem?.detail ?? "The Control request could not be completed.");
    this.name = "ControlRequestError";
    this.code = problem?.code ?? "request_failed";
    this.status = status;
  }
}

export function newIdempotencyKey(): string {
  return `console_${crypto.randomUUID().replaceAll("-", "")}`;
}

export class IdempotencyAttempt {
  private key: string | null = null;
  private inFlight = false;

  begin(): string | null {
    if (this.inFlight) return null;
    this.inFlight = true;
    this.key ??= newIdempotencyKey();
    return this.key;
  }

  settle(error?: unknown): void {
    this.inFlight = false;
    if (error === undefined || !isAmbiguousIdempotencyFailure(error)) {
      this.key = null;
    }
  }

  abandon(): void {
    this.inFlight = false;
    this.key = null;
  }

  get retainsKey(): boolean {
    return this.key !== null;
  }
}

export function isAmbiguousIdempotencyFailure(error: unknown): boolean {
  if (!(error instanceof ControlRequestError)) return true;
  return (
    error.status === 408 ||
    error.status >= 500 ||
    (error.status === 409 && error.code === "operation_in_progress")
  );
}

export function requireData<T>(data: T | undefined, error: unknown, response: Response): T {
  if (data !== undefined) return data;
  throw new ControlRequestError(isProblemDetails(error) ? error : undefined, response.status);
}

function isProblemDetails(value: unknown): value is ProblemDetails {
  if (typeof value !== "object" || value === null) return false;
  return (
    "code" in value &&
    typeof value.code === "string" &&
    "detail" in value &&
    typeof value.detail === "string"
  );
}

function createControlClient(
  controlBase: string,
  operatorKey: string,
  fetchImplementation: typeof fetch,
): DisposableControlClient {
  let activeKey = operatorKey;
  let disposed = false;
  const lifetime = new AbortController();

  const baseUrl = assertSameOriginPlaneUrl(controlBase, controlBase).href;
  const client = createClient<paths>({
    baseUrl,
    fetch: async (input) => {
      if (disposed) {
        throw new Error("Control client is locked");
      }

      const request = input instanceof Request ? input : new Request(input);
      assertSameOriginPlaneUrl(request.url, controlBase);
      const headers = new Headers(request.headers);
      headers.delete("authorization");
      headers.set("authorization", `Bearer ${activeKey}`);
      const signal = AbortSignal.any([request.signal, lifetime.signal]);
      return fetchImplementation(new Request(request, { headers, signal }));
    },
  });

  return {
    client,
    dispose() {
      if (disposed) return;
      disposed = true;
      lifetime.abort();
      activeKey = "";
    },
  };
}

/**
 * Verifies one page-memory key through the ordinary Control API and returns its
 * disposable same-base client. A failed or malformed response always disposes the key.
 */
export async function verifyControlKey(
  controlBase: string,
  operatorKey: string,
  fetchImplementation: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<DisposableControlClient> {
  const disposable = createControlClient(controlBase, operatorKey, fetchImplementation);
  try {
    const { data, response } = await disposable.client.GET(
      "/v1/system",
      signal === undefined ? {} : { signal },
    );
    if (!response.ok || data?.product !== "owlauth-server" || !data.provisioning) {
      throw new ControlAuthenticationError();
    }
    return disposable;
  } catch (error) {
    disposable.dispose();
    if (error instanceof ControlAuthenticationError) throw error;
    throw new ControlAuthenticationError();
  }
}
