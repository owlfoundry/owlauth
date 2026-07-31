export type ErrorCategory =
  | "Configuration"
  | "Protocol"
  | "Login"
  | "Handoff"
  | "Authentication"
  | "Session"
  | "Refresh"
  | "RateLimited"
  | "Transport"
  | "Timeout"
  | "Cancelled"
  | "Indeterminate";

export type RetryDisposition = "never" | "safe_after_delay" | "application_decision";

export type CallerAction =
  | "none"
  | "discard_pending"
  | "quarantine_pending"
  | "invalidate_credentials"
  | "quarantine_credentials"
  | "reauthenticate";

export interface ClientErrorOptions {
  readonly category: ErrorCategory;
  readonly code: string;
  readonly message: string;
  readonly operation: string;
  readonly retry: RetryDisposition;
  readonly action: CallerAction;
  readonly requestId?: string;
  readonly status?: number;
  readonly cause?: Error;
}

/** Stable, secret-free OwlAuth protocol failure. */
export class OwlAuthError extends Error {
  readonly category: ErrorCategory;
  readonly code: string;
  readonly operation: string;
  readonly retry: RetryDisposition;
  readonly action: CallerAction;
  readonly requestId: string | undefined;
  readonly status: number | undefined;

  constructor(options: ClientErrorOptions) {
    super(options.message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "OwlAuthError";
    this.category = options.category;
    this.code = options.code;
    this.operation = options.operation;
    this.retry = options.retry;
    this.action = options.action;
    this.requestId = options.requestId;
    this.status = options.status;
  }

  override toString(): string {
    return `${this.name}[${this.category}/${this.code}] ${this.message}`;
  }
}

export function configurationError(code: string, message: string): OwlAuthError {
  return new OwlAuthError({
    category: "Configuration",
    code,
    message,
    operation: "configure_client",
    retry: "never",
    action: "none",
  });
}
