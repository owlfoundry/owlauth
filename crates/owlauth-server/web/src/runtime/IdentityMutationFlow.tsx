import { useEffect, useMemo, useRef, useState } from "react";

import type { components } from "../generated/runtime-openapi";
import { readConfiguredBase } from "../shared/configured-base";
import styles from "./app.module.css";
import { createRuntimeClient } from "./client";

export type IdentityMutationOperation = "link" | "unlink" | "merge";
export type IdentityMutationSlotRole =
  "destination_owner" | "candidate_identity" | "identity_owner" | "winner_owner" | "loser_owner";
export type IdentityMutationSlotState =
  | "unselected"
  | "provider_started"
  | "provider_exchange"
  | "provider_failed"
  | "email_address_entry"
  | "email_challenge_pending"
  | "proved"
  | "expired";
export type IdentityMutationNextAction =
  "select_method" | "enter_email" | "verify_email" | "await_provider" | "restart_provider";

export interface IdentityMutationHostedSlot {
  id: string;
  role: IdentityMutationSlotRole;
  identity_kind: "provider" | "email";
  method_kind: "provider" | "email";
  state: IdentityMutationSlotState;
  next_action?: IdentityMutationNextAction | null;
  proved: boolean;
}

export interface IdentityMutationHostedBootstrap {
  project_public_id: string;
  operation_kind: IdentityMutationOperation;
  status: "pending_proof" | "ready" | "completed" | "expired" | "cancelled";
  revision: number;
  csrf: string;
  expires_at: string;
  slots: IdentityMutationHostedSlot[];
}

interface EmailChallenge {
  challengeId: string;
  generation: number;
  proofModes: components["schemas"]["EmailProofMode"][];
  expiresAt: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const HANDLE = /^[A-Za-z0-9._-]{1,256}$/u;
const SAFE_TOKEN = /^[A-Za-z0-9_-]{1,64}$/u;
const SLOT_STATES = new Set<IdentityMutationSlotState>([
  "unselected",
  "provider_started",
  "provider_exchange",
  "provider_failed",
  "email_address_entry",
  "email_challenge_pending",
  "proved",
  "expired",
]);
const NEXT_ACTIONS = new Set<IdentityMutationNextAction>([
  "select_method",
  "enter_email",
  "verify_email",
  "await_provider",
  "restart_provider",
]);
const EXPECTED_NEXT_ACTION: Record<IdentityMutationSlotState, IdentityMutationNextAction | null> = {
  unselected: "select_method",
  provider_started: "await_provider",
  provider_exchange: "await_provider",
  provider_failed: "restart_provider",
  email_address_entry: "enter_email",
  email_challenge_pending: "verify_email",
  proved: null,
  expired: null,
};
export const identityMutationNavigation = {
  replace(target: string) {
    window.location.replace(target);
  },
};

const ROLE_LABEL: Record<IdentityMutationSlotRole, string> = {
  destination_owner: "Destination owner proof",
  candidate_identity: "New identity proof",
  identity_owner: "Identity owner proof",
  winner_owner: "Winning user proof",
  loser_owner: "Losing user proof",
};

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return (
    keys.length === expected.length &&
    keys.every((key, index) => key === [...expected].sort()[index])
  );
}

function positiveRevision(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function validSlot(value: unknown): value is IdentityMutationHostedSlot {
  if (typeof value !== "object" || value === null) return false;
  const slot = value as Record<string, unknown>;
  const expected = ["id", "role", "identity_kind", "method_kind", "state", "next_action", "proved"];
  if (!exactKeys(slot, expected)) return false;
  if (!UUID.test(String(slot["id"]))) return false;
  const role = slot["role"];
  if (
    role !== "destination_owner" &&
    role !== "candidate_identity" &&
    role !== "identity_owner" &&
    role !== "winner_owner" &&
    role !== "loser_owner"
  ) {
    return false;
  }
  const kind = slot["identity_kind"];
  const method = slot["method_kind"];
  if ((kind !== "provider" && kind !== "email") || method !== kind) return false;
  const state = slot["state"];
  if (typeof state !== "string" || !SLOT_STATES.has(state as IdentityMutationSlotState))
    return false;
  const next = slot["next_action"];
  if (
    next !== null &&
    (typeof next !== "string" || !NEXT_ACTIONS.has(next as IdentityMutationNextAction))
  ) {
    return false;
  }
  const typedState = state as IdentityMutationSlotState;
  if (next !== EXPECTED_NEXT_ACTION[typedState]) return false;
  return typeof slot["proved"] === "boolean" && slot["proved"] === (typedState === "proved");
}

/** Strictly admits only the safe server bootstrap shape. Unknown fields fail closed. */
export function validateIdentityMutationBootstrap(
  value: unknown,
): value is IdentityMutationHostedBootstrap {
  if (typeof value !== "object" || value === null) return false;
  const bootstrap = value as Record<string, unknown>;
  if (
    !exactKeys(bootstrap, [
      "project_public_id",
      "operation_kind",
      "status",
      "revision",
      "csrf",
      "expires_at",
      "slots",
    ])
  ) {
    return false;
  }
  if (
    typeof bootstrap["project_public_id"] !== "string" ||
    !HANDLE.test(bootstrap["project_public_id"])
  ) {
    return false;
  }
  const operation = bootstrap["operation_kind"];
  if (operation !== "link" && operation !== "unlink" && operation !== "merge") return false;
  const status = bootstrap["status"];
  if (
    status !== "pending_proof" &&
    status !== "ready" &&
    status !== "completed" &&
    status !== "expired" &&
    status !== "cancelled"
  ) {
    return false;
  }
  if (!positiveRevision(bootstrap["revision"])) return false;
  if (typeof bootstrap["csrf"] !== "string" || !SAFE_TOKEN.test(bootstrap["csrf"])) return false;
  if (
    typeof bootstrap["expires_at"] !== "string" ||
    bootstrap["expires_at"].length > 64 ||
    Number.isNaN(Date.parse(bootstrap["expires_at"]))
  ) {
    return false;
  }
  const slots = bootstrap["slots"];
  if (!Array.isArray(slots) || slots.length < 1 || slots.length > 2 || !slots.every(validSlot)) {
    return false;
  }
  if (new Set(slots.map((slot) => slot.id)).size !== slots.length) return false;
  const roles = slots
    .map((slot) => slot.role)
    .sort()
    .join(":");
  if (
    (operation === "link" && roles !== "candidate_identity:destination_owner") ||
    (operation === "unlink" && roles !== "identity_owner") ||
    (operation === "merge" && roles !== "loser_owner:winner_owner")
  ) {
    return false;
  }
  if (status === "ready" && !slots.every((slot) => slot.proved)) return false;
  return true;
}

export function identityMutationHandleFromPath(): string | null {
  const marker = "/auth/identity-mutations/";
  const index = window.location.pathname.lastIndexOf(marker);
  if (index < 0) return null;
  const encoded = window.location.pathname.slice(index + marker.length);
  if (encoded.length === 0 || encoded.includes("/") || encoded === "email") return null;
  try {
    const handle = decodeURIComponent(encoded);
    return HANDLE.test(handle) ? handle : null;
  } catch {
    return null;
  }
}

function safeProviderNavigation(value: string): string | null {
  if (value.length === 0 || value.length > 4096) return null;
  let target: URL;
  try {
    target = new URL(value);
  } catch {
    return null;
  }
  if (target.username !== "" || target.password !== "" || target.hash !== "") return null;
  if (target.protocol === "https:") return target.href;
  const loopback =
    target.hostname === "localhost" ||
    target.hostname === "127.0.0.1" ||
    target.hostname === "[::1]";
  return target.protocol === "http:" && loopback ? target.href : null;
}

function validProofModes(value: unknown): value is components["schemas"]["EmailProofMode"][] {
  return (
    Array.isArray(value) &&
    value.length >= 1 &&
    value.length <= 2 &&
    value.every((mode) => mode === "otp" || mode === "magic_link") &&
    new Set(value).size === value.length
  );
}

function stateDescription(slot: IdentityMutationHostedSlot): string {
  switch (slot.state) {
    case "unselected":
      return `Ready to start the fixed ${slot.method_kind} proof method.`;
    case "provider_started":
    case "provider_exchange":
      return "Provider verification is in progress. Return here after the provider finishes.";
    case "provider_failed":
      return "Provider verification did not finish. You may explicitly restart this fixed method.";
    case "email_address_entry":
      return "Enter the address controlled by this proof subject.";
    case "email_challenge_pending":
      return "Use the newest email code or link. A resend creates a newer generation.";
    case "proved":
      return "Proof complete. Ownership has not changed.";
    case "expired":
      return "This proof slot expired.";
  }
}

interface IdentityMutationFlowProps {
  readonly handle: string;
  readonly bootstrap: IdentityMutationHostedBootstrap;
}

export function IdentityMutationFlow({ handle, bootstrap }: IdentityMutationFlowProps) {
  const [intent, setIntent] = useState(bootstrap);
  const [pendingSlot, setPendingSlot] = useState<string | null>(null);
  const [emailBySlot, setEmailBySlot] = useState<Record<string, string>>({});
  const [otpBySlot, setOtpBySlot] = useState<Record<string, string>>({});
  const [challengeBySlot, setChallengeBySlot] = useState<Record<string, EmailChallenge>>({});
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);
  const feedbackRef = useRef<HTMLHeadingElement>(null);

  useEffect(
    () => () => {
      abort.current?.abort();
      abort.current = null;
    },
    [],
  );
  useEffect(() => {
    if (feedback !== null || error !== null) feedbackRef.current?.focus();
  }, [error, feedback]);

  const allProved = useMemo(() => intent.slots.every((slot) => slot.proved), [intent.slots]);

  function beginRequest(slotId: string | null): AbortController {
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    setPendingSlot(slotId ?? "intent");
    setFeedback("Please wait.");
    setError(null);
    return controller;
  }

  function finishRequest(controller: AbortController) {
    if (abort.current === controller) abort.current = null;
    setPendingSlot(null);
  }

  function updateSlot(slotId: string, revision: number, state: IdentityMutationSlotState) {
    setIntent((current) => ({
      ...current,
      revision,
      slots: current.slots.map((slot) =>
        slot.id === slotId
          ? {
              ...slot,
              state,
              next_action: EXPECTED_NEXT_ACTION[state],
              proved: state === "proved",
            }
          : slot,
      ),
    }));
  }

  async function selectMethod(slot: IdentityMutationHostedSlot) {
    if (pendingSlot !== null || intent.status !== "pending_proof") return;
    const controller = beginRequest(slot.id);
    try {
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/method",
        {
          params: {
            path: {
              project_public_id: intent.project_public_id,
              intent: handle,
              proof_slot: slot.id,
            },
          },
          body: {
            expected_revision: intent.revision,
            csrf: intent.csrf,
            method_kind: slot.method_kind,
          },
          signal: controller.signal,
        },
      );
      if (controller.signal.aborted) return;
      if (!response.ok || data?.method_kind !== slot.method_kind) throw new Error("rejected");
      if (data.method_kind === "provider") {
        const target = safeProviderNavigation(data.result.url);
        if (target === null) throw new Error("unsafe navigation");
        identityMutationNavigation.replace(target);
        return;
      }
      if (!positiveRevision(data.result.revision) || data.result.state !== "email_address_entry") {
        throw new Error("invalid response");
      }
      updateSlot(slot.id, data.result.revision, "email_address_entry");
      setFeedback("Email proof is ready for address entry.");
    } catch {
      if (!controller.signal.aborted) {
        setError("The proof method could not be started. Reload this request before trying again.");
        setFeedback(null);
      }
    } finally {
      finishRequest(controller);
    }
  }

  async function sendChallenge(slot: IdentityMutationHostedSlot) {
    const email = emailBySlot[slot.id] ?? "";
    if (!/^\S{1,64}@\S{3,253}$/u.test(email) || email.length > 254 || pendingSlot !== null) return;
    const controller = beginRequest(slot.id);
    setEmailBySlot((current) => ({ ...current, [slot.id]: "" }));
    try {
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/email/challenges",
        {
          params: {
            path: {
              project_public_id: intent.project_public_id,
              intent: handle,
              proof_slot: slot.id,
            },
          },
          body: { expected_revision: intent.revision, csrf: intent.csrf, email },
          signal: controller.signal,
        },
      );
      if (
        controller.signal.aborted ||
        !response.ok ||
        data?.accepted !== true ||
        !positiveRevision(data.revision) ||
        typeof data.challenge_id !== "string" ||
        !UUID.test(data.challenge_id) ||
        !Number.isSafeInteger(data.generation) ||
        data.generation < 1 ||
        !validProofModes(data.proof_modes) ||
        typeof data.expires_at !== "string" ||
        Number.isNaN(Date.parse(data.expires_at))
      ) {
        throw new Error("invalid response");
      }
      updateSlot(slot.id, data.revision, "email_challenge_pending");
      setChallengeBySlot((current) => ({
        ...current,
        [slot.id]: {
          challengeId: data.challenge_id,
          generation: data.generation,
          proofModes: data.proof_modes,
          expiresAt: data.expires_at,
        },
      }));
      setFeedback("Email accepted. Use only the newest code or link.");
    } catch {
      if (!controller.signal.aborted) {
        setError(
          "The email challenge could not be created. Reload before retrying an uncertain request.",
        );
        setFeedback(null);
      }
    } finally {
      finishRequest(controller);
    }
  }

  async function verifyOtp(slot: IdentityMutationHostedSlot) {
    const challenge = challengeBySlot[slot.id];
    const otp = otpBySlot[slot.id] ?? "";
    if (
      challenge === undefined ||
      !challenge.proofModes.includes("otp") ||
      !/^\d{6,10}$/u.test(otp)
    ) {
      return;
    }
    const controller = beginRequest(slot.id);
    setOtpBySlot((current) => ({ ...current, [slot.id]: "" }));
    try {
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/email/otp/verify",
        {
          params: {
            path: {
              project_public_id: intent.project_public_id,
              intent: handle,
              proof_slot: slot.id,
            },
          },
          body: {
            expected_revision: intent.revision,
            csrf: intent.csrf,
            challenge_id: challenge.challengeId,
            generation: challenge.generation,
            otp,
          },
          signal: controller.signal,
        },
      );
      if (!response.ok || data?.state !== "proved" || !positiveRevision(data.revision)) {
        setError("The code was not accepted. Use only the newest code.");
        setFeedback(null);
        return;
      }
      updateSlot(slot.id, data.revision, "proved");
      setFeedback(`${ROLE_LABEL[slot.role]} completed. Ownership has not changed.`);
    } catch {
      if (!controller.signal.aborted) {
        setError("Proof status is uncertain. Reload this request before taking another action.");
        setFeedback(null);
      }
    } finally {
      finishRequest(controller);
    }
  }

  async function confirmReady() {
    if (!allProved || pendingSlot !== null || intent.status !== "pending_proof") return;
    const controller = beginRequest(null);
    try {
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/confirm",
        {
          params: { path: { project_public_id: intent.project_public_id, intent: handle } },
          body: { expected_revision: intent.revision, csrf: intent.csrf },
          signal: controller.signal,
        },
      );
      if (!response.ok || data?.status !== "ready" || !positiveRevision(data.revision)) {
        throw new Error("not ready");
      }
      setIntent((current) => ({ ...current, revision: data.revision, status: "ready" }));
      setFeedback("Proof collection is ready. Return to the operator for final confirmation.");
    } catch {
      if (!controller.signal.aborted) {
        setError(
          "Ready status is uncertain. Ask the operator to read the intent before continuing.",
        );
        setFeedback(null);
      }
    } finally {
      finishRequest(controller);
    }
  }

  if (intent.status === "expired") {
    return (
      <MutationTerminal
        title="Identity verification expired"
        message="Ask the operator to create a new request."
        error
      />
    );
  }
  if (intent.status === "cancelled") {
    return (
      <MutationTerminal
        title="Identity verification cancelled"
        message="No identity ownership was changed."
      />
    );
  }
  if (intent.status === "completed") {
    return (
      <MutationTerminal
        title="Identity change completed"
        message="The operator completed the requested identity change."
      />
    );
  }
  if (intent.status === "ready") {
    return (
      <MutationTerminal
        title="Proofs ready for operator review"
        message="Proof collection is complete. Identity ownership has not changed until the operator confirms the immutable plan."
      />
    );
  }

  return (
    <section aria-labelledby="identity-mutation-heading" aria-busy={pendingSlot !== null}>
      <h2 id="identity-mutation-heading">Verify the {intent.operation_kind} request</h2>
      <p className={styles["summary"]}>
        Complete every server-selected proof slot. Proof completion does not itself link, unlink, or
        merge an identity.
      </p>
      {error === null && feedback === null ? null : (
        <div className={error === null ? styles["notice"] : styles["error"]}>
          <h3 ref={feedbackRef} tabIndex={-1} className={styles["focusTarget"]}>
            {error === null ? "Status" : "Action not completed"}
          </h3>
          <p role={error === null ? "status" : "alert"}>{error ?? feedback}</p>
        </div>
      )}
      <ol className={styles["proofSlots"]} aria-label="Required identity proofs">
        {intent.slots.map((slot) => {
          const challenge = challengeBySlot[slot.id];
          const canStart =
            slot.next_action === "select_method" || slot.next_action === "restart_provider";
          const canEnterEmail =
            slot.method_kind === "email" &&
            (slot.next_action === "enter_email" || slot.next_action === "verify_email");
          return (
            <li key={slot.id}>
              <h3>{ROLE_LABEL[slot.role]}</h3>
              <p>
                Fixed method: {slot.method_kind}; state: <strong>{slot.state}</strong>
                {slot.next_action === null ? null : <>; next action: {slot.next_action}</>}.
              </p>
              <p>{stateDescription(slot)}</p>
              {canStart ? (
                <button
                  className={styles["method"]}
                  type="button"
                  disabled={pendingSlot !== null}
                  onClick={() => void selectMethod(slot)}
                >
                  {slot.next_action === "restart_provider"
                    ? "Restart fixed provider proof"
                    : `Start ${slot.method_kind} proof`}
                </button>
              ) : null}
              {canEnterEmail ? (
                <form
                  onSubmit={(event) => {
                    event.preventDefault();
                    void sendChallenge(slot);
                  }}
                >
                  <label htmlFor={`identity-email-${slot.id}`}>Email address for this proof</label>
                  <input
                    id={`identity-email-${slot.id}`}
                    type="email"
                    autoComplete="email"
                    required
                    maxLength={254}
                    value={emailBySlot[slot.id] ?? ""}
                    onChange={(event) => {
                      setEmailBySlot((current) => ({ ...current, [slot.id]: event.target.value }));
                    }}
                  />
                  <button
                    className={styles["secondary"]}
                    type="submit"
                    disabled={pendingSlot !== null}
                  >
                    {slot.next_action === "verify_email"
                      ? "Send a newer email"
                      : "Send verification email"}
                  </button>
                </form>
              ) : null}
              {challenge?.proofModes.includes("otp") === true &&
              slot.state === "email_challenge_pending" ? (
                <form
                  onSubmit={(event) => {
                    event.preventDefault();
                    void verifyOtp(slot);
                  }}
                >
                  <p>
                    Use the newest code. This challenge expires at{" "}
                    {new Date(challenge.expiresAt).toLocaleTimeString()}.
                  </p>
                  <label htmlFor={`identity-otp-${slot.id}`}>One-time code</label>
                  <input
                    id={`identity-otp-${slot.id}`}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9]{6,10}"
                    minLength={6}
                    maxLength={10}
                    required
                    value={otpBySlot[slot.id] ?? ""}
                    onChange={(event) => {
                      setOtpBySlot((current) => ({
                        ...current,
                        [slot.id]: event.target.value.replace(/\D/gu, "").slice(0, 10),
                      }));
                    }}
                  />
                  <button
                    className={styles["method"]}
                    type="submit"
                    disabled={pendingSlot !== null}
                  >
                    Verify newest code
                  </button>
                </form>
              ) : null}
            </li>
          );
        })}
      </ol>
      {allProved ? (
        <section aria-labelledby="identity-ready-heading" className={styles["notice"]}>
          <h3 id="identity-ready-heading">All required proofs are complete</h3>
          <p>
            Explicitly mark proof collection ready. The operator must still review and confirm the
            exact plan.
          </p>
          <button
            className={styles["method"]}
            type="button"
            disabled={pendingSlot !== null}
            onClick={() => void confirmReady()}
          >
            Mark proofs ready for operator review
          </button>
        </section>
      ) : null}
    </section>
  );
}

function MutationTerminal({
  title,
  message,
  error = false,
}: {
  readonly title: string;
  readonly message: string;
  readonly error?: boolean;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus();
  }, []);
  return (
    <section aria-labelledby="identity-mutation-result" aria-live="polite">
      <h2
        id="identity-mutation-result"
        ref={heading}
        tabIndex={-1}
        className={styles["focusTarget"]}
      >
        {title}
      </h2>
      <p role={error ? "alert" : "status"} className={error ? styles["error"] : undefined}>
        {message}
      </p>
    </section>
  );
}
