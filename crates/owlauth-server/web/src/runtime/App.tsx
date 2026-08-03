import { useEffect, useRef, useState } from "react";

import type { components } from "../generated/runtime-openapi";
import { readConfiguredBase } from "../shared/configured-base";
import { Shell } from "../shared/Shell";
import styles from "./app.module.css";
import { createRuntimeClient } from "./client";
import {
  IdentityMutationFlow,
  identityMutationHandleFromPath,
  type IdentityMutationHostedBootstrap,
  validateIdentityMutationBootstrap,
} from "./IdentityMutationFlow";
import {
  consumeIdentityMutationMagicBootstrap,
  IdentityMutationMagicFlow,
  type IdentityMutationMagicBootstrap,
} from "./IdentityMutationMagicFlow";

export const hostedNavigation = {
  replace(target: string) {
    window.location.replace(target);
  },
};

type HostedInteraction = components["schemas"]["HostedInteractionResponse"];
type HostedProvider = components["schemas"]["HostedProvider"];
type EmailProofMode = components["schemas"]["EmailProofMode"];
type BrowserLogout = components["schemas"]["BrowserLogoutResponse"];
interface SafeHostedError {
  title: string;
  message: string;
}
interface ManagedReauthorizationBootstrap {
  project_public_id: string;
  provider_key: string;
  status: string;
  revision: number;
  csrf?: string;
  expires_at: string;
}
type RuntimeFlow =
  | { kind: "interaction"; handle: string; bootstrap: HostedInteraction }
  | { kind: "managed-reauthorization"; handle: string; bootstrap: ManagedReauthorizationBootstrap }
  | { kind: "browser-logout"; handle: string; bootstrap: BrowserLogout }
  | { kind: "email-magic"; challengeId: string; context: MagicContext | null }
  | { kind: "identity-mutation"; handle: string; bootstrap: IdentityMutationHostedBootstrap }
  | { kind: "identity-mutation-magic"; bootstrap: IdentityMutationMagicBootstrap }
  | { kind: "error"; bootstrap: SafeHostedError };
interface MagicContext {
  proof: string;
  project: string;
  transaction: string;
  csrf: string;
  generation: number;
  revision: number;
}
type ViewState =
  | { status: "ready-interaction"; handle: string; bootstrap: HostedInteraction }
  | { status: "email-entry"; handle: string; bootstrap: HostedInteraction }
  | {
      status: "email-proof";
      handle: string;
      bootstrap: HostedInteraction;
      challengeId: string;
      generation: number;
      proofModes: EmailProofMode[];
      expiresAt: string;
    }
  | { status: "ready-magic"; challengeId: string; context: MagicContext | null }
  | { status: "identity-mutation"; handle: string; bootstrap: IdentityMutationHostedBootstrap }
  | { status: "identity-mutation-magic"; bootstrap: IdentityMutationMagicBootstrap }
  | { status: "ready-logout"; handle: string; bootstrap: BrowserLogout }
  | {
      status: "ready-managed-reauthorization";
      handle: string;
      bootstrap: ManagedReauthorizationBootstrap;
    }
  | { status: "submitting"; title: string; message: string }
  | { status: "progress"; title: string; message: string }
  | { status: "complete"; title: string; message: string }
  | { status: "error"; title: string; message: string }
  | { status: "idle" };

const MAX_HANDLE_LENGTH = 256;
const MAX_NAVIGATION_LENGTH = 4096;
const HANDLE_PATTERN = /^[A-Za-z0-9._-]+$/u;
const INTERACTION_STATUSES = new Set([
  "awaiting_method_selection",
  "email_address_entry",
  "email_challenge_pending",
  "provider_authorization_started",
  "provider_exchange_in_progress",
  "authenticated",
  "handoff_issued",
  "completed",
  "failed",
  "expired",
]);

function boundedString(value: unknown, maximum: number, allowEmpty = false): value is string {
  return typeof value === "string" && value.length <= maximum && (allowEmpty || value.length > 0);
}

function validHandle(value: string): boolean {
  return value.length <= MAX_HANDLE_LENGTH && HANDLE_PATTERN.test(value);
}

function pathHandle(marker: string): string | null {
  const index = window.location.pathname.lastIndexOf(marker);
  if (index < 0) return null;
  const encoded = window.location.pathname.slice(index + marker.length);
  if (encoded.length === 0 || encoded.includes("/")) return null;
  try {
    const value = decodeURIComponent(encoded);
    return validHandle(value) ? value : null;
  } catch {
    return null;
  }
}

function validProofModes(value: unknown, allowEmpty: boolean): value is EmailProofMode[] {
  if (!Array.isArray(value) || value.length > 2 || (!allowEmpty && value.length === 0))
    return false;
  if (!value.every((mode) => mode === "otp" || mode === "magic_link")) return false;
  return new Set(value).size === value.length;
}

function validProvider(value: unknown): value is HostedProvider {
  if (typeof value !== "object" || value === null) return false;
  const provider = value as Record<string, unknown>;
  return boundedString(provider["key"], 64) && boundedString(provider["display_name"], 128);
}

function validInteraction(value: unknown): value is HostedInteraction {
  if (typeof value !== "object" || value === null) return false;
  const interaction = value as Record<string, unknown>;
  const providers = interaction["providers"];
  if (!Array.isArray(providers) || providers.length > 50) return false;
  const emailAvailable = interaction["email_available"];
  if (typeof emailAvailable !== "boolean") return false;
  if (!validProofModes(interaction["email_proof_modes"], !emailAvailable)) return false;
  if (emailAvailable !== interaction["email_proof_modes"].length > 0) return false;
  if (!providers.every(validProvider)) return false;
  const keys = providers.map((provider) => provider.key);
  return (
    new Set(keys).size === keys.length &&
    boundedString(interaction["project_id"], 96) &&
    boundedString(interaction["project_display_name"], 128) &&
    boundedString(interaction["application_id"], 96) &&
    boundedString(interaction["application_display_name"], 128) &&
    (interaction["application_type"] === "web" || interaction["application_type"] === "native") &&
    boundedString(interaction["csrf"], 64) &&
    boundedString(interaction["expires_at"], 64) &&
    !Number.isNaN(Date.parse(interaction["expires_at"])) &&
    typeof interaction["revision"] === "number" &&
    Number.isSafeInteger(interaction["revision"]) &&
    interaction["revision"] > 0 &&
    typeof interaction["session_reuse_available"] === "boolean" &&
    (providers.length > 0 || emailAvailable) &&
    (interaction["presentation_hint"] === null ||
      interaction["presentation_hint"] === undefined ||
      boundedString(interaction["presentation_hint"], 64)) &&
    boundedString(interaction["status"], 64) &&
    INTERACTION_STATUSES.has(interaction["status"])
  );
}

function validManagedReauthorization(value: unknown): value is ManagedReauthorizationBootstrap {
  if (typeof value !== "object" || value === null) return false;
  const interaction = value as Record<string, unknown>;
  const statuses = new Set([
    "awaiting_provider_start",
    "provider_authorization_started",
    "provider_exchange_in_progress",
    "completed",
    "provider_exchange_failed",
    "expired",
    "cancelled",
  ]);
  return (
    boundedString(interaction["project_public_id"], 96) &&
    boundedString(interaction["provider_key"], 64) &&
    boundedString(interaction["status"], 64) &&
    statuses.has(interaction["status"]) &&
    typeof interaction["revision"] === "number" &&
    Number.isSafeInteger(interaction["revision"]) &&
    interaction["revision"] > 0 &&
    (interaction["csrf"] === undefined || boundedString(interaction["csrf"], 64)) &&
    boundedString(interaction["expires_at"], 64) &&
    !Number.isNaN(Date.parse(interaction["expires_at"]))
  );
}

function validHostedError(value: unknown): value is SafeHostedError {
  if (typeof value !== "object" || value === null) return false;
  const error = value as Record<string, unknown>;
  return boundedString(error["title"], 128) && boundedString(error["message"], 256);
}

function validBrowserLogout(value: unknown): value is BrowserLogout {
  if (typeof value !== "object" || value === null) return false;
  const logout = value as Record<string, unknown>;
  return (
    boundedString(logout["project_id"], 96) &&
    boundedString(logout["csrf"], 64) &&
    boundedString(logout["expires_at"], 64) &&
    !Number.isNaN(Date.parse(logout["expires_at"])) &&
    typeof logout["revision"] === "number" &&
    Number.isSafeInteger(logout["revision"]) &&
    logout["revision"] > 0
  );
}

export function consumeRuntimeFlow(): RuntimeFlow | null {
  const flowElement = document.head.querySelector<HTMLMetaElement>(
    'meta[name="owlauth-runtime-flow"]',
  );
  const bootstrapElement = document.head.querySelector<HTMLMetaElement>(
    'meta[name="owlauth-runtime-bootstrap"]',
  );
  const magicCsrfElement = document.head.querySelector<HTMLMetaElement>(
    'meta[name="owlauth-magic-csrf"]',
  );
  const flow = flowElement?.content;
  const serialized = bootstrapElement?.content;
  const magicCsrf = magicCsrfElement?.content;
  flowElement?.remove();
  bootstrapElement?.remove();
  magicCsrfElement?.remove();
  if (flow === "identity_mutation_magic") {
    return { kind: "identity-mutation-magic", bootstrap: consumeIdentityMutationMagicBootstrap() };
  }
  if (flow === "email-magic") {
    const challengeId = pathHandle("/auth/email/confirm/");
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const proof = fragment.get("proof");
    const project = fragment.get("project");
    const transaction = fragment.get("transaction");
    const generation = Number(fragment.get("generation"));
    const revision = Number(fragment.get("revision"));
    window.history.replaceState(
      window.history.state,
      "",
      window.location.pathname + window.location.search,
    );
    const context =
      proof !== null &&
      /^[A-Za-z0-9_-]{22,128}$/u.test(proof) &&
      project !== null &&
      validHandle(project) &&
      transaction !== null &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        transaction,
      ) &&
      magicCsrf !== undefined &&
      magicCsrf.length <= 64 &&
      /^[A-Za-z0-9_-]+$/u.test(magicCsrf) &&
      Number.isSafeInteger(generation) &&
      generation >= 1 &&
      generation <= 5 &&
      Number.isSafeInteger(revision) &&
      revision > 0
        ? { proof, project, transaction, csrf: magicCsrf, generation, revision }
        : null;
    return challengeId === null ? null : { kind: "email-magic", challengeId, context };
  }
  if (serialized === undefined) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    return null;
  }
  if (flow === "interaction" && validInteraction(parsed)) {
    const handle = pathHandle("/auth/interactions/");
    return handle === null ? null : { kind: "interaction", handle, bootstrap: parsed };
  }
  if (flow === "identity_mutation" && validateIdentityMutationBootstrap(parsed)) {
    const handle = identityMutationHandleFromPath();
    return handle === null ? null : { kind: "identity-mutation", handle, bootstrap: parsed };
  }
  if (flow === "managed_reauthorization" && validManagedReauthorization(parsed)) {
    const handle = pathHandle("/auth/managed-reauthorizations/");
    return handle === null ? null : { kind: "managed-reauthorization", handle, bootstrap: parsed };
  }
  if (flow === "browser-logout" && validBrowserLogout(parsed)) {
    const handle = pathHandle("/auth/browser-logout/");
    return handle === null ? null : { kind: "browser-logout", handle, bootstrap: parsed };
  }
  if (flow === "error" && validHostedError(parsed)) {
    return { kind: "error", bootstrap: parsed };
  }
  return null;
}

export function safeNavigationUrl(
  value: string,
  providerNavigation: boolean,
  applicationType: "web" | "native" = "web",
): string | null {
  if (value.length === 0 || value.length > MAX_NAVIGATION_LENGTH) return null;
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
  if (providerNavigation) return target.protocol === "http:" && loopback ? target.href : null;
  if (target.protocol === "http:") return target.href;
  const scheme = target.protocol.slice(0, -1);
  const forbiddenSchemes = new Set([
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
  ]);
  return applicationType === "native" &&
    scheme.includes(".") &&
    !forbiddenSchemes.has(scheme) &&
    target.host === ""
    ? target.href
    : null;
}

function expiredView(
  flow: Extract<
    RuntimeFlow,
    { kind: "interaction" | "browser-logout" | "managed-reauthorization" }
  >,
): ViewState {
  switch (flow.kind) {
    case "interaction":
      return {
        status: "error",
        title: "Sign-in expired",
        message: "Return to your Application and start again.",
      };
    case "browser-logout":
      return {
        status: "error",
        title: "Sign-out request expired",
        message: "Return to your Application and start again.",
      };
    case "managed-reauthorization":
      return {
        status: "error",
        title: "Reauthorization expired",
        message: "Return to the management flow and create a new reauthorization.",
      };
  }
}

function initialView(flow: RuntimeFlow | null): ViewState {
  if (flow === null) {
    if (
      window.location.pathname.includes("/auth/interactions/") ||
      window.location.pathname.includes("/auth/managed-reauthorizations/") ||
      window.location.pathname.includes("/auth/identity-mutations/") ||
      window.location.pathname.includes("/auth/browser-logout/")
    ) {
      return {
        status: "error",
        title: "Request unavailable",
        message: "Return to your Application and start again.",
      };
    }
    return { status: "idle" };
  }
  if (flow.kind === "error") {
    return { status: "error", title: flow.bootstrap.title, message: flow.bootstrap.message };
  }
  if (flow.kind === "email-magic") {
    return { status: "ready-magic", challengeId: flow.challengeId, context: flow.context };
  }
  if (flow.kind === "identity-mutation") {
    return {
      status: "identity-mutation",
      handle: flow.handle,
      bootstrap:
        Date.parse(flow.bootstrap.expires_at) <= Date.now()
          ? { ...flow.bootstrap, status: "expired" }
          : flow.bootstrap,
    };
  }
  if (flow.kind === "identity-mutation-magic") {
    return { status: "identity-mutation-magic", bootstrap: flow.bootstrap };
  }
  if (Date.parse(flow.bootstrap.expires_at) <= Date.now()) {
    return expiredView(flow);
  }
  if (flow.kind === "browser-logout") {
    return { status: "ready-logout", handle: flow.handle, bootstrap: flow.bootstrap };
  }
  if (flow.kind === "managed-reauthorization") {
    switch (flow.bootstrap.status) {
      case "awaiting_provider_start":
        return {
          status: "ready-managed-reauthorization",
          handle: flow.handle,
          bootstrap: flow.bootstrap,
        };
      case "provider_authorization_started":
      case "provider_exchange_in_progress":
        return {
          status: "progress",
          title: "Reauthorization is in progress",
          message: "Do not submit this interaction again.",
        };
      case "completed":
        return {
          status: "complete",
          title: "Connection reauthorized",
          message: "You can close this page and return to the Console.",
        };
      default:
        return {
          status: "error",
          title: "Reauthorization unavailable",
          message: "Ask the operator to create a new managed reauthorization interaction.",
        };
    }
  }
  switch (flow.bootstrap.status) {
    case "awaiting_method_selection":
      return { status: "ready-interaction", handle: flow.handle, bootstrap: flow.bootstrap };
    case "email_address_entry":
      return { status: "email-entry", handle: flow.handle, bootstrap: flow.bootstrap };
    case "email_challenge_pending":
      return {
        status: "error",
        title: "Check your email",
        message: "Use the newest code or link. If this page was reloaded, restart sign-in safely.",
      };
    case "provider_authorization_started":
    case "provider_exchange_in_progress":
    case "authenticated":
      return {
        status: "progress",
        title: "Completing sign-in",
        message: "Authentication is in progress. Do not submit the interaction again.",
      };
    case "handoff_issued":
    case "completed":
      return {
        status: "complete",
        title: "Sign-in completed",
        message: "Return to your Application to continue.",
      };
    case "failed":
      return {
        status: "error",
        title: "Sign-in could not be completed",
        message: "Return to your Application and start sign-in again.",
      };
    case "expired":
      return {
        status: "error",
        title: "Sign-in expired",
        message: "Return to your Application and start sign-in again.",
      };
    default:
      return {
        status: "error",
        title: "Sign-in could not be displayed",
        message: "Return to your Application and start sign-in again.",
      };
  }
}

function TerminalView({
  state,
}: {
  readonly state: Extract<ViewState, { status: "error" | "complete" | "progress" }>;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus();
  }, []);
  return (
    <section aria-labelledby="runtime-result" aria-live="polite">
      <h2 id="runtime-result" ref={heading} tabIndex={-1} className={styles["focusTarget"]}>
        {state.title}
      </h2>
      <p
        role={state.status === "error" ? "alert" : "status"}
        className={state.status === "error" ? styles["error"] : undefined}
      >
        {state.message}
      </p>
    </section>
  );
}

export function RuntimeApp() {
  const [state, setState] = useState<ViewState>(() => initialView(consumeRuntimeFlow()));
  const [emailAddress, setEmailAddress] = useState("");
  const [otp, setOtp] = useState("");
  const [otpError, setOtpError] = useState<string | null>(null);
  const activeRequest = useRef<AbortController | null>(null);

  useEffect(
    () => () => {
      activeRequest.current?.abort();
      activeRequest.current = null;
    },
    [],
  );

  async function selectProvider(provider: HostedProvider) {
    if (state.status !== "ready-interaction") return;
    const { bootstrap, handle } = state;
    const controller = new AbortController();
    activeRequest.current?.abort();
    activeRequest.current = controller;
    setState({
      status: "submitting",
      title: "Connecting to your identity provider",
      message: `Continuing with ${provider.display_name}.`,
    });
    try {
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        "/v1/projects/{project_public_id}/auth/interactions/{interaction}/method",
        {
          params: { path: { project_public_id: bootstrap.project_id, interaction: handle } },
          body: {
            csrf: bootstrap.csrf,
            expected_revision: bootstrap.revision,
            provider_key: provider.key,
          },
          signal: controller.signal,
        },
      );
      if (controller.signal.aborted) return;
      const target = data === undefined ? null : safeNavigationUrl(data.url, true);
      if (!response.ok || target === null) {
        setState({
          status: "error",
          title: "Sign-in could not be started",
          message: "Return to your Application and start sign-in again.",
        });
        return;
      }
      hostedNavigation.replace(target);
    } catch {
      if (!controller.signal.aborted) {
        setState({
          status: "error",
          title: "Sign-in status is uncertain",
          message:
            "Do not submit this interaction again. Return to your Application and start sign-in again.",
        });
      }
    } finally {
      if (activeRequest.current === controller) activeRequest.current = null;
    }
  }

  async function selectEmail() {
    if (state.status !== "ready-interaction") return;
    const { bootstrap, handle } = state;
    setState({ status: "submitting", title: "Preparing email sign-in", message: "Please wait." });
    try {
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/select",
        {
          params: { path: { project_public_id: bootstrap.project_id, interaction: handle } },
          body: { csrf: bootstrap.csrf, expected_revision: bootstrap.revision },
        },
      );
      if (!response.ok || data?.completed !== true) throw new Error("selection rejected");
      setState({
        status: "email-entry",
        handle,
        bootstrap: {
          ...bootstrap,
          revision: bootstrap.revision + 1,
          status: "email_address_entry",
        },
      });
    } catch {
      setState({
        status: "error",
        title: "Email sign-in unavailable",
        message: "Return to your Application and start again.",
      });
    }
  }

  async function sendEmailChallenge(resend = false) {
    if (state.status !== "email-entry" && state.status !== "email-proof") return;
    const { bootstrap, handle } = state;
    const address = emailAddress;
    if (!/^\S{1,64}@\S{3,253}$/u.test(address) || address.length > 254) return;
    setState({
      status: "submitting",
      title: resend ? "Sending a new code" : "Sending your sign-in email",
      message: "Please wait.",
    });
    setEmailAddress("");
    try {
      const path = resend
        ? "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/resend"
        : "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/challenges";
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        path,
        {
          params: { path: { project_public_id: bootstrap.project_id, interaction: handle } },
          body: { csrf: bootstrap.csrf, expected_revision: bootstrap.revision, email: address },
        },
      );
      if (!response.ok || data?.accepted !== true || !validProofModes(data.proof_modes, false)) {
        throw new Error("challenge rejected");
      }
      setOtpError(null);
      setState({
        status: "email-proof",
        handle,
        bootstrap: { ...bootstrap, revision: data.revision, status: "email_challenge_pending" },
        challengeId: data.challenge_id,
        generation: data.generation,
        proofModes: data.proof_modes,
        expiresAt: data.expires_at,
      });
    } catch {
      setState({
        status: "error",
        title: "Email could not be sent",
        message: "Return to your Application and start again.",
      });
    }
  }

  async function verifyOtp() {
    if (
      state.status !== "email-proof" ||
      !state.proofModes.includes("otp") ||
      !/^\d{6,10}$/u.test(otp)
    ) {
      return;
    }
    const proofState = state;
    const { bootstrap, handle, challengeId, generation } = proofState;
    const submittedOtp = otp;
    setOtp("");
    setOtpError(null);
    setState({ status: "submitting", title: "Checking your code", message: "Please wait." });
    try {
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/otp/verify",
        {
          params: { path: { project_public_id: bootstrap.project_id, interaction: handle } },
          body: {
            csrf: bootstrap.csrf,
            expected_revision: bootstrap.revision,
            challenge_id: challengeId,
            generation,
            otp: submittedOtp,
          },
        },
      );
      if (
        !response.ok ||
        data?.completed !== true ||
        data.redirect_url === null ||
        data.redirect_url === undefined ||
        data.application_type !== bootstrap.application_type
      ) {
        setState(proofState);
        setOtpError("Use the newest code, or return to your Application and restart.");
        return;
      }
      const target = safeNavigationUrl(data.redirect_url, false, data.application_type);
      if (target === null) throw new Error("unsafe navigation");
      hostedNavigation.replace(target);
    } catch {
      setState({
        status: "error",
        title: "Sign-in status is uncertain",
        message: "Return to your Application before trying again.",
      });
    }
  }

  async function confirmMagic() {
    if (state.status !== "ready-magic" || state.context === null) return;
    const { challengeId, context } = state;
    setState({ status: "submitting", title: "Confirming email sign-in", message: "Please wait." });
    try {
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        "/v1/projects/{project_public_id}/auth/email/magic/confirm",
        {
          params: {
            path: { project_public_id: context.project },
          },
          body: {
            csrf: context.csrf,
            expected_revision: context.revision,
            challenge_id: challengeId,
            transaction_id: context.transaction,
            generation: context.generation,
            proof: context.proof,
          },
        },
      );
      if (
        !response.ok ||
        data?.completed !== true ||
        data.redirect_url === null ||
        data.redirect_url === undefined ||
        (data.application_type !== "web" && data.application_type !== "native")
      ) {
        setState({
          status: "error",
          title: "Link invalid or expired",
          message: "Use the newest link, or restart sign-in from your Application.",
        });
        return;
      }
      const target = safeNavigationUrl(data.redirect_url, false, data.application_type);
      if (target === null) throw new Error("unsafe navigation");
      hostedNavigation.replace(target);
    } catch {
      setState({
        status: "error",
        title: "Sign-in status is uncertain",
        message: "Return to your Application before trying again.",
      });
    }
  }

  async function startManagedReauthorization() {
    if (state.status !== "ready-managed-reauthorization" || state.bootstrap.csrf === undefined) {
      return;
    }
    const csrf = state.bootstrap.csrf;
    const { bootstrap, handle } = state;
    const controller = new AbortController();
    activeRequest.current?.abort();
    activeRequest.current = controller;
    setState({
      status: "submitting",
      title: "Connecting to your identity provider",
      message: `Reauthorizing the fixed ${bootstrap.provider_key} connection.`,
    });
    try {
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        "/v1/projects/{project_public_id}/auth/managed-reauthorizations/{interaction}/start",
        {
          params: {
            path: { project_public_id: bootstrap.project_public_id, interaction: handle },
          },
          body: { csrf, expected_revision: bootstrap.revision },
          signal: controller.signal,
        },
      );
      if (controller.signal.aborted) return;
      const target = data === undefined ? null : safeNavigationUrl(data.url, true);
      if (!response.ok || target === null) {
        setState({
          status: "error",
          title: "Reauthorization could not be started",
          message: "Ask the operator to create a new managed reauthorization interaction.",
        });
        return;
      }
      hostedNavigation.replace(target);
    } catch {
      if (!controller.signal.aborted) {
        setState({
          status: "error",
          title: "Reauthorization status is uncertain",
          message: "Do not submit this interaction again. Ask the operator to inspect it.",
        });
      }
    } finally {
      if (activeRequest.current === controller) activeRequest.current = null;
    }
  }

  async function reuseSession() {
    if (state.status !== "ready-interaction") return;
    const { bootstrap, handle } = state;
    const controller = new AbortController();
    activeRequest.current?.abort();
    activeRequest.current = controller;
    setState({ status: "submitting", title: "Confirming your session", message: "Please wait." });
    try {
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        "/v1/projects/{project_public_id}/auth/interactions/{interaction}/session/reuse",
        {
          params: { path: { project_public_id: bootstrap.project_id, interaction: handle } },
          body: { csrf: bootstrap.csrf, expected_revision: bootstrap.revision },
          signal: controller.signal,
        },
      );
      if (controller.signal.aborted) return;
      const target =
        data === undefined ? null : safeNavigationUrl(data.url, false, bootstrap.application_type);
      if (!response.ok || target === null) {
        setState({
          status: "error",
          title: "Session could not be reused",
          message: "Return to your Application and start sign-in again.",
        });
        return;
      }
      hostedNavigation.replace(target);
    } catch {
      if (!controller.signal.aborted) {
        setState({
          status: "error",
          title: "Sign-in status is uncertain",
          message:
            "Do not submit this interaction again. Return to your Application and start sign-in again.",
        });
      }
    } finally {
      if (activeRequest.current === controller) activeRequest.current = null;
    }
  }

  async function confirmLogout() {
    if (state.status !== "ready-logout") return;
    const { bootstrap, handle } = state;
    const controller = new AbortController();
    activeRequest.current?.abort();
    activeRequest.current = controller;
    setState({ status: "submitting", title: "Signing out", message: "Please wait." });
    try {
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        "/v1/projects/{project_public_id}/auth/browser-logout/{preparation}/confirm",
        {
          params: { path: { project_public_id: bootstrap.project_id, preparation: handle } },
          body: { csrf: bootstrap.csrf, expected_revision: bootstrap.revision },
          signal: controller.signal,
        },
      );
      if (controller.signal.aborted) return;
      if (!response.ok || data?.completed !== true) {
        setState({
          status: "error",
          title: "Sign-out could not be confirmed",
          message: "Close this page and return to your Application.",
        });
        return;
      }
      setState({
        status: "complete",
        title: "Signed out",
        message: "Your Project browser session has ended. You can close this page.",
      });
    } catch {
      if (!controller.signal.aborted) {
        setState({
          status: "error",
          title: "Sign-out status is uncertain",
          message: "Close this page and return to your Application before signing in again.",
        });
      }
    } finally {
      if (activeRequest.current === controller) activeRequest.current = null;
    }
  }

  const title =
    state.status === "ready-interaction" ||
    state.status === "email-entry" ||
    state.status === "email-proof"
      ? state.bootstrap.application_display_name
      : state.status === "ready-magic"
        ? "Confirm email sign-in"
        : state.status === "identity-mutation" || state.status === "identity-mutation-magic"
          ? "Identity verification"
          : state.status === "ready-managed-reauthorization"
            ? "Reauthorize managed connection"
            : state.status === "ready-logout"
              ? "Sign out"
              : state.status === "submitting"
                ? state.title
                : "Hosted authentication";

  return (
    <Shell eyebrow="OwlAuth Runtime" title={title}>
      {state.status === "identity-mutation" ? (
        <IdentityMutationFlow handle={state.handle} bootstrap={state.bootstrap} />
      ) : state.status === "identity-mutation-magic" ? (
        <IdentityMutationMagicFlow bootstrap={state.bootstrap} />
      ) : state.status === "ready-interaction" ? (
        <section aria-labelledby="runtime-project" aria-busy="false">
          <h2 id="runtime-project">{state.bootstrap.project_display_name}</h2>
          <p className={styles["summary"]}>
            Choose a sign-in method for {state.bootstrap.application_display_name}.
          </p>
          {state.bootstrap.presentation_hint === undefined ||
          state.bootstrap.presentation_hint === null ? null : (
            <p className={styles["notice"]}>{state.bootstrap.presentation_hint}</p>
          )}
          <div className={styles["methods"]} role="group" aria-label="Sign-in methods">
            {state.bootstrap.email_available ? (
              <button className={styles["method"]} type="button" onClick={() => void selectEmail()}>
                Continue with email
              </button>
            ) : null}
            {state.bootstrap.providers.map((provider) => (
              <button
                className={styles["method"]}
                type="button"
                key={provider.key}
                onClick={() => void selectProvider(provider)}
              >
                Continue with {provider.display_name}
              </button>
            ))}
          </div>
          {state.bootstrap.session_reuse_available ? (
            <>
              <hr className={styles["divider"]} />
              <section aria-labelledby="reuse-session">
                <h3 id="reuse-session">Continue with your current Project session</h3>
                <p>This is a separate confirmation and will not select an identity provider.</p>
                <button
                  className={styles["secondary"]}
                  type="button"
                  onClick={() => void reuseSession()}
                >
                  Continue with current session
                </button>
              </section>
            </>
          ) : null}
        </section>
      ) : state.status === "email-entry" ? (
        <section aria-labelledby="email-entry-title">
          <h2 id="email-entry-title">Enter your email address</h2>
          <p className={styles["summary"]}>
            We will respond the same way whether or not an account already exists.
          </p>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void sendEmailChallenge();
            }}
          >
            <label htmlFor="email-address">Email address</label>
            <input
              id="email-address"
              name="email"
              type="email"
              autoComplete="email"
              required
              maxLength={254}
              value={emailAddress}
              onChange={(event) => {
                setEmailAddress(event.target.value);
              }}
            />
            <button className={styles["method"]} type="submit">
              Send sign-in email
            </button>
          </form>
        </section>
      ) : state.status === "email-proof" ? (
        <section aria-labelledby="email-proof-title" aria-live="polite">
          <h2 id="email-proof-title">Check your email</h2>
          <p role="status">
            {state.proofModes.length === 2
              ? "Use the newest code or open the newest sign-in link. "
              : state.proofModes.includes("otp")
                ? "Use the newest code. "
                : "Open the newest sign-in link. "}
            This challenge expires at {new Date(state.expiresAt).toLocaleTimeString()}.
          </p>
          {otpError === null ? null : (
            <div role="alert" className={styles["error"]}>
              <h3>Code invalid or expired</h3>
              <p>{otpError}</p>
            </div>
          )}
          {state.proofModes.includes("otp") ? (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void verifyOtp();
              }}
            >
              <label htmlFor="email-otp">One-time code</label>
              <input
                id="email-otp"
                name="otp"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6,10}"
                minLength={6}
                maxLength={10}
                required
                value={otp}
                onChange={(event) => {
                  setOtp(event.target.value.replace(/\D/gu, "").slice(0, 10));
                }}
              />
              <button className={styles["method"]} type="submit">
                Verify code
              </button>
            </form>
          ) : null}
          <p>Need another message? Enter the same email address and request a new generation.</p>
          <label htmlFor="resend-email">Email address</label>
          <input
            id="resend-email"
            type="email"
            autoComplete="email"
            maxLength={254}
            value={emailAddress}
            onChange={(event) => {
              setEmailAddress(event.target.value);
            }}
          />
          <button
            className={styles["secondary"]}
            type="button"
            onClick={() => void sendEmailChallenge(true)}
          >
            Resend
          </button>
        </section>
      ) : state.status === "ready-magic" ? (
        <section aria-labelledby="magic-confirm-title">
          <h2 id="magic-confirm-title">Continue email sign-in</h2>
          {state.context === null ? (
            <p role="alert" className={styles["error"]}>
              This link is invalid or expired. Return to the browser where sign-in started.
            </p>
          ) : (
            <>
              <p role="status">
                The link has been removed from browser history. Continue only if you requested this
                sign-in.
              </p>
              <button
                className={styles["method"]}
                type="button"
                onClick={() => void confirmMagic()}
              >
                Continue
              </button>
            </>
          )}
        </section>
      ) : state.status === "ready-managed-reauthorization" ? (
        <section aria-labelledby="managed-reauthorization">
          <h2 id="managed-reauthorization">Confirm provider credential replacement</h2>
          <p>
            Continue only with the fixed {state.bootstrap.provider_key} provider. This action
            replaces one managed credential generation and does not sign you in to an Application.
          </p>
          <button
            className={styles["method"]}
            type="button"
            onClick={() => void startManagedReauthorization()}
          >
            Continue with {state.bootstrap.provider_key}
          </button>
        </section>
      ) : state.status === "ready-logout" ? (
        <section aria-labelledby="confirm-sign-out">
          <h2 id="confirm-sign-out">Sign out of this Project?</h2>
          <p>This ends the Project browser session and sessions derived from it.</p>
          <div className={styles["actions"]}>
            <button className={styles["danger"]} type="button" onClick={() => void confirmLogout()}>
              Confirm sign out
            </button>
            <button
              className={styles["secondary"]}
              type="button"
              onClick={() => {
                setState({
                  status: "complete",
                  title: "Sign-out cancelled",
                  message: "No changes were made. You can close this page.",
                });
              }}
            >
              Cancel
            </button>
          </div>
        </section>
      ) : state.status === "submitting" ? (
        <section aria-busy="true">
          <h2>{state.title}</h2>
          <p role="status">{state.message}</p>
        </section>
      ) : state.status === "error" || state.status === "complete" || state.status === "progress" ? (
        <TerminalView state={state} />
      ) : (
        <p>No authentication interaction is active. Start sign-in from an OwlAuth Application.</p>
      )}
    </Shell>
  );
}
