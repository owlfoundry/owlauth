import { useEffect, useRef, useState } from "react";

import type { components } from "../generated/runtime-openapi";
import { readConfiguredBase } from "../shared/configured-base";
import { Shell } from "../shared/Shell";
import styles from "./app.module.css";
import { createRuntimeClient } from "./client";

type HostedInteraction = components["schemas"]["HostedInteractionResponse"];
type HostedProvider = components["schemas"]["HostedProvider"];
type BrowserLogout = components["schemas"]["BrowserLogoutResponse"];
interface SafeHostedError {
  title: string;
  message: string;
}
type RuntimeFlow =
  | { kind: "interaction"; handle: string; bootstrap: HostedInteraction }
  | { kind: "browser-logout"; handle: string; bootstrap: BrowserLogout }
  | { kind: "error"; bootstrap: SafeHostedError };
type ViewState =
  | { status: "ready-interaction"; handle: string; bootstrap: HostedInteraction }
  | { status: "ready-logout"; handle: string; bootstrap: BrowserLogout }
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

function validProvider(value: unknown): value is HostedProvider {
  if (typeof value !== "object" || value === null) return false;
  const provider = value as Record<string, unknown>;
  return boundedString(provider["key"], 64) && boundedString(provider["display_name"], 128);
}

function validInteraction(value: unknown): value is HostedInteraction {
  if (typeof value !== "object" || value === null) return false;
  const interaction = value as Record<string, unknown>;
  const providers = interaction["providers"];
  if (!Array.isArray(providers) || providers.length === 0 || providers.length > 50) return false;
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
    (interaction["presentation_hint"] === null ||
      interaction["presentation_hint"] === undefined ||
      boundedString(interaction["presentation_hint"], 64)) &&
    boundedString(interaction["status"], 64) &&
    INTERACTION_STATUSES.has(interaction["status"])
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
  const flow = flowElement?.content;
  const serialized = bootstrapElement?.content;
  flowElement?.remove();
  bootstrapElement?.remove();
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

function initialView(flow: RuntimeFlow | null): ViewState {
  if (flow === null) {
    if (
      window.location.pathname.includes("/auth/interactions/") ||
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
  if (Date.parse(flow.bootstrap.expires_at) <= Date.now()) {
    return {
      status: "error",
      title: flow.kind === "interaction" ? "Sign-in expired" : "Sign-out request expired",
      message: "Return to your Application and start again.",
    };
  }
  if (flow.kind === "browser-logout") {
    return { status: "ready-logout", handle: flow.handle, bootstrap: flow.bootstrap };
  }
  switch (flow.bootstrap.status) {
    case "awaiting_method_selection":
      return { status: "ready-interaction", handle: flow.handle, bootstrap: flow.bootstrap };
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
      window.location.replace(target);
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
      window.location.replace(target);
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
    state.status === "ready-interaction"
      ? state.bootstrap.application_display_name
      : state.status === "ready-logout"
        ? "Sign out"
        : state.status === "submitting"
          ? state.title
          : "Hosted authentication";

  return (
    <Shell eyebrow="OwlAuth Runtime" title={title}>
      {state.status === "ready-interaction" ? (
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
