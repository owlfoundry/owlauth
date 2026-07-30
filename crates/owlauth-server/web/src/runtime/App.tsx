import { useEffect, useState } from "react";

import type { components } from "../generated/runtime-openapi";
import { readConfiguredBase } from "../shared/configured-base";
import { Shell } from "../shared/Shell";
import { createRuntimeClient } from "./client";

type PublicConfig = components["schemas"]["PublicApplicationConfig"];
type LoadState =
  | { status: "idle" | "loading" | "missing" | "failed" }
  | {
      status: "ready";
      config: PublicConfig;
    };

export function RuntimeApp() {
  const initialParameters = new URLSearchParams(window.location.search);
  const hasPublicTarget =
    initialParameters.has("project_id") && initialParameters.has("application_id");
  const [state, setState] = useState<LoadState>(
    hasPublicTarget ? { status: "loading" } : { status: "idle" },
  );

  useEffect(() => {
    const parameters = new URLSearchParams(window.location.search);
    const projectId = parameters.get("project_id");
    const applicationId = parameters.get("application_id");
    if (projectId === null || applicationId === null) return;
    const controller = new AbortController();
    void createRuntimeClient(readConfiguredBase("runtime"))
      .GET("/v1/projects/{project_public_id}/auth/config", {
        params: {
          path: { project_public_id: projectId },
          query: { application_id: applicationId },
        },
        signal: controller.signal,
      })
      .then(({ data, response }) => {
        if (controller.signal.aborted) return;
        if (response.status === 404) {
          setState({ status: "missing" });
        } else if (data === undefined || !response.ok) {
          setState({ status: "failed" });
        } else {
          setState({ status: "ready", config: data });
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) setState({ status: "failed" });
      });
    return () => {
      controller.abort();
    };
  }, []);

  return (
    <Shell
      eyebrow="OwlAuth Runtime"
      title={
        state.status === "ready" ? state.config.application_display_name : "Hosted authentication"
      }
    >
      {state.status === "ready" ? (
        <section aria-labelledby="runtime-project">
          <h2 id="runtime-project">{state.config.project_display_name}</h2>
          {state.config.providers.length === 0 ? (
            <p>No login methods are configured.</p>
          ) : (
            <p>
              Configured methods:{" "}
              {state.config.providers.map((provider) => provider.display_name).join(", ")}.
            </p>
          )}
          <p>Login is not available in this release block.</p>
        </section>
      ) : state.status === "loading" ? (
        <p role="status">Loading public application configuration…</p>
      ) : state.status === "missing" ? (
        <p>The requested public Application was not found.</p>
      ) : state.status === "failed" ? (
        <p>Public application configuration is temporarily unavailable.</p>
      ) : null}
      <p>No authentication interaction is active. Start sign-in from an OwlAuth Application.</p>
    </Shell>
  );
}
