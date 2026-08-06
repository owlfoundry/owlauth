import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router";

import { EmptyState, PageHeader } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert } from "../../shared/primitives/Feedback";
import { useControl, useProject } from "../app/ControlContext";
import { type Application, requireData } from "../client";
import { EmailSettings } from "../features/EmailSettings";
import styles from "./pages.module.css";

export function EmailPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, refreshProjects, handleError, setMessage } = useControl();
  const [applications, setApplications] = useState<Application[]>([]);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "failed">("loading");

  const refreshApplications = useCallback(
    async (signal?: AbortSignal) => {
      if (project === null) return;
      const result = await session.client.GET("/v1/projects/{project_id}/applications", {
        params: { path: { project_id: project.id } },
        signal: signal ?? null,
      });
      if (signal?.aborted !== true) {
        setApplications(requireData(result.data, result.error, result.response).items);
      }
    },
    [project, session],
  );

  const loadApplications = useCallback(
    async (signal?: AbortSignal) => {
      setLoadState("loading");
      try {
        await refreshApplications(signal);
        if (signal?.aborted !== true) setLoadState("ready");
      } catch (error) {
        if (signal?.aborted !== true) setLoadState("failed");
        throw error;
      }
    },
    [refreshApplications],
  );

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      void loadApplications(controller.signal).catch((error: unknown) => {
        if (!controller.signal.aborted) void handleError(error);
      });
    }, 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [handleError, loadApplications]);

  if (project === null) {
    return (
      <EmptyState
        level={1}
        title="Project not found"
        description="Select an existing Project before configuring passwordless email."
        action={<Link to="/">Return to Projects</Link>}
      />
    );
  }

  return (
    <div className={styles["page"]}>
      <PageHeader
        title="Passwordless email"
        description="Configure proof modes, Application assignments, and SMTP generations."
      />
      {loadState === "loading" ? <p role="status">Loading Applications</p> : null}
      {loadState === "failed" ? (
        <InlineAlert tone="danger" role="alert">
          <p>Applications required for email assignments could not be loaded.</p>
          <Button type="button" onClick={() => void loadApplications().catch(handleError)}>
            Retry Applications
          </Button>
        </InlineAlert>
      ) : null}
      {loadState === "ready" ? (
        <EmailSettings
          session={session}
          project={project}
          applications={applications}
          onApplicationsChanged={refreshApplications}
          onProjectChanged={async () => {
            await refreshProjects();
          }}
          onError={handleError}
          setMessage={(message) => {
            setMessage(message, "success");
          }}
        />
      ) : null}
    </div>
  );
}
