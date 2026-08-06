import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router";

import { EmptyState, PageHeader } from "../../shared/layout/Layout";
import { useControl, useProject } from "../app/ControlContext";
import { type Application, type Provider, requireData } from "../client";
import { UserManagement } from "../features/UserManagement";
import styles from "./pages.module.css";

export function UserDetailPage() {
  const { projectId, userId } = useParams();
  const project = useProject(projectId);
  const { session, handleError, setMessage } = useControl();
  const [applications, setApplications] = useState<Application[]>([]);
  const [providers, setProviders] = useState<Provider[]>([]);

  const refreshDependencies = useCallback(
    async (signal?: AbortSignal) => {
      if (project === null) return;
      const [applicationResult, providerResult] = await Promise.all([
        session.client.GET("/v1/projects/{project_id}/applications", {
          params: { path: { project_id: project.id } },
          signal: signal ?? null,
        }),
        session.client.GET("/v1/projects/{project_id}/providers", {
          params: { path: { project_id: project.id } },
          signal: signal ?? null,
        }),
      ]);
      if (signal?.aborted !== true) {
        setApplications(
          requireData(applicationResult.data, applicationResult.error, applicationResult.response)
            .items,
        );
        setProviders(
          requireData(providerResult.data, providerResult.error, providerResult.response).items,
        );
      }
    },
    [project, session],
  );

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      void refreshDependencies(controller.signal).catch((error: unknown) => {
        if (!controller.signal.aborted) void handleError(error);
      });
    }, 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [handleError, refreshDependencies]);

  if (project === null || userId === undefined) {
    return (
      <EmptyState
        level={1}
        title={project === null ? "Project not found" : "User not found"}
        description="Return to the Project user inventory and select an existing user."
        action={
          <Link to={project === null ? "/" : `/projects/${project.id}/users`}>Return to users</Link>
        }
      />
    );
  }

  return (
    <div className={styles["page"]}>
      <PageHeader
        title="User detail"
        description="Review this user's provenance, sessions, managed connections, and exact identity operations."
        actions={<Link to={`/projects/${project.id}/users`}>Back to users</Link>}
      />
      <UserManagement
        session={session}
        project={project}
        applications={applications}
        providers={providers}
        initialUserId={userId}
        detailOnly
        onError={handleError}
        setMessage={(message) => {
          setMessage(message, "success");
        }}
      />
    </div>
  );
}
