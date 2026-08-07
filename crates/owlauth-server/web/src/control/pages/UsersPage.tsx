import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { EmptyState, PageHeader } from "../../shared/layout/Layout";
import { useControl, useProject } from "../app/ControlContext";
import { type Provider, requireData } from "../client";
import { UserManagement } from "../features/UserManagement";
import styles from "./pages.module.css";

export function UsersPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, handleError, setMessage } = useControl();
  const navigate = useNavigate();
  const [providerInventory, setProviderInventory] = useState<{
    projectId: string;
    items: Provider[];
  } | null>(null);
  const providers =
    project !== null && providerInventory?.projectId === project.id ? providerInventory.items : [];

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      if (project === null) return;
      void session.client
        .GET("/v1/projects/{project_id}/providers", {
          params: { path: { project_id: project.id } },
          signal: controller.signal,
        })
        .then((result) => {
          if (!controller.signal.aborted) {
            setProviderInventory({
              projectId: project.id,
              items: requireData(result.data, result.error, result.response).items,
            });
          }
        })
        .catch((error: unknown) => {
          if (!controller.signal.aborted) void handleError(error);
        });
    }, 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [handleError, project, session]);

  if (project === null) {
    return (
      <EmptyState
        level={1}
        title="Project not found"
        description="Select an existing Project before reviewing users."
        action={<Link to="/">Return to Projects</Link>}
      />
    );
  }

  return (
    <div className={styles["page"]}>
      <PageHeader
        title="Users"
        description="Select a bounded Project user to inspect on its dedicated authority page."
      />
      <UserManagement
        session={session}
        project={project}
        providers={providers}
        onUserSelected={(selectedUserId) => {
          void navigate(`/projects/${project.id}/users/${selectedUserId}`);
        }}
        onError={handleError}
        setMessage={(message) => {
          setMessage(message, "success");
        }}
      />
    </div>
  );
}
