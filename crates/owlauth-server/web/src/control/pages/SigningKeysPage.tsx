import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router";

import { EmptyState, PageHeader } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert } from "../../shared/primitives/Feedback";
import { useControl, useProject } from "../app/ControlContext";
import { type SigningKey, requireData } from "../client";
import { SigningKeyManagement } from "../features/SigningKeyManagement";
import styles from "./pages.module.css";

export function SigningKeysPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, handleError, setMessage } = useControl();
  const [keys, setKeys] = useState<SigningKey[]>([]);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "failed">("loading");

  const refresh = useCallback(async () => {
    if (project === null) return;
    setLoadState("loading");
    try {
      const result = await session.client.GET("/v1/projects/{project_id}/signing-keys", {
        params: { path: { project_id: project.id } },
      });
      setKeys(requireData(result.data, result.error, result.response).items);
      setLoadState("ready");
    } catch (error) {
      setLoadState("failed");
      throw error;
    }
  }, [project, session]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void refresh().catch(handleError);
    }, 0);
    return () => {
      window.clearTimeout(timer);
    };
  }, [handleError, refresh]);

  if (project === null) {
    return (
      <EmptyState
        level={1}
        title="Project not found"
        description="Select an existing Project before managing signing keys."
        action={<Link to="/">Return to Projects</Link>}
      />
    );
  }

  return (
    <div className={styles["page"]}>
      <PageHeader
        title="Signing keys"
        description="Provision, activate, rotate, retire, and recover Project signing authority."
      />
      {loadState === "loading" ? <p role="status">Loading signing keys</p> : null}
      {loadState === "failed" ? (
        <InlineAlert tone="danger" role="alert">
          <p>The signing-key inventory could not be loaded.</p>
          <Button type="button" onClick={() => void refresh().catch(handleError)}>
            Retry signing keys
          </Button>
        </InlineAlert>
      ) : null}
      {loadState === "ready" ? (
        <SigningKeyManagement
          session={session}
          project={project}
          keys={keys}
          onChanged={refresh}
          onError={(error) => handleError(error, refresh)}
          setMessage={(message) => {
            setMessage(message, "success");
          }}
        />
      ) : null}
    </div>
  );
}
