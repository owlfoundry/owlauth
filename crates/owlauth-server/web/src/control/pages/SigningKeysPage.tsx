import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
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
  const [inventoryProjectId, setInventoryProjectId] = useState<string | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "failed">("loading");
  const requestGeneration = useRef(0);
  const currentProjectId = project?.id ?? null;
  const currentProjectIdRef = useRef(currentProjectId);
  useLayoutEffect(() => {
    currentProjectIdRef.current = currentProjectId;
    return () => {
      currentProjectIdRef.current = null;
    };
  }, [currentProjectId]);

  const refresh = useCallback(
    async (showLoading = true, signal?: AbortSignal) => {
      if (project === null) return;
      const requestedProjectId = project.id;
      if (currentProjectIdRef.current !== requestedProjectId) return;
      const generation = requestGeneration.current + 1;
      requestGeneration.current = generation;
      if (showLoading) {
        setInventoryProjectId(requestedProjectId);
        setLoadState("loading");
      }
      try {
        const result = await session.client.GET("/v1/projects/{project_id}/signing-keys", {
          params: { path: { project_id: project.id } },
          signal: signal ?? null,
        });
        const items = requireData(result.data, result.error, result.response).items;
        if (
          signal?.aborted === true ||
          generation !== requestGeneration.current ||
          currentProjectIdRef.current !== requestedProjectId
        )
          return;
        setKeys(items);
        setInventoryProjectId(requestedProjectId);
        setLoadState("ready");
      } catch (error) {
        if (
          signal?.aborted === true ||
          generation !== requestGeneration.current ||
          currentProjectIdRef.current !== requestedProjectId
        )
          return;
        setInventoryProjectId(requestedProjectId);
        setLoadState("failed");
        throw error;
      }
    },
    [project, session],
  );

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      void refresh(true, controller.signal).catch((error: unknown) => {
        if (!controller.signal.aborted) void handleError(error);
      });
    }, 0);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [handleError, refresh]);

  const visibleLoadState =
    project !== null && inventoryProjectId === project.id ? loadState : "loading";
  const maintenancePending =
    visibleLoadState === "ready" &&
    (keys.length === 0 ||
      keys.some((key) => ["provisioning", "published", "retiring"].includes(key.state)));
  useEffect(() => {
    if (!maintenancePending) return;
    let cancelled = false;
    let timer: number | undefined;
    const controller = new AbortController();
    const poll = async () => {
      try {
        await refresh(false, controller.signal);
      } catch (error) {
        if (!cancelled && !controller.signal.aborted) await handleError(error);
        return;
      }
      if (!cancelled && !controller.signal.aborted) {
        timer = window.setTimeout(() => {
          void poll();
        }, 500);
      }
    };
    timer = window.setTimeout(() => {
      void poll();
    }, 500);
    return () => {
      cancelled = true;
      controller.abort();
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [handleError, maintenancePending, refresh]);

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
        description="Review automatically managed Project signing authority and request rotations."
      />
      {visibleLoadState === "loading" ? <p role="status">Loading signing keys</p> : null}
      {visibleLoadState === "failed" ? (
        <InlineAlert tone="danger" role="alert">
          <p>The signing-key inventory could not be loaded.</p>
          <Button type="button" onClick={() => void refresh().catch(handleError)}>
            Retry signing keys
          </Button>
        </InlineAlert>
      ) : null}
      {visibleLoadState === "ready" ? (
        <SigningKeyManagement
          session={session}
          project={project}
          keys={keys}
          onChanged={refresh}
          onError={(error) =>
            currentProjectIdRef.current === project.id
              ? handleError(error, refresh)
              : Promise.resolve()
          }
          setMessage={(message) => {
            if (currentProjectIdRef.current === project.id) setMessage(message, "success");
          }}
        />
      ) : null}
    </div>
  );
}
