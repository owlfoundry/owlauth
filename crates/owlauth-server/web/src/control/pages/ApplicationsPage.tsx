import { useCallback, useEffect, useRef, useState } from "react";
import type { SyntheticEvent } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { DataTable, EmptyState, PageHeader } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Field, Input, Select } from "../../shared/primitives/Field";
import { Dialog } from "../../shared/primitives/Overlay";
import { useControl, useProject } from "../app/ControlContext";
import { UnsavedChangesGuard } from "../app/UnsavedChangesGuard";
import { type Application, ControlRequestError, IdempotencyAttempt, requireData } from "../client";
import styles from "./pages.module.css";

export function ApplicationsPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, handleError, setMessage } = useControl();
  const [applications, setApplications] = useState<Application[]>([]);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "failed">("loading");
  const [creating, setCreating] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createType, setCreateType] = useState<"web" | "native">("web");
  const [createError, setCreateError] = useState<string | null>(null);
  const [createdApplicationId, setCreatedApplicationId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const attempt = useRef(new IdempotencyAttempt());
  const navigate = useNavigate();

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      if (project === null) return;
      setLoadState("loading");
      try {
        const result = await session.client.GET("/v1/projects/{project_id}/applications", {
          params: { path: { project_id: project.id } },
          signal: signal ?? null,
        });
        if (signal?.aborted !== true) {
          setApplications(requireData(result.data, result.error, result.response).items);
          setLoadState("ready");
        }
      } catch (error) {
        if (signal?.aborted !== true) setLoadState("failed");
        throw error;
      }
    },
    [project, session],
  );

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      void refresh(controller.signal).catch((error: unknown) => {
        if (!controller.signal.aborted) void handleError(error);
      });
    }, 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [handleError, refresh]);

  useEffect(() => {
    if (createdApplicationId === null || project === null) return;
    const timer = window.setTimeout(() => {
      setCreatedApplicationId(null);
      void navigate(`/projects/${project.id}/applications/${createdApplicationId}`);
    }, 0);
    return () => {
      window.clearTimeout(timer);
    };
  }, [createdApplicationId, navigate, project]);

  function discardCreate() {
    attempt.current.abandon();
    setCreating(false);
    setCreateName("");
    setCreateType("web");
    setCreateError(null);
  }

  function closeCreate() {
    if (!submitting) discardCreate();
  }

  async function createApplication(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    const displayName = text(fields, "display_name");
    if (displayName.trim() === "") {
      setCreateError("Display name must include a non-space character.");
      return;
    }
    const idempotencyKey = attempt.current.begin();
    if (idempotencyKey === null) return;
    setCreateError(null);
    setSubmitting(true);
    try {
      const result = await session.client.POST("/v1/projects/{project_id}/applications", {
        params: {
          path: { project_id: project.id },
          header: { "Idempotency-Key": idempotencyKey },
        },
        body: {
          display_name: displayName,
          application_type: text(fields, "application_type") === "native" ? "native" : "web",
        },
      });
      const created = requireData(result.data, result.error, result.response);
      attempt.current.settle();
      setApplications((current) => [
        ...current.filter((application) => application.id !== created.id),
        created,
      ]);
      setCreating(false);
      setCreateName("");
      setCreateType("web");
      setCreateError(null);
      setMessage(`Application “${created.display_name}” created.`, "success");
      setCreatedApplicationId(created.id);
    } catch (error) {
      attempt.current.settle(error);
      setCreateError(
        error instanceof ControlRequestError ? error.message : "Application could not be created.",
      );
      await handleError(error, refresh);
    } finally {
      setSubmitting(false);
    }
  }

  if (project === null) {
    return (
      <EmptyState
        level={1}
        title="Project not found"
        description="Select an existing Project before managing Applications."
        action={<Link to="/">Return to Projects</Link>}
      />
    );
  }

  const createDirty = creating && (createName !== "" || createType !== "web");
  return (
    <div className={styles["page"]}>
      <UnsavedChangesGuard dirty={createDirty} submitting={submitting} onDiscard={discardCreate} />
      <PageHeader
        title="Applications"
        description={`Applications that use ${project.display_name} as their authentication authority.`}
        actions={
          project.status === "active" ? (
            <Button
              type="button"
              variant="primary"
              onClick={() => {
                setCreateError(null);
                setCreating(true);
              }}
            >
              Create Application
            </Button>
          ) : undefined
        }
      />
      {loadState === "loading" ? <p role="status">Loading Applications</p> : null}
      {loadState === "failed" ? (
        <InlineAlert tone="danger" role="alert">
          <p>The Application inventory could not be loaded.</p>
          <Button type="button" onClick={() => void refresh().catch(handleError)}>
            Retry Applications
          </Button>
        </InlineAlert>
      ) : null}
      {loadState === "ready" && applications.length === 0 ? (
        <EmptyState
          title="No Applications"
          description="Create an Application to define exact redirects, origins, and user delivery."
        />
      ) : loadState === "ready" ? (
        <DataTable caption="Applications" headings={["Application", "Type", "Status"]}>
          {applications.map((application) => (
            <tr key={application.id}>
              <td>
                <Link
                  className={styles["resourceLink"]}
                  to={`/projects/${project.id}/applications/${application.id}`}
                >
                  {application.display_name}
                </Link>
                <span className={styles["machineValue"]}>{application.public_id}</span>
              </td>
              <td>{application.application_type}</td>
              <td>
                <StatusBadge status={application.status} />
              </td>
            </tr>
          ))}
        </DataTable>
      ) : null}
      <Dialog
        open={creating}
        title="Create Application"
        onClose={closeCreate}
        actions={
          <>
            <Button type="button" variant="quiet" disabled={submitting} onClick={closeCreate}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" form="create-application" busy={submitting}>
              Create Application
            </Button>
          </>
        }
      >
        {createError === null ? null : (
          <InlineAlert tone="danger" role="alert">
            {createError}
          </InlineAlert>
        )}
        <form
          id="create-application"
          className={styles["form"]}
          onSubmit={(event) => void createApplication(event)}
        >
          <Field label="Display name" htmlFor="application-name">
            <Input
              id="application-name"
              name="display_name"
              required
              maxLength={128}
              value={createName}
              onChange={(event) => {
                setCreateName(event.currentTarget.value);
              }}
              data-owl-initial-focus
            />
          </Field>
          <Field label="Application type" htmlFor="application-type">
            <Select
              id="application-type"
              name="application_type"
              value={createType}
              onChange={(event) => {
                setCreateType(event.currentTarget.value === "native" ? "native" : "web");
              }}
            >
              <option value="web">Web</option>
              <option value="native">Native</option>
            </Select>
          </Field>
        </form>
      </Dialog>
    </div>
  );
}

function text(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}
