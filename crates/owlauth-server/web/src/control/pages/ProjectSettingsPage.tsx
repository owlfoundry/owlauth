import { useCallback, useEffect, useState } from "react";
import type { SyntheticEvent } from "react";
import { flushSync } from "react-dom";
import { Link, useNavigate, useParams } from "react-router";

import { CopyValue, formatDuration } from "../../shared/compositions/CopyValue";
import {
  DescriptionList,
  EmptyState,
  LoadingState,
  PageHeader,
  Section,
} from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Checkbox, Field, Input } from "../../shared/primitives/Field";
import { Dialog } from "../../shared/primitives/Overlay";
import { useControl, useProject } from "../app/ControlContext";
import { UnsavedChangesGuard } from "../app/UnsavedChangesGuard";
import { ControlRequestError, type ProjectPolicy, requireData } from "../client";
import styles from "./pages.module.css";

type LoadState = "loading" | "ready" | "failed";
type LifecycleAction = "disable" | "enable";

export function ProjectSettingsPage() {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const project = useProject(projectId);
  const { session, refreshProjects, upsertProject, handleError, setMessage } = useControl();
  const [policy, setPolicy] = useState<ProjectPolicy | null>(null);
  const [policyLoadState, setPolicyLoadState] = useState<LoadState>("loading");
  const [editingMetadata, setEditingMetadata] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState(false);
  const [lifecycleAction, setLifecycleAction] = useState<LifecycleAction | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteConfirmation, setDeleteConfirmation] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [metadataError, setMetadataError] = useState<string | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [lifecycleError, setLifecycleError] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const refreshPolicy = useCallback(
    async (signal?: AbortSignal) => {
      if (project === null) return;
      setPolicyLoadState("loading");
      try {
        const result = await session.client.GET("/v1/projects/{project_id}/policy", {
          params: { path: { project_id: project.id } },
          signal: signal ?? null,
        });
        if (signal?.aborted !== true) {
          setPolicy(requireData(result.data, result.error, result.response));
          setPolicyLoadState("ready");
        }
      } catch (error) {
        if (signal?.aborted !== true) setPolicyLoadState("failed");
        throw error;
      }
    },
    [project, session],
  );

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      setPolicy(null);
      void refreshPolicy(controller.signal).catch((error: unknown) => {
        if (!controller.signal.aborted) void handleError(error);
      });
    }, 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [handleError, refreshPolicy]);

  async function updateProject(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null) return;
    const fields = new FormData(event.currentTarget);
    setMetadataError(null);
    setSubmitting(true);
    try {
      const result = await session.client.PATCH("/v1/projects/{project_id}", {
        params: { path: { project_id: project.id } },
        body: {
          display_name: text(fields, "display_name"),
          belongs_to: project.belongs_to ?? null,
          expected_metadata_revision: project.metadata_revision,
        },
      });
      requireData(result.data, result.error, result.response);
      await refreshProjects();
      setEditingMetadata(false);
      setMessage("Project metadata updated.", "success");
    } catch (error) {
      const conflict =
        error instanceof ControlRequestError &&
        error.status === 409 &&
        error.code === "revision_conflict";
      if (conflict) setEditingMetadata(false);
      else
        setMetadataError(
          error instanceof ControlRequestError
            ? error.message
            : "Project name could not be updated.",
        );
      await handleError(error, async () => {
        await refreshProjects();
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function updatePolicy(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null || policy === null) return;
    const fields = new FormData(event.currentTarget);
    setPolicyError(null);
    setSubmitting(true);
    try {
      const result = await session.client.PUT("/v1/projects/{project_id}/policy", {
        params: { path: { project_id: project.id } },
        body: {
          access_token_lifetime_seconds: Number(text(fields, "access_token_lifetime_seconds")),
          browser_session_reuse: fields.get("browser_session_reuse") === "on",
          expected_claims_revision: policy.claims_revision,
          expected_session_revision: policy.session_revision,
        },
      });
      setPolicy(requireData(result.data, result.error, result.response));
      setEditingPolicy(false);
      setMessage("Project policy updated.", "success");
    } catch (error) {
      const conflict =
        error instanceof ControlRequestError &&
        error.status === 409 &&
        error.code === "revision_conflict";
      if (conflict) setEditingPolicy(false);
      else
        setPolicyError(
          error instanceof ControlRequestError
            ? error.message
            : "Project policy could not be updated.",
        );
      await handleError(error, async () => {
        await refreshPolicy();
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function transitionProject(action: LifecycleAction) {
    if (project === null) return;
    setLifecycleError(null);
    setSubmitting(true);
    try {
      const result =
        action === "disable"
          ? await session.client.POST("/v1/projects/{project_id}/disable", {
              params: { path: { project_id: project.id } },
              body: { expected_security_revision: project.security_revision },
            })
          : await session.client.POST("/v1/projects/{project_id}/enable", {
              params: { path: { project_id: project.id } },
              body: { expected_security_revision: project.security_revision },
            });
      requireData(result.data, result.error, result.response);
      await refreshProjects();
      setLifecycleAction(null);
      setMessage(action === "disable" ? "Project disabled." : "Project enabled.", "success");
    } catch (error) {
      const conflict =
        error instanceof ControlRequestError &&
        error.status === 409 &&
        error.code === "revision_conflict";
      if (conflict) setLifecycleAction(null);
      else
        setLifecycleError(
          error instanceof ControlRequestError
            ? error.message
            : `Project could not be ${action === "disable" ? "disabled" : "enabled"}.`,
        );
      await handleError(error, async () => {
        await refreshProjects();
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function deleteProject(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (deleteConfirmation !== project?.display_name) return;
    setDeleteError(null);
    setSubmitting(true);
    try {
      const result = await session.client.DELETE("/v1/projects/{project_id}", {
        params: { path: { project_id: project.id } },
        body: {
          expected_security_revision: project.security_revision,
        },
      });
      const deletingProject = requireData(result.data, result.error, result.response);
      setConfirmDelete(false);
      setDeleteConfirmation("");
      flushSync(() => {
        setSubmitting(false);
      });
      upsertProject(deletingProject);
      setMessage("Project deletion accepted.", "success");
      void navigate("/", { replace: true });
    } catch (error) {
      const conflict =
        error instanceof ControlRequestError &&
        error.status === 409 &&
        error.code === "revision_conflict";
      if (conflict) {
        setConfirmDelete(false);
        setDeleteConfirmation("");
      } else {
        setDeleteError(
          error instanceof ControlRequestError
            ? error.message
            : "Project deletion could not be accepted.",
        );
      }
      await handleError(error, async () => {
        await refreshProjects();
      });
    } finally {
      setSubmitting(false);
    }
  }

  if (project === null) {
    return (
      <EmptyState
        level={1}
        title="Project not found"
        description="Select an existing Project before changing settings."
        action={<Link to="/">Return to Projects</Link>}
      />
    );
  }

  const active = project.status === "active";
  return (
    <div className={styles["page"]}>
      <UnsavedChangesGuard
        dirty={editingMetadata || editingPolicy}
        submitting={submitting}
        onDiscard={() => {
          setEditingMetadata(false);
          setEditingPolicy(false);
          setMetadataError(null);
          setPolicyError(null);
        }}
      />
      <PageHeader
        title="Project settings"
        description="Review committed metadata and security policy before entering an edit."
        status={<StatusBadge status={project.status} />}
      />
      {!active ? (
        <InlineAlert tone="warning">
          This Project is disabled. Its committed configuration remains visible, but changes and
          Runtime authentication are blocked until it is enabled.
        </InlineAlert>
      ) : null}
      <Section
        title="Project metadata"
        action={
          active ? (
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                setMetadataError(null);
                setEditingMetadata(true);
              }}
            >
              Edit metadata
            </Button>
          ) : undefined
        }
      >
        <DescriptionList
          items={[
            { term: "Display name", detail: project.display_name },
            {
              term: "Public ID",
              detail: (
                <CopyValue
                  value={project.public_id}
                  label="Project public ID"
                  onCopied={(message) => {
                    setMessage(message, "success");
                  }}
                />
              ),
            },
          ]}
        />
      </Section>
      <Section
        title="Session and token policy"
        action={
          active && policy !== null && policyLoadState === "ready" ? (
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                setPolicyError(null);
                setEditingPolicy(true);
              }}
            >
              Edit policy
            </Button>
          ) : undefined
        }
      >
        {policyLoadState === "failed" ? (
          <InlineAlert tone="danger">
            Project policy could not be loaded. Previously loaded values, if shown, may be stale.{" "}
            <Button
              type="button"
              variant="quiet"
              onClick={() => void refreshPolicy().catch(handleError)}
            >
              Retry Project policy
            </Button>
          </InlineAlert>
        ) : null}
        {policy === null ? (
          policyLoadState === "loading" ? (
            <LoadingState>Loading project policy</LoadingState>
          ) : null
        ) : (
          <DescriptionList
            items={[
              {
                term: "Access token lifetime",
                detail: formatDuration(policy.access_token_lifetime_seconds),
              },
              {
                term: "Session reuse",
                detail: policy.browser_session_reuse ? "Explicit confirmation allowed" : "Disabled",
              },
            ]}
          />
        )}
      </Section>
      <Dialog
        open={editingMetadata}
        title="Edit Project name"
        onClose={() => {
          if (!submitting) setEditingMetadata(false);
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={() => {
                setEditingMetadata(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" form="project-metadata-form" variant="primary" busy={submitting}>
              Save Project name
            </Button>
          </>
        }
      >
        <form id="project-metadata-form" onSubmit={(event) => void updateProject(event)}>
          {metadataError === null ? null : (
            <InlineAlert tone="danger" role="alert">
              {metadataError}
            </InlineAlert>
          )}
          <Field label="Display name" htmlFor="project-update-name">
            <Input
              id="project-update-name"
              name="display_name"
              defaultValue={project.display_name}
              required
              maxLength={128}
              data-owl-initial-focus
            />
          </Field>
        </form>
      </Dialog>
      <Dialog
        open={editingPolicy && policy !== null}
        title="Edit session and token policy"
        onClose={() => {
          if (!submitting) setEditingPolicy(false);
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={() => {
                setEditingPolicy(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" form="project-policy-form" variant="primary" busy={submitting}>
              Save policy
            </Button>
          </>
        }
      >
        {policy === null ? null : (
          <form
            id="project-policy-form"
            className={styles["form"]}
            onSubmit={(event) => void updatePolicy(event)}
          >
            {policyError === null ? null : (
              <InlineAlert tone="danger" role="alert">
                {policyError}
              </InlineAlert>
            )}
            <Field
              label="Access token lifetime in seconds"
              htmlFor="access-token-lifetime"
              description={`Currently ${formatDuration(policy.access_token_lifetime_seconds)}.`}
            >
              <Input
                id="access-token-lifetime"
                name="access_token_lifetime_seconds"
                type="number"
                min={60}
                max={3600}
                defaultValue={policy.access_token_lifetime_seconds}
                required
                data-owl-initial-focus
              />
            </Field>
            <Checkbox name="browser_session_reuse" defaultChecked={policy.browser_session_reuse}>
              Allow users to explicitly confirm reuse of their browser session
            </Checkbox>
          </form>
        )}
      </Dialog>
      <section className={styles["dangerZone"]}>
        <h2>Danger zone</h2>
        <p>
          {active
            ? "Disable this Project to stop Runtime authentication and configuration changes without deleting its data."
            : "Enable this Project to restore Runtime authentication and configuration changes."}
        </p>
        <div className={styles["actions"]}>
          <Button
            type="button"
            variant={active ? "danger" : "secondary"}
            onClick={() => {
              setLifecycleError(null);
              setLifecycleAction(active ? "disable" : "enable");
            }}
          >
            {active ? "Disable Project" : "Enable Project"}
          </Button>
          <Button
            type="button"
            variant="danger"
            onClick={() => {
              setDeleteError(null);
              setDeleteConfirmation("");
              setConfirmDelete(true);
            }}
          >
            Permanently delete Project
          </Button>
        </div>
      </section>
      <Dialog
        open={lifecycleAction !== null}
        title={lifecycleAction === "disable" ? "Disable Project" : "Enable Project"}
        onClose={() => {
          if (!submitting) setLifecycleAction(null);
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={() => {
                setLifecycleAction(null);
              }}
            >
              Cancel
            </Button>
            {lifecycleAction === null ? null : (
              <Button
                type="button"
                variant={lifecycleAction === "disable" ? "danger" : "primary"}
                busy={submitting}
                onClick={() => void transitionProject(lifecycleAction)}
              >
                {lifecycleAction === "disable" ? "Disable" : "Enable"} {project.display_name}
              </Button>
            )}
          </>
        }
      >
        {lifecycleError === null ? null : (
          <InlineAlert tone="danger" role="alert">
            {lifecycleError}
          </InlineAlert>
        )}
        <p>
          {lifecycleAction === "disable" ? "Disable" : "Enable"}{" "}
          <strong>{project.display_name}</strong>?
          {lifecycleAction === "disable"
            ? " New authentication and configuration actions will be blocked until it is enabled again."
            : " Runtime authentication and configuration actions will become available again."}
        </p>
      </Dialog>
      <Dialog
        open={confirmDelete}
        title="Permanently delete Project"
        onClose={() => {
          if (!submitting) {
            setConfirmDelete(false);
            setDeleteConfirmation("");
          }
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={() => {
                setConfirmDelete(false);
                setDeleteConfirmation("");
              }}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              form="delete-project-form"
              variant="danger"
              busy={submitting}
              disabled={deleteConfirmation !== project.display_name}
            >
              Permanently delete Project
            </Button>
          </>
        }
      >
        {deleteError === null ? null : (
          <InlineAlert tone="danger" role="alert">
            {deleteError}
          </InlineAlert>
        )}
        <InlineAlert tone="danger">
          Access stops immediately. This action cannot be undone. Provider key cleanup may continue
          asynchronously before all live Project data is physically removed.
        </InlineAlert>
        <form
          id="delete-project-form"
          className={styles["form"]}
          onSubmit={(event) => void deleteProject(event)}
        >
          <Field
            label={`Type ${project.display_name} to confirm`}
            htmlFor="delete-project-confirmation"
            description="Enter the exact current Project display name."
          >
            <Input
              id="delete-project-confirmation"
              value={deleteConfirmation}
              autoComplete="off"
              onChange={(event) => {
                setDeleteConfirmation(event.currentTarget.value);
              }}
              data-owl-initial-focus
            />
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
