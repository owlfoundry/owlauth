import { useEffect, useRef, useState } from "react";
import type { SyntheticEvent } from "react";
import { Link, useNavigate } from "react-router";

import { ArrowRightIcon, PlusIcon } from "../../shared/icons/Icons";
import { EmptyState, PageHeader } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Field, Input } from "../../shared/primitives/Field";
import { Dialog } from "../../shared/primitives/Overlay";
import { useControl } from "../app/ControlContext";
import { UnsavedChangesGuard } from "../app/UnsavedChangesGuard";
import { ControlRequestError, IdempotencyAttempt, requireData } from "../client";
import styles from "./pages.module.css";

export function ProjectsPage() {
  const { session, projects, loadingProjects, upsertProject, setMessage, handleError } =
    useControl();
  const [creating, setCreating] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [createdProjectId, setCreatedProjectId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const attempt = useRef(new IdempotencyAttempt());
  const navigate = useNavigate();

  useEffect(() => {
    if (createdProjectId === null) return;
    const timer = window.setTimeout(() => {
      setCreatedProjectId(null);
      void navigate(`/projects/${createdProjectId}`);
    }, 0);
    return () => {
      window.clearTimeout(timer);
    };
  }, [createdProjectId, navigate]);

  function discardCreate() {
    attempt.current.abandon();
    setCreating(false);
    setCreateName("");
    setCreateError(null);
  }

  function closeCreate() {
    if (!submitting) discardCreate();
  }

  async function createProject(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
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
      const result = await session.client.POST("/v1/projects", {
        params: { header: { "Idempotency-Key": idempotencyKey } },
        body: {
          display_name: displayName,
          belongs_to: null,
        },
      });
      const created = requireData(result.data, result.error, result.response);
      attempt.current.settle();
      upsertProject(created);
      setCreating(false);
      setCreateName("");
      setCreateError(null);
      setMessage(`Project “${created.display_name}” created.`, "success");
      setCreatedProjectId(created.id);
    } catch (error) {
      attempt.current.settle(error);
      setCreateError(
        error instanceof ControlRequestError ? error.message : "Project could not be created.",
      );
      await handleError(error);
    } finally {
      setSubmitting(false);
    }
  }

  const createDirty = creating && createName !== "";
  return (
    <div className={styles["page"]}>
      <UnsavedChangesGuard dirty={createDirty} submitting={submitting} onDiscard={discardCreate} />
      <PageHeader
        title="Projects"
        description="Create and manage isolated authentication projects."
        actions={
          <Button
            type="button"
            variant="primary"
            onClick={() => {
              setCreateError(null);
              setCreating(true);
            }}
          >
            <PlusIcon />
            Create Project
          </Button>
        }
      />
      {loadingProjects ? <p role="status">Loading Projects</p> : null}
      {projects.length === 0 && !loadingProjects ? (
        <EmptyState
          title="No Projects yet"
          description="Create the first Project to configure Applications and authentication methods."
        />
      ) : (
        <ul className={styles["projectDirectory"]} aria-label="Projects in this deployment">
          {projects.map((project) => (
            <li key={project.id}>
              <Link
                className={styles["projectDirectoryItem"]}
                to={`/projects/${project.id}`}
                aria-labelledby={`project-${project.id}-name`}
                aria-describedby={`project-${project.id}-public-id project-${project.id}-status`}
              >
                <span className={styles["projectDirectoryBody"]}>
                  <strong id={`project-${project.id}-name`}>{project.display_name}</strong>
                  <code id={`project-${project.id}-public-id`}>{project.public_id}</code>
                </span>
                <span className={styles["projectDirectoryMeta"]}>
                  <span id={`project-${project.id}-status`}>
                    <StatusBadge status={project.status} />
                  </span>
                  <ArrowRightIcon />
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      <Dialog
        open={creating}
        title="Create Project"
        onClose={closeCreate}
        actions={
          <>
            <Button type="button" variant="quiet" disabled={submitting} onClick={closeCreate}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" form="create-project-form" busy={submitting}>
              Create Project
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
          id="create-project-form"
          className={styles["form"]}
          onSubmit={(event) => void createProject(event)}
        >
          <Field label="Display name" htmlFor="project-name">
            <Input
              id="project-name"
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
        </form>
      </Dialog>
    </div>
  );
}

function text(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}
