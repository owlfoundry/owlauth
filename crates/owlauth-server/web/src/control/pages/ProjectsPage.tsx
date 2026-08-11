import { useEffect, useMemo, useRef, useState } from "react";
import type { SyntheticEvent } from "react";
import { Link, useNavigate } from "react-router";

import { ArrowRightIcon, PlusIcon } from "../../shared/icons/Icons";
import { EmptyState, LoadingState, PageHeader } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Checkbox, Field, Input } from "../../shared/primitives/Field";
import { Dialog } from "../../shared/primitives/Overlay";
import { useControl } from "../app/ControlContext";
import { UnsavedChangesGuard } from "../app/UnsavedChangesGuard";
import { ControlRequestError, IdempotencyAttempt, type Project, requireData } from "../client";
import styles from "./pages.module.css";

export function ProjectsPage() {
  const { session, projects, loadingProjects, upsertProject, setMessage, handleError } =
    useControl();
  const [creating, setCreating] = useState(false);
  const [showInactiveProjects, setShowInactiveProjects] = useState(false);
  const [projectSearch, setProjectSearch] = useState("");
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
  const normalizedProjectSearch = projectSearch.trim().toLowerCase();
  const visibleProjects = useMemo(
    () =>
      projects.filter((project) => {
        if (!showInactiveProjects && project.status !== "active") return false;
        if (normalizedProjectSearch === "") return true;
        return [project.display_name, project.public_id].some((value) =>
          value.toLowerCase().includes(normalizedProjectSearch),
        );
      }),
    [normalizedProjectSearch, projects, showInactiveProjects],
  );
  const hasInactiveProjects = projects.some((project) => project.status !== "active");
  const hasProjectSearch = normalizedProjectSearch !== "";
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
      {loadingProjects ? <LoadingState>Loading projects</LoadingState> : null}
      {!loadingProjects && projects.length > 0 ? (
        <div className={styles["directoryControls"]} aria-label="Project directory filters">
          <div className={styles["directorySearch"]}>
            <Input
              type="search"
              value={projectSearch}
              placeholder="Search by name or Project ID"
              aria-label="Search projects"
              onChange={(event) => {
                setProjectSearch(event.currentTarget.value);
              }}
            />
          </div>
          <span className={styles["directoryResultCount"]} aria-live="polite">
            {visibleProjects.length} {visibleProjects.length === 1 ? "Project" : "Projects"}
          </span>
          {hasInactiveProjects ? (
            <div className={styles["inactiveFilter"]}>
              <Checkbox
                checked={showInactiveProjects}
                onChange={(event) => {
                  setShowInactiveProjects(event.currentTarget.checked);
                }}
              >
                Show inactive projects
              </Checkbox>
            </div>
          ) : null}
        </div>
      ) : null}
      {visibleProjects.length === 0 && !loadingProjects ? (
        <EmptyState
          title={
            projects.length === 0
              ? "No Projects yet"
              : hasProjectSearch
                ? "No matching Projects"
                : "No active Projects"
          }
          description={
            projects.length === 0
              ? "Create the first Project to configure Applications and authentication methods."
              : hasProjectSearch
                ? "Try another name or Project ID, or adjust the inactive filter."
                : "Enable an inactive Project or show inactive projects to review its status."
          }
        />
      ) : (
        <ul className={styles["projectDirectory"]} aria-label="Projects in this deployment">
          {visibleProjects.map((project) => (
            <li key={project.id}>
              {project.status === "deleting" ? (
                <div
                  className={`${styles["projectDirectoryItem"] ?? ""} ${styles["projectDirectoryItemStatic"] ?? ""}`}
                  aria-labelledby={`project-${project.id}-name`}
                  aria-describedby={`project-${project.id}-public-id project-${project.id}-status`}
                >
                  <ProjectDirectoryBody project={project} />
                  <span className={styles["projectDirectoryMeta"]}>
                    <span id={`project-${project.id}-status`}>
                      <StatusBadge status={project.status} />
                    </span>
                  </span>
                </div>
              ) : (
                <Link
                  className={styles["projectDirectoryItem"]}
                  to={`/projects/${project.id}`}
                  aria-labelledby={`project-${project.id}-name`}
                  aria-describedby={`project-${project.id}-public-id project-${project.id}-status`}
                >
                  <ProjectDirectoryBody project={project} />
                  <span className={styles["projectDirectoryMeta"]}>
                    <span id={`project-${project.id}-status`}>
                      <StatusBadge status={project.status} />
                    </span>
                    <ArrowRightIcon />
                  </span>
                </Link>
              )}
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

function ProjectDirectoryBody({ project }: { readonly project: Project }) {
  return (
    <span className={styles["projectDirectoryBody"]}>
      <strong id={`project-${project.id}-name`}>{project.display_name}</strong>
      <code id={`project-${project.id}-public-id`}>{project.public_id}</code>
    </span>
  );
}

function text(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}
