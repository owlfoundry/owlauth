import { useRef, useState } from "react";
import type { SyntheticEvent } from "react";
import { Link, useNavigate } from "react-router";

import { DataTable, EmptyState, PageHeader } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { Field, Input } from "../../shared/primitives/Field";
import { Dialog } from "../../shared/primitives/Overlay";
import { StatusBadge } from "../../shared/primitives/Feedback";
import { useControl } from "../app/ControlContext";
import { IdempotencyAttempt, requireData } from "../client";
import styles from "./pages.module.css";

export function ProjectsPage() {
  const { session, projects, loadingProjects, refreshProjects, setMessage, handleError } =
    useControl();
  const [creating, setCreating] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const attempt = useRef(new IdempotencyAttempt());
  const navigate = useNavigate();

  function closeCreate() {
    if (submitting) return;
    attempt.current.abandon();
    setCreating(false);
  }

  async function createProject(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    const idempotencyKey = attempt.current.begin();
    if (idempotencyKey === null) return;
    setSubmitting(true);
    try {
      const result = await session.client.POST("/v1/projects", {
        params: { header: { "Idempotency-Key": idempotencyKey } },
        body: {
          display_name: text(fields, "display_name"),
          belongs_to: optionalText(fields, "belongs_to"),
        },
      });
      const created = requireData(result.data, result.error, result.response);
      attempt.current.settle();
      await refreshProjects();
      setCreating(false);
      setMessage("Project created.", "success");
      void navigate(`/projects/${created.id}`);
    } catch (error) {
      attempt.current.settle(error);
      await handleError(error);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className={styles["page"]}>
      <PageHeader
        title="Projects"
        description="Select a Project or create a bounded authentication authority."
        actions={
          <Button
            type="button"
            variant="primary"
            onClick={() => {
              setCreating(true);
            }}
          >
            Create Project
          </Button>
        }
      />
      {loadingProjects ? <p role="status">Loading Projects</p> : null}
      {projects.length === 0 && !loadingProjects ? (
        <EmptyState
          title="No Projects yet"
          description="Create the first Project to configure Applications and authentication methods."
          action={
            <Button
              type="button"
              variant="primary"
              onClick={() => {
                setCreating(true);
              }}
            >
              Create Project
            </Button>
          }
        />
      ) : (
        <DataTable
          caption="Projects in this deployment"
          headings={["Project", "Status", "External owner", "Revision"]}
        >
          {projects.map((project) => (
            <tr key={project.id}>
              <td>
                <Link className={styles["resourceLink"]} to={`/projects/${project.id}`}>
                  {project.display_name}
                </Link>
                <span className={styles["machineValue"]}>{project.public_id}</span>
              </td>
              <td>
                <StatusBadge status={project.status} />
              </td>
              <td>{project.belongs_to ?? "Not set"}</td>
              <td>{String(project.metadata_revision)}</td>
            </tr>
          ))}
        </DataTable>
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
              data-owl-initial-focus
            />
          </Field>
          <Field
            label="External owner metadata"
            htmlFor="project-owner"
            optional
            description="A safe operator-defined reference; it does not grant authority."
          >
            <Input id="project-owner" name="belongs_to" maxLength={256} />
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

function optionalText(fields: FormData, name: string): string | null {
  const value = text(fields, name).trim();
  return value === "" ? null : value;
}
