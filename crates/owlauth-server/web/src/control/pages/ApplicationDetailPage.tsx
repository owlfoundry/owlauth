import { useCallback, useEffect, useRef, useState } from "react";
import type { SyntheticEvent } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { DescriptionList, EmptyState, PageHeader, Section } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Field, Input, Textarea } from "../../shared/primitives/Field";
import { Dialog } from "../../shared/primitives/Overlay";
import { useControl, useProject } from "../app/ControlContext";
import { ApplicationDelivery } from "../features/ApplicationDelivery";
import { type Application, ControlRequestError, requireData } from "../client";
import styles from "./pages.module.css";

export function ApplicationDetailPage() {
  const { projectId, applicationId } = useParams();
  const project = useProject(projectId);
  const { session, handleError, setMessage } = useControl();
  const [application, setApplication] = useState<Application | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "not-found" | "failed">(
    "loading",
  );
  const [editingMetadata, setEditingMetadata] = useState(false);
  const [editingConfiguration, setEditingConfiguration] = useState(false);
  const [confirmDisable, setConfirmDisable] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const navigate = useNavigate();

  const refresh = useCallback(async () => {
    if (project === null || applicationId === undefined) return;
    setLoadState("loading");
    try {
      const result = await session.client.GET(
        "/v1/projects/{project_id}/applications/{application_id}",
        {
          params: { path: { project_id: project.id, application_id: applicationId } },
        },
      );
      setApplication(requireData(result.data, result.error, result.response));
      setLoadState("ready");
    } catch (error) {
      setApplication(null);
      if (error instanceof ControlRequestError && error.status === 404) {
        setLoadState("not-found");
        return;
      }
      setLoadState("failed");
      throw error;
    }
  }, [applicationId, project, session]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void refresh().catch(handleError);
    }, 0);
    return () => {
      window.clearTimeout(timer);
    };
  }, [handleError, refresh]);

  useEffect(() => {
    if (loadState === "loading") return;
    const frame = window.requestAnimationFrame(() => {
      headingRef.current?.focus();
    });
    return () => {
      window.cancelAnimationFrame(frame);
    };
  }, [application, loadState]);

  async function updateMetadata(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (application === null) return;
    const fields = new FormData(event.currentTarget);
    setSubmitting(true);
    try {
      const result = await session.client.PATCH(
        "/v1/projects/{project_id}/applications/{application_id}",
        {
          params: { path: { project_id: application.project_id, application_id: application.id } },
          body: {
            display_name: text(fields, "display_name"),
            expected_metadata_revision: application.metadata_revision,
          },
        },
      );
      requireData(result.data, result.error, result.response);
      await refresh();
      setEditingMetadata(false);
      setMessage("Application metadata updated.", "success");
    } catch (error) {
      await handleError(error, async () => {
        await refresh();
        setEditingMetadata(false);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function replaceConfiguration(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (application === null) return;
    const fields = new FormData(event.currentTarget);
    setSubmitting(true);
    try {
      const result = await session.client.PUT(
        "/v1/projects/{project_id}/applications/{application_id}/configuration",
        {
          params: { path: { project_id: application.project_id, application_id: application.id } },
          body: {
            redirect_uris: lines(fields, "redirect_uris"),
            allowed_origins: lines(fields, "allowed_origins"),
            expected_security_revision: application.security_revision,
          },
        },
      );
      requireData(result.data, result.error, result.response);
      await refresh();
      setEditingConfiguration(false);
      setMessage("Exact browser configuration replaced.", "success");
    } catch (error) {
      await handleError(error, async () => {
        await refresh();
        setEditingConfiguration(false);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function disableApplication() {
    if (application === null) return;
    setSubmitting(true);
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/applications/{application_id}/disable",
        {
          params: { path: { project_id: application.project_id, application_id: application.id } },
          body: { expected_security_revision: application.security_revision },
        },
      );
      requireData(result.data, result.error, result.response);
      await refresh();
      setConfirmDisable(false);
      setMessage("Application disabled.", "success");
    } catch (error) {
      await handleError(error, refresh);
    } finally {
      setSubmitting(false);
    }
  }

  if (project === null) {
    return (
      <EmptyState
        level={1}
        headingRef={headingRef}
        title="Project not found"
        description="The Project is not present in the current deployment state."
        action={<Link to="/">Return to Projects</Link>}
      />
    );
  }
  if (loadState === "loading") {
    return (
      <div className={styles["page"]}>
        <PageHeader
          title="Application"
          description="Loading committed Application state."
          headingRef={headingRef}
        />
        <p role="status">Loading Application</p>
      </div>
    );
  }
  if (loadState === "failed") {
    return (
      <div className={styles["page"]}>
        <PageHeader
          title="Application unavailable"
          description="Committed Application state could not be loaded."
          headingRef={headingRef}
        />
        <InlineAlert tone="danger" role="alert">
          <p>The Application could not be loaded. No missing-resource conclusion was made.</p>
          <Button type="button" onClick={() => void refresh().catch(handleError)}>
            Retry Application
          </Button>
        </InlineAlert>
      </div>
    );
  }
  if (loadState === "not-found" || application === null) {
    return (
      <EmptyState
        level={1}
        headingRef={headingRef}
        title="Application not found"
        description="The Application is not present in the current Project state."
        action={<Link to={`/projects/${project.id}/applications`}>Return to Applications</Link>}
      />
    );
  }

  const active = project.status === "active" && application.status === "active";
  return (
    <div className={styles["page"]}>
      <PageHeader
        title={application.display_name}
        headingRef={headingRef}
        description="Review browser configuration and Application user delivery."
        status={<StatusBadge status={application.status} />}
        actions={
          <Button
            type="button"
            variant="quiet"
            onClick={() => {
              void navigate(`/projects/${project.id}/applications`);
            }}
          >
            Back to Applications
          </Button>
        }
      />
      {!active ? (
        <InlineAlert tone="warning">
          This Application cannot be changed in its current state.
        </InlineAlert>
      ) : null}
      <Section
        title="Application details"
        action={
          active && !editingMetadata ? (
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                setEditingMetadata(true);
              }}
            >
              Edit metadata
            </Button>
          ) : undefined
        }
      >
        {editingMetadata ? (
          <form className={styles["form"]} onSubmit={(event) => void updateMetadata(event)}>
            <Field label="Display name" htmlFor="application-update-name">
              <Input
                id="application-update-name"
                name="display_name"
                defaultValue={application.display_name}
                required
                maxLength={128}
                data-owl-initial-focus
              />
            </Field>
            <div className={styles["formActions"]}>
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
              <Button type="submit" variant="primary" busy={submitting}>
                Save Application
              </Button>
            </div>
          </form>
        ) : (
          <DescriptionList
            items={[
              {
                term: "Public ID",
                detail: <span className={styles["machineValue"]}>{application.public_id}</span>,
              },
              { term: "Type", detail: application.application_type },
              { term: "Metadata revision", detail: String(application.metadata_revision) },
              { term: "Security revision", detail: String(application.security_revision) },
            ]}
          />
        )}
      </Section>
      <Section
        title="Exact browser configuration"
        description="Redirect URIs and allowed origins are replaced as one reviewed set."
        action={
          active && !editingConfiguration ? (
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                setEditingConfiguration(true);
              }}
            >
              Edit configuration
            </Button>
          ) : undefined
        }
      >
        {editingConfiguration ? (
          <form className={styles["form"]} onSubmit={(event) => void replaceConfiguration(event)}>
            <Field
              label="Redirect URIs"
              htmlFor="redirect-uris"
              description="One exact URI per line."
            >
              <Textarea
                id="redirect-uris"
                name="redirect_uris"
                rows={5}
                defaultValue={application.configuration.redirect_uris.join("\n")}
                data-owl-initial-focus
              />
            </Field>
            <Field
              label="Allowed origins"
              htmlFor="allowed-origins"
              description="One exact origin per line."
            >
              <Textarea
                id="allowed-origins"
                name="allowed_origins"
                rows={5}
                defaultValue={application.configuration.allowed_origins.join("\n")}
              />
            </Field>
            <div className={styles["formActions"]}>
              <Button
                type="button"
                variant="quiet"
                disabled={submitting}
                onClick={() => {
                  setEditingConfiguration(false);
                }}
              >
                Cancel
              </Button>
              <Button type="submit" variant="primary" busy={submitting}>
                Replace configuration
              </Button>
            </div>
          </form>
        ) : (
          <DescriptionList
            items={[
              {
                term: "Redirect URIs",
                detail:
                  application.configuration.redirect_uris.length === 0
                    ? "None configured"
                    : application.configuration.redirect_uris.map((value) => (
                        <span className={styles["machineValue"]} key={value}>
                          {value}
                        </span>
                      )),
              },
              {
                term: "Allowed origins",
                detail:
                  application.configuration.allowed_origins.length === 0
                    ? "None configured"
                    : application.configuration.allowed_origins.map((value) => (
                        <span className={styles["machineValue"]} key={value}>
                          {value}
                        </span>
                      )),
              },
              {
                term: "Publishable identifiers",
                detail: application.configuration.publishable_keys.map((value) => (
                  <span className={styles["machineValue"]} key={value}>
                    {value}
                  </span>
                )),
              },
            ]}
          />
        )}
      </Section>
      <ApplicationDelivery
        session={session}
        application={application}
        onError={handleError}
        setMessage={(message) => {
          setMessage(message, "success");
        }}
      />
      {active ? (
        <section className={styles["dangerZone"]}>
          <h2>Danger zone</h2>
          <p>Disabling prevents new authentication for this Application.</p>
          <Button
            type="button"
            variant="danger"
            onClick={() => {
              setConfirmDisable(true);
            }}
          >
            Disable Application
          </Button>
        </section>
      ) : null}
      <Dialog
        open={confirmDisable}
        title="Disable Application"
        onClose={() => {
          setConfirmDisable(false);
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={() => {
                setConfirmDisable(false);
              }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="danger"
              busy={submitting}
              onClick={() => void disableApplication()}
            >
              Disable {application.display_name}
            </Button>
          </>
        }
      >
        <p>
          Disable <strong>{application.display_name}</strong>? Existing state is retained, but new
          sign-in is blocked.
        </p>
      </Dialog>
    </div>
  );
}

function text(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}

function lines(fields: FormData, name: string): string[] {
  return text(fields, name)
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
}
