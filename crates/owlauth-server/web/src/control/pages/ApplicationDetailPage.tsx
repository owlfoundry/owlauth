import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { SyntheticEvent } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";

import { CopyValue } from "../../shared/compositions/CopyValue";
import { ArrowLeftIcon } from "../../shared/icons/Icons";
import {
  compactStringList,
  isValidStringList,
  StringListField,
} from "../../shared/compositions/StringListField";
import {
  DescriptionList,
  EmptyState,
  LoadingState,
  PageHeader,
  Section,
  tabClassName,
  Tabs,
} from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Field, Input } from "../../shared/primitives/Field";
import { Dialog, SideSheet } from "../../shared/primitives/Overlay";
import { useControl, useProject } from "../app/ControlContext";
import { UnsavedChangesGuard } from "../app/UnsavedChangesGuard";
import {
  ApplicationDelivery,
  type ApplicationDeliveryDraft,
} from "../features/ApplicationDelivery";
import { ApplicationAuthentication } from "../features/ApplicationAuthentication";
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
  const [redirectUris, setRedirectUris] = useState<string[]>([""]);
  const [allowedOrigins, setAllowedOrigins] = useState<string[]>([""]);
  const [confirmDisable, setConfirmDisable] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [metadataError, setMetadataError] = useState<string | null>(null);
  const [configurationError, setConfigurationError] = useState<string | null>(null);
  const [disableError, setDisableError] = useState<string | null>(null);
  const [deliveryDraft, setDeliveryDraft] = useState<ApplicationDeliveryDraft | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      if (project === null || applicationId === undefined) return;
      setLoadState((current) => (current === "ready" ? current : "loading"));
      try {
        const result = await session.client.GET(
          "/v1/projects/{project_id}/applications/{application_id}",
          {
            params: { path: { project_id: project.id, application_id: applicationId } },
            signal: signal ?? null,
          },
        );
        if (signal?.aborted !== true) {
          setApplication(requireData(result.data, result.error, result.response));
          setLoadState("ready");
        }
      } catch (error) {
        if (signal?.aborted === true) throw error;
        setApplication(null);
        if (error instanceof ControlRequestError && error.status === 404) {
          setLoadState("not-found");
          return;
        }
        setLoadState("failed");
        throw error;
      }
    },
    [applicationId, project, session],
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

  useLayoutEffect(() => {
    if (loadState !== "loading") headingRef.current?.focus();
  }, [application?.id, loadState]);

  async function updateMetadata(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (application === null) return;
    const fields = new FormData(event.currentTarget);
    setMetadataError(null);
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
      const conflict =
        error instanceof ControlRequestError &&
        error.status === 409 &&
        error.code === "revision_conflict";
      if (conflict) setEditingMetadata(false);
      else
        setMetadataError(
          error instanceof ControlRequestError
            ? error.message
            : "Application metadata could not be updated.",
        );
      await handleError(error, async () => {
        await refresh();
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function replaceConfiguration(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (
      application === null ||
      !isValidStringList(redirectUris) ||
      !isValidStringList(allowedOrigins)
    )
      return;
    setConfigurationError(null);
    setSubmitting(true);
    try {
      const result = await session.client.PUT(
        "/v1/projects/{project_id}/applications/{application_id}/configuration",
        {
          params: { path: { project_id: application.project_id, application_id: application.id } },
          body: {
            redirect_uris: compactStringList(redirectUris),
            allowed_origins: compactStringList(allowedOrigins),
            expected_security_revision: application.security_revision,
          },
        },
      );
      requireData(result.data, result.error, result.response);
      await refresh();
      setEditingConfiguration(false);
      setMessage("Exact browser configuration replaced.", "success");
    } catch (error) {
      const conflict =
        error instanceof ControlRequestError &&
        error.status === 409 &&
        error.code === "revision_conflict";
      if (conflict) setEditingConfiguration(false);
      else
        setConfigurationError(
          error instanceof ControlRequestError
            ? error.message
            : "Login URL configuration could not be updated.",
        );
      await handleError(error, async () => {
        await refresh();
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function disableApplication() {
    if (application === null) return;
    setDisableError(null);
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
      const conflict =
        error instanceof ControlRequestError &&
        error.status === 409 &&
        error.code === "revision_conflict";
      if (conflict) setConfirmDisable(false);
      else
        setDisableError(
          error instanceof ControlRequestError
            ? error.message
            : "Application could not be disabled.",
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
        <LoadingState>Loading application</LoadingState>
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
  const configurationDirty =
    editingConfiguration &&
    (JSON.stringify(compactStringList(redirectUris)) !==
      JSON.stringify(application.configuration.redirect_uris) ||
      JSON.stringify(compactStringList(allowedOrigins)) !==
        JSON.stringify(application.configuration.allowed_origins));
  const requestedSection = searchParams.get("section");
  const section = ["general", "authentication", "urls", "webhooks", "advanced"].includes(
    requestedSection ?? "",
  )
    ? requestedSection
    : "general";
  const copyToast = (message: string) => {
    setMessage(message, "success");
  };
  return (
    <div className={styles["page"]}>
      <UnsavedChangesGuard
        dirty={configurationDirty || editingMetadata || deliveryDraft !== null}
        submitting={submitting || deliveryDraft?.submitting === true}
        onDiscard={() => {
          setEditingMetadata(false);
          setEditingConfiguration(false);
          setMetadataError(null);
          setConfigurationError(null);
          deliveryDraft?.discard();
        }}
      />
      <PageHeader
        title={application.display_name}
        headingRef={headingRef}
        description="Configure sign-in, integration values, and webhook delivery."
        status={<StatusBadge status={application.status} />}
        actions={
          <Button
            type="button"
            variant="secondary"
            onClick={() => {
              void navigate(`/projects/${project.id}/applications`);
            }}
          >
            <ArrowLeftIcon />
            Back to Applications
          </Button>
        }
      />
      {!active ? (
        <InlineAlert tone="warning">
          This Application cannot be changed in its current state.
        </InlineAlert>
      ) : null}
      <Tabs label="Application sections">
        {(
          [
            ["general", "General"],
            ["authentication", "Authentication"],
            ["urls", "Login URLs"],
            ["webhooks", "Webhooks"],
            ["advanced", "Advanced"],
          ] as const
        ).map(([value, label]) => (
          <Link
            key={value}
            className={tabClassName()}
            to={`?section=${value}`}
            aria-current={section === value ? "page" : undefined}
          >
            {label}
          </Link>
        ))}
      </Tabs>
      {section === "general" ? (
        <Section
          title="Application details"
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
                Edit name
              </Button>
            ) : undefined
          }
        >
          <DescriptionList
            items={[
              {
                term: "Public ID",
                detail: (
                  <CopyValue
                    value={application.public_id}
                    label="Application public ID"
                    onCopied={copyToast}
                  />
                ),
              },
              { term: "Type", detail: application.application_type === "web" ? "Web" : "Native" },
              {
                term: "Publishable identifiers",
                detail:
                  application.configuration.publishable_keys.length === 0
                    ? "None"
                    : application.configuration.publishable_keys.map((value) => (
                        <CopyValue
                          key={value}
                          value={value}
                          label="publishable identifier"
                          block
                          onCopied={copyToast}
                        />
                      )),
              },
            ]}
          />
        </Section>
      ) : null}
      {section === "authentication" ? (
        <ApplicationAuthentication
          session={session}
          application={application}
          editable={active}
          onApplicationChanged={refresh}
          onError={handleError}
          setMessage={(message) => {
            setMessage(message, "success");
          }}
        />
      ) : null}
      {section === "urls" ? (
        <Section
          title="Login URLs"
          description="Only these exact redirect URLs and browser origins are accepted."
          action={
            active ? (
              <Button
                type="button"
                variant="primary"
                onClick={() => {
                  setRedirectUris(
                    application.configuration.redirect_uris.length === 0
                      ? [""]
                      : [...application.configuration.redirect_uris],
                  );
                  setAllowedOrigins(
                    application.configuration.allowed_origins.length === 0
                      ? [""]
                      : [...application.configuration.allowed_origins],
                  );
                  setConfigurationError(null);
                  setEditingConfiguration(true);
                }}
              >
                Edit login URLs
              </Button>
            ) : undefined
          }
        >
          <DescriptionList
            items={[
              {
                term: "Redirect URLs",
                detail:
                  application.configuration.redirect_uris.length === 0
                    ? "None configured"
                    : application.configuration.redirect_uris.map((value) => (
                        <CopyValue
                          key={value}
                          value={value}
                          label="redirect URL"
                          block
                          onCopied={copyToast}
                        />
                      )),
              },
              {
                term: "Allowed origins",
                detail:
                  application.configuration.allowed_origins.length === 0
                    ? "None configured"
                    : application.configuration.allowed_origins.map((value) => (
                        <CopyValue
                          key={value}
                          value={value}
                          label="allowed origin"
                          block
                          onCopied={copyToast}
                        />
                      )),
              },
            ]}
          />
        </Section>
      ) : null}
      {section === "webhooks" ? (
        <ApplicationDelivery
          session={session}
          application={application}
          onError={handleError}
          setMessage={(message) => {
            setMessage(message, "success");
          }}
          onDraftChange={setDeliveryDraft}
        />
      ) : null}
      {section === "advanced" && active ? (
        <section className={styles["dangerZone"]}>
          <h2>Danger zone</h2>
          <p>Disabling prevents new authentication for this Application.</p>
          <Button
            type="button"
            variant="danger"
            onClick={() => {
              setDisableError(null);
              setConfirmDisable(true);
            }}
          >
            Disable Application
          </Button>
        </section>
      ) : null}
      <Dialog
        open={editingMetadata}
        title="Edit Application name"
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
            <Button
              type="submit"
              form="application-metadata-form"
              variant="primary"
              busy={submitting}
            >
              Save name
            </Button>
          </>
        }
      >
        <form id="application-metadata-form" onSubmit={(event) => void updateMetadata(event)}>
          {metadataError === null ? null : (
            <InlineAlert tone="danger" role="alert">
              {metadataError}
            </InlineAlert>
          )}
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
        </form>
      </Dialog>
      <SideSheet
        open={editingConfiguration}
        side="right"
        title="Edit login URLs"
        closeLabel="Close login URL editor"
        onClose={() => {
          if (!submitting) setEditingConfiguration(false);
        }}
        actions={
          <>
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
            <Button
              type="submit"
              form="application-configuration-form"
              variant="primary"
              busy={submitting}
            >
              Save login URLs
            </Button>
          </>
        }
      >
        <form
          id="application-configuration-form"
          className={styles["form"]}
          onSubmit={(event) => void replaceConfiguration(event)}
        >
          {configurationError === null ? null : (
            <InlineAlert tone="danger" role="alert">
              {configurationError}
            </InlineAlert>
          )}
          <StringListField
            label="Redirect URLs"
            description="Add each exact URL OwlAuth may return users to after sign-in."
            itemLabel="Redirect URL"
            placeholder={`https://app.example.com/auth/callback`}
            values={redirectUris}
            onChange={setRedirectUris}
          />
          <StringListField
            label="Allowed origins"
            description="Add each exact browser origin allowed to start sign-in."
            itemLabel="Allowed origin"
            placeholder={`https://app.example.com`}
            values={allowedOrigins}
            onChange={setAllowedOrigins}
          />
        </form>
      </SideSheet>
      <Dialog
        open={confirmDisable}
        title="Disable Application"
        onClose={() => {
          if (!submitting) setConfirmDisable(false);
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
        {disableError === null ? null : (
          <InlineAlert tone="danger" role="alert">
            {disableError}
          </InlineAlert>
        )}
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
