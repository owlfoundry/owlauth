import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router";

import { CopyValue } from "../../shared/compositions/CopyValue";
import { EmptyState, PageHeader, Section } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { useControl, useProject } from "../app/ControlContext";
import { requireData } from "../client";
import styles from "./pages.module.css";

interface Summary {
  readonly applications: number;
  readonly configuredApplications: number;
  readonly providers: number;
  readonly assignedMethods: number;
  readonly activeSigningKeys: number;
}

export function ProjectOverviewPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, handleError, setMessage } = useControl();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "failed">("loading");

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      if (project === null) return;
      setLoadState("loading");
      try {
        const [applications, providers, keys, emailPolicy, emailAssignments] = await Promise.all([
          session.client.GET("/v1/projects/{project_id}/applications", {
            params: { path: { project_id: project.id } },
            signal: signal ?? null,
          }),
          session.client.GET("/v1/projects/{project_id}/providers", {
            params: { path: { project_id: project.id } },
            signal: signal ?? null,
          }),
          session.client.GET("/v1/projects/{project_id}/signing-keys", {
            params: { path: { project_id: project.id } },
            signal: signal ?? null,
          }),
          session.client.GET("/v1/projects/{project_id}/email-method", {
            params: { path: { project_id: project.id } },
            signal: signal ?? null,
          }),
          session.client.GET("/v1/projects/{project_id}/email-method/assignments", {
            params: { path: { project_id: project.id } },
            signal: signal ?? null,
          }),
        ]);
        const applicationItems = requireData(
          applications.data,
          applications.error,
          applications.response,
        ).items;
        const providerItems = requireData(
          providers.data,
          providers.error,
          providers.response,
        ).items;
        const keyItems = requireData(keys.data, keys.error, keys.response).items;
        const email = requireData(emailPolicy.data, emailPolicy.error, emailPolicy.response);
        const emailAssignmentItems = requireData(
          emailAssignments.data,
          emailAssignments.error,
          emailAssignments.response,
        ).items;
        const activeApplications = applicationItems.filter(
          (application) => application.status === "active",
        );
        const activeApplicationIds = new Set(
          activeApplications.map((application) => application.id),
        );
        const next = {
          applications: activeApplications.length,
          configuredApplications: activeApplications.filter(
            (application) => application.configuration.redirect_uris.length > 0,
          ).length,
          providers: providerItems.filter((provider) => provider.status === "active").length,
          assignedMethods:
            providerItems
              .filter((provider) => provider.status === "active")
              .reduce(
                (total, provider) =>
                  total +
                  provider.assigned_application_ids.filter((id) => activeApplicationIds.has(id))
                    .length,
                0,
              ) +
            (email.enabled
              ? emailAssignmentItems.filter(
                  (assignment) =>
                    assignment.enabled && activeApplicationIds.has(assignment.application_id),
                ).length
              : 0),
          activeSigningKeys: keyItems.filter((key) => key.state === "active").length,
        };
        if (signal?.aborted !== true) {
          setSummary(next);
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

  if (project === null) {
    return (
      <EmptyState
        level={1}
        title="Project not found"
        description="The Project does not exist in the current deployment state."
        action={<Link to="/">Return to Projects</Link>}
      />
    );
  }

  return (
    <div className={styles["page"]}>
      <PageHeader
        title={project.display_name}
        description="Review committed Project state and continue with one configuration area."
        status={<StatusBadge status={project.status} />}
      />
      {project.status !== "active" ? (
        <InlineAlert tone="warning">
          This Project is disabled. Configuration actions are unavailable.
        </InlineAlert>
      ) : null}
      <Section title="Project ID" description="Use this public identifier in trusted integrations.">
        <CopyValue
          value={project.public_id}
          label="Project public ID"
          block
          onCopied={(message) => {
            setMessage(message, "success");
          }}
        />
      </Section>
      <Section
        title="Set up sign-in"
        description="Complete the steps in order. Status comes from committed Project resources."
      >
        {loadState === "loading" ? <p role="status">Loading Project resources</p> : null}
        {loadState === "failed" ? (
          <InlineAlert tone="danger" role="alert">
            <p>Project resource summaries could not be loaded.</p>
            <Button type="button" onClick={() => void refresh().catch(handleError)}>
              Retry Project resources
            </Button>
          </InlineAlert>
        ) : null}
        {loadState === "ready" && summary !== null ? (
          <ol className={styles["setupList"]}>
            <SetupStep
              title="Create an Application"
              ready={summary.applications > 0}
              detail={
                summary.applications > 0
                  ? `${String(summary.applications)} configured`
                  : "Add the app that will send users to OwlAuth."
              }
              href={`/projects/${project.id}/applications`}
              action={summary.applications > 0 ? "Review Applications" : "Create Application"}
            />
            <SetupStep
              title="Add login URLs"
              ready={summary.configuredApplications > 0}
              detail={
                summary.configuredApplications > 0
                  ? `${String(summary.configuredApplications)} Application${summary.configuredApplications === 1 ? "" : "s"} with redirect URLs`
                  : "Add exact redirect URLs before starting browser sign-in."
              }
              href={`/projects/${project.id}/applications`}
              action="Configure login URLs"
            />
            <SetupStep
              title="Choose how users sign in"
              ready={summary.assignedMethods > 0}
              detail={
                summary.assignedMethods > 0
                  ? `${String(summary.assignedMethods)} method assignment${summary.assignedMethods === 1 ? "" : "s"}`
                  : summary.providers > 0
                    ? "Assign an existing provider to an Application."
                    : "Add a provider or configure passwordless email."
              }
              href={`/projects/${project.id}/authentication/providers`}
              action={summary.providers > 0 ? "Assign provider" : "Add sign-in method"}
            />
            <SetupStep
              title="Activate a signing key"
              ready={summary.activeSigningKeys > 0}
              detail={
                summary.activeSigningKeys > 0
                  ? "An active key can issue tokens."
                  : "OwlAuth needs an active signing key before sign-in can complete."
              }
              href={`/projects/${project.id}/security/signing-keys`}
              action="Review signing keys"
            />
          </ol>
        ) : null}
      </Section>
    </div>
  );
}

function SetupStep({
  title,
  ready,
  detail,
  href,
  action,
}: {
  readonly title: string;
  readonly ready: boolean;
  readonly detail: string;
  readonly href: string;
  readonly action: string;
}) {
  return (
    <li className={styles["setupStep"]}>
      <div>
        <StatusBadge
          status={ready ? "Ready" : "Not configured"}
          family={ready ? "active" : "disabled"}
        />
        <h3>{title}</h3>
        <p>{detail}</p>
      </div>
      <Link to={href}>{action}</Link>
    </li>
  );
}
