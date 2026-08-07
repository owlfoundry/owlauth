import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router";

import { CopyValue } from "../../shared/compositions/CopyValue";
import { ArrowRightIcon } from "../../shared/icons/Icons";
import { EmptyState, LoadingState, PageHeader, Section } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert } from "../../shared/primitives/Feedback";
import { useControl, useProject } from "../app/ControlContext";
import { requireData } from "../client";
import styles from "./pages.module.css";

interface Summary {
  readonly applications: number;
  readonly activeApplications: number;
  readonly configuredApplications: number;
  readonly providers: number;
  readonly activeProviders: number;
  readonly providerAssignments: number;
  readonly emailAssignments: number;
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
        const activeProviders = providerItems.filter((provider) => provider.status === "active");
        const next = {
          applications: applicationItems.length,
          activeApplications: activeApplications.length,
          configuredApplications: activeApplications.filter(
            (application) => application.configuration.redirect_uris.length > 0,
          ).length,
          providers: providerItems.length,
          activeProviders: activeProviders.length,
          providerAssignments: activeProviders.reduce(
            (total, provider) =>
              total +
              provider.assigned_application_ids.filter((id) => activeApplicationIds.has(id)).length,
            0,
          ),
          emailAssignments: email.enabled
            ? emailAssignmentItems.filter(
                (assignment) =>
                  assignment.enabled && activeApplicationIds.has(assignment.application_id),
              ).length
            : 0,
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
        description={
          <span className={styles["projectIdentity"]}>
            <span className={styles["projectIdentityLabel"]}>Project ID</span>
            <CopyValue
              value={project.public_id}
              label="Project public ID"
              onCopied={(message) => {
                setMessage(message, "success");
              }}
            />
          </span>
        }
      />
      {project.status !== "active" ? (
        <InlineAlert tone="warning">
          This Project is disabled. Configuration actions are unavailable.
        </InlineAlert>
      ) : null}
      <Section title="Resources" description="Current Project configuration at a glance.">
        {loadState === "loading" ? <LoadingState>Loading project resources</LoadingState> : null}
        {loadState === "failed" ? (
          <InlineAlert tone="danger" role="alert">
            <p>Project resource summaries could not be loaded.</p>
            <Button type="button" onClick={() => void refresh().catch(handleError)}>
              Retry Project resources
            </Button>
          </InlineAlert>
        ) : null}
        {loadState === "ready" && summary !== null ? (
          <ul className={styles["dashboardGrid"]} aria-label="Project resource summary">
            <li>
              <DashboardCard
                title="Applications"
                value={summary.applications}
                detail={`${String(summary.activeApplications)} active · ${String(summary.configuredApplications)} with login URLs`}
                href={`/projects/${project.id}/applications`}
              />
            </li>
            <li>
              <DashboardCard
                title="Identity providers"
                value={summary.providers}
                detail={`${String(summary.activeProviders)} active · ${String(summary.providerAssignments)} Application assignments`}
                href={`/projects/${project.id}/authentication/providers`}
              />
            </li>
            <li>
              <DashboardCard
                title="Passwordless email"
                value={summary.emailAssignments}
                detail="Active Application assignments"
                href={`/projects/${project.id}/authentication/email`}
              />
            </li>
            <li>
              <DashboardCard
                title="Signing keys"
                value={summary.activeSigningKeys}
                detail="Active keys available for token issuance"
                href={`/projects/${project.id}/security/signing-keys`}
              />
            </li>
          </ul>
        ) : null}
      </Section>
    </div>
  );
}

function DashboardCard({
  title,
  value,
  detail,
  href,
}: {
  readonly title: string;
  readonly value: number;
  readonly detail: string;
  readonly href: string;
}) {
  return (
    <Link
      className={styles["dashboardCard"]}
      to={href}
      aria-label={`${title}: ${String(value)}. ${detail}`}
    >
      <span className={styles["dashboardCardHeader"]}>
        <h3>{title}</h3>
        <ArrowRightIcon />
      </span>
      <strong className={styles["dashboardValue"]}>{value}</strong>
      <span className={styles["dashboardDetail"]}>{detail}</span>
    </Link>
  );
}
