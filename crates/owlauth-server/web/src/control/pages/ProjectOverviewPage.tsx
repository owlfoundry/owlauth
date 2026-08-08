import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router";

import { CopyValue } from "../../shared/compositions/CopyValue";
import { ArrowRightIcon } from "../../shared/icons/Icons";
import { EmptyState, LoadingState, PageHeader, Section } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert } from "../../shared/primitives/Feedback";
import { useControl, useProject } from "../app/ControlContext";
import { requireData, type ProjectOverviewSummary } from "../client";
import styles from "./pages.module.css";

export function ProjectOverviewPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, handleError, setMessage } = useControl();
  const [summary, setSummary] = useState<ProjectOverviewSummary | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "failed">("loading");

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      if (project === null) return;
      setLoadState("loading");
      try {
        const response = await session.client.GET("/v1/projects/{project_id}/overview", {
          params: { path: { project_id: project.id } },
          signal: signal ?? null,
        });
        const next = requireData(response.data, response.error, response.response);
        if (next.project_id !== project.id) {
          throw new TypeError("Project overview authority mismatch");
        }
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
                value={summary.applications.total}
                detail={`${String(summary.applications.active)} active · ${String(summary.applications.configured)} with login URLs`}
                href={`/projects/${project.id}/applications`}
              />
            </li>
            <li>
              <DashboardCard
                title="Identity providers"
                value={summary.providers.total}
                detail={`${String(summary.providers.active)} active · ${String(summary.providers.active_assignments)} Application assignments`}
                href={`/projects/${project.id}/authentication/providers`}
              />
            </li>
            <li>
              <DashboardCard
                title="Users"
                value={summary.users.total}
                detail={`${String(summary.users.active)} active · ${String(summary.users.disabled)} disabled · ${String(summary.users.merged)} merged`}
                href={`/projects/${project.id}/users`}
              />
            </li>
            <li>
              <DashboardCard
                title="Project secret keys"
                value={summary.project_server_keys.total}
                detail={`${String(summary.project_server_keys.active)} active · ${String(summary.project_server_keys.revoked)} revoked`}
                href={`/projects/${project.id}/security/server-keys`}
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
