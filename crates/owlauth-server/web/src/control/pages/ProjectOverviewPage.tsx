import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router";

import { DescriptionList, EmptyState, PageHeader, Section } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { useControl, useProject } from "../app/ControlContext";
import { requireData } from "../client";
import styles from "./pages.module.css";

interface Summary {
  applications: number;
  providers: number;
  signingKeys: number;
}

export function ProjectOverviewPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, handleError } = useControl();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "failed">("loading");

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      if (project === null) return;
      setLoadState("loading");
      try {
        const [applications, providers, keys] = await Promise.all([
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
        ]);
        const next = {
          applications: requireData(applications.data, applications.error, applications.response)
            .items.length,
          providers: requireData(providers.data, providers.error, providers.response).items.length,
          signingKeys: requireData(keys.data, keys.error, keys.response).items.length,
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
      <Section title="Project details">
        <DescriptionList
          items={[
            {
              term: "Public ID",
              detail: <span className={styles["machineValue"]}>{project.public_id}</span>,
            },
            { term: "External owner", detail: project.belongs_to ?? "Not set" },
            { term: "Metadata revision", detail: String(project.metadata_revision) },
            { term: "Security revision", detail: String(project.security_revision) },
          ]}
        />
      </Section>
      <Section
        title="Configuration"
        description="These summaries are based only on committed Control API resources."
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
          <div className={styles["grid"]}>
            <SummaryCard
              title="Applications"
              count={summary.applications}
              href={`/projects/${project.id}/applications`}
              action="Configure Applications"
            />
            <SummaryCard
              title="Authentication providers"
              count={summary.providers}
              href={`/projects/${project.id}/authentication/providers`}
              action="Configure providers"
            />
            <SummaryCard
              title="Signing keys"
              count={summary.signingKeys}
              href={`/projects/${project.id}/security/signing-keys`}
              action="Review signing keys"
            />
          </div>
        ) : null}
      </Section>
    </div>
  );
}

function SummaryCard({
  title,
  count,
  href,
  action,
}: {
  readonly title: string;
  readonly count: number;
  readonly href: string;
  readonly action: string;
}) {
  return (
    <article className={styles["summaryCard"]}>
      <h2>{title}</h2>
      <p>{count === 1 ? "1 configured resource" : `${String(count)} configured resources`}</p>
      <p>
        <Link to={href}>{action}</Link>
      </p>
    </article>
  );
}
