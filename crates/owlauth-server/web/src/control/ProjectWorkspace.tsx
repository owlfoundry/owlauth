import { useCallback, useEffect, useRef, useState } from "react";
import type { SyntheticEvent } from "react";

import styles from "./app.module.css";
import {
  type Application,
  ControlRequestError,
  type DisposableControlClient,
  IdempotencyAttempt,
  type Project,
  type ProjectPolicy,
  type Provider,
  type SigningKey,
  requireData,
} from "./client";
import { ProviderPanel } from "./ProviderPanel";
import { SigningKeyPanel } from "./SigningKeyPanel";
import { UserSessionPanel } from "./UserSessionPanel";

interface ProjectWorkspaceProps {
  readonly session: DisposableControlClient;
  readonly project: Project;
  readonly onError: (error: unknown) => Promise<void>;
  readonly onProjectChanged: (project: Project) => Promise<void>;
  readonly setMessage: (message: string | null) => void;
}

export function ProjectWorkspace({
  session,
  project,
  onError,
  onProjectChanged,
  setMessage,
}: ProjectWorkspaceProps) {
  const [applications, setApplications] = useState<Application[]>([]);
  const [keys, setKeys] = useState<SigningKey[]>([]);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [policy, setPolicy] = useState<ProjectPolicy | null>(null);
  const [selectedApplicationId, setSelectedApplicationId] = useState<string | null>(null);
  const createApplicationAttempt = useRef(new IdempotencyAttempt());

  const refresh = useCallback(async () => {
    const [applicationResult, keyResult, providerResult, policyResult] = await Promise.all([
      session.client.GET("/v1/projects/{project_id}/applications", {
        params: { path: { project_id: project.id } },
      }),
      session.client.GET("/v1/projects/{project_id}/signing-keys", {
        params: { path: { project_id: project.id } },
      }),
      session.client.GET("/v1/projects/{project_id}/providers", {
        params: { path: { project_id: project.id } },
      }),
      session.client.GET("/v1/projects/{project_id}/policy", {
        params: { path: { project_id: project.id } },
      }),
    ]);
    const nextApplications = requireData(
      applicationResult.data,
      applicationResult.error,
      applicationResult.response,
    ).items;
    setApplications(nextApplications);
    setKeys(requireData(keyResult.data, keyResult.error, keyResult.response).items);
    setProviders(
      requireData(providerResult.data, providerResult.error, providerResult.response).items,
    );
    setPolicy(requireData(policyResult.data, policyResult.error, policyResult.response));
    setSelectedApplicationId((current) =>
      current !== null && nextApplications.some((application) => application.id === current)
        ? current
        : (nextApplications[0]?.id ?? null),
    );
  }, [project.id, session]);

  const handleMutationError = useCallback(
    async (error: unknown) => {
      if (error instanceof ControlRequestError && error.status === 409) {
        try {
          await refresh();
        } catch (refreshError) {
          await onError(refreshError);
          return;
        }
      }
      await onError(error);
    },
    [onError, refresh],
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void refresh().catch(onError);
    }, 0);
    return () => {
      window.clearTimeout(timer);
    };
  }, [onError, refresh]);

  async function updateProject(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    try {
      const result = await session.client.PATCH("/v1/projects/{project_id}", {
        params: { path: { project_id: project.id } },
        body: {
          display_name: fieldText(fields, "display_name"),
          belongs_to: fieldText(fields, "belongs_to").trim() || null,
          expected_metadata_revision: project.metadata_revision,
        },
      });
      const updated = requireData(result.data, result.error, result.response);
      await onProjectChanged(updated);
      setMessage("Project metadata updated.");
    } catch (error) {
      await handleMutationError(error);
    }
  }

  async function updatePolicy(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (policy === null) return;
    const fields = new FormData(event.currentTarget);
    try {
      const result = await session.client.PUT("/v1/projects/{project_id}/policy", {
        params: { path: { project_id: project.id } },
        body: {
          access_token_lifetime_seconds: Number(fieldText(fields, "access_token_lifetime_seconds")),
          browser_session_reuse: fields.get("browser_session_reuse") === "on",
          expected_claims_revision: policy.claims_revision,
          expected_session_revision: policy.session_revision,
        },
      });
      setPolicy(requireData(result.data, result.error, result.response));
      setMessage("Project policy updated.");
    } catch (error) {
      await handleMutationError(error);
    }
  }

  async function disableProject() {
    if (!window.confirm(`Disable Project “${project.display_name}”?`)) return;
    try {
      const result = await session.client.POST("/v1/projects/{project_id}/disable", {
        params: { path: { project_id: project.id } },
        body: { expected_security_revision: project.security_revision },
      });
      const updated = requireData(result.data, result.error, result.response);
      await onProjectChanged(updated);
      setMessage("Project disabled.");
    } catch (error) {
      await handleMutationError(error);
    }
  }

  async function createApplication(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    const idempotencyKey = createApplicationAttempt.current.begin();
    if (idempotencyKey === null) return;
    const applicationType = fieldText(fields, "application_type") === "native" ? "native" : "web";
    try {
      const result = await session.client.POST("/v1/projects/{project_id}/applications", {
        params: {
          path: { project_id: project.id },
          header: { "Idempotency-Key": idempotencyKey },
        },
        body: {
          display_name: fieldText(fields, "display_name"),
          application_type: applicationType,
        },
      });
      const created = requireData(result.data, result.error, result.response);
      createApplicationAttempt.current.settle();
      form.reset();
      await refresh();
      setSelectedApplicationId(created.id);
      setMessage("Application created.");
    } catch (error) {
      createApplicationAttempt.current.settle(error);
      await handleMutationError(error);
    }
  }

  const selectedApplication =
    applications.find((application) => application.id === selectedApplicationId) ?? null;

  return (
    <section className={styles["detail"]} aria-labelledby="project-detail-heading">
      <div className={styles["sectionHeader"]}>
        <div>
          <h2 id="project-detail-heading">{project.display_name}</h2>
          <p>
            Public ID: <code>{project.public_id}</code>
          </p>
          <p>
            Status: {project.status}; metadata revision {String(project.metadata_revision)};
            security revision {String(project.security_revision)}
          </p>
        </div>
        {project.status === "active" ? (
          <button className={styles["danger"]} type="button" onClick={() => void disableProject()}>
            Disable Project
          </button>
        ) : null}
      </div>
      <form className={styles["form"]} onSubmit={(event) => void updateProject(event)}>
        <h3>Project metadata</h3>
        <label htmlFor="project-update-name">Display name</label>
        <input
          id="project-update-name"
          name="display_name"
          defaultValue={project.display_name}
          required
          maxLength={128}
          disabled={project.status !== "active"}
        />
        <label htmlFor="project-update-belongs-to">Belongs to</label>
        <input
          id="project-update-belongs-to"
          name="belongs_to"
          defaultValue={project.belongs_to ?? ""}
          maxLength={255}
          disabled={project.status !== "active"}
        />
        <button type="submit" disabled={project.status !== "active"}>
          Update Project
        </button>
      </form>

      {policy === null ? null : (
        <form className={styles["form"]} onSubmit={(event) => void updatePolicy(event)}>
          <h3>Project policy</h3>
          <p>
            Claims revision {String(policy.claims_revision)}; session revision{" "}
            {String(policy.session_revision)}
          </p>
          <label htmlFor="access-token-lifetime">Access token lifetime (seconds)</label>
          <input
            id="access-token-lifetime"
            name="access_token_lifetime_seconds"
            type="number"
            min={60}
            max={3600}
            defaultValue={policy.access_token_lifetime_seconds}
            required
            disabled={project.status !== "active"}
          />
          <label>
            <input
              name="browser_session_reuse"
              type="checkbox"
              defaultChecked={policy.browser_session_reuse}
              disabled={project.status !== "active"}
            />
            Allow explicit browser session reuse confirmation
          </label>
          <button type="submit" disabled={project.status !== "active"}>
            Update Project policy
          </button>
        </form>
      )}

      <section aria-labelledby="applications-heading">
        <h3 id="applications-heading">Applications</h3>
        <form className={styles["form"]} onSubmit={(event) => void createApplication(event)}>
          <label htmlFor="application-name">Display name</label>
          <input
            id="application-name"
            name="display_name"
            required
            maxLength={128}
            disabled={project.status !== "active"}
          />
          <label htmlFor="application-type">Type</label>
          <select
            id="application-type"
            name="application_type"
            defaultValue="web"
            disabled={project.status !== "active"}
          >
            <option value="web">Web</option>
            <option value="native">Native</option>
          </select>
          <button type="submit" disabled={project.status !== "active"}>
            Create Application
          </button>
        </form>
        <ul className={styles["list"]}>
          {applications.map((application) => (
            <li key={application.id}>
              <button
                type="button"
                onClick={() => {
                  setSelectedApplicationId(application.id);
                }}
                aria-pressed={application.id === selectedApplicationId}
              >
                {application.display_name} <span>{application.status}</span>
              </button>
            </li>
          ))}
        </ul>
        {selectedApplication === null ? null : (
          <ApplicationEditor
            key={`${selectedApplication.id}:${String(selectedApplication.metadata_revision)}:${String(selectedApplication.security_revision)}`}
            session={session}
            application={selectedApplication}
            onChanged={refresh}
            onError={handleMutationError}
            setMessage={setMessage}
          />
        )}
      </section>

      <UserSessionPanel
        session={session}
        project={project}
        onError={handleMutationError}
        setMessage={setMessage}
      />
      <SigningKeyPanel
        session={session}
        project={project}
        keys={keys}
        onChanged={refresh}
        onError={handleMutationError}
        setMessage={setMessage}
      />
      <ProviderPanel
        session={session}
        project={project}
        applications={applications}
        providers={providers}
        onChanged={refresh}
        onError={handleMutationError}
        setMessage={setMessage}
      />
    </section>
  );
}

interface ApplicationEditorProps {
  readonly session: DisposableControlClient;
  readonly application: Application;
  readonly onChanged: () => Promise<void>;
  readonly onError: (error: unknown) => Promise<void>;
  readonly setMessage: (message: string | null) => void;
}

function ApplicationEditor({
  session,
  application,
  onChanged,
  onError,
  setMessage,
}: ApplicationEditorProps) {
  async function update(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    try {
      const result = await session.client.PATCH(
        "/v1/projects/{project_id}/applications/{application_id}",
        {
          params: { path: { project_id: application.project_id, application_id: application.id } },
          body: {
            display_name: fieldText(fields, "display_name"),
            expected_metadata_revision: application.metadata_revision,
          },
        },
      );
      requireData(result.data, result.error, result.response);
      await onChanged();
      setMessage("Application metadata updated.");
    } catch (error) {
      await onError(error);
    }
  }

  async function replaceConfiguration(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
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
      await onChanged();
      setMessage("Exact redirect and origin configuration replaced.");
    } catch (error) {
      await onError(error);
    }
  }

  async function disable() {
    if (!window.confirm(`Disable Application “${application.display_name}”?`)) return;
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/applications/{application_id}/disable",
        {
          params: { path: { project_id: application.project_id, application_id: application.id } },
          body: { expected_security_revision: application.security_revision },
        },
      );
      requireData(result.data, result.error, result.response);
      await onChanged();
      setMessage("Application disabled.");
    } catch (error) {
      await onError(error);
    }
  }

  return (
    <article className={styles["panel"]}>
      <div className={styles["sectionHeader"]}>
        <div>
          <h4>{application.display_name}</h4>
          <p>
            Public ID: <code>{application.public_id}</code>
          </p>
        </div>
        {application.status === "active" ? (
          <button className={styles["danger"]} type="button" onClick={() => void disable()}>
            Disable Application
          </button>
        ) : null}
      </div>
      <form className={styles["form"]} onSubmit={(event) => void update(event)}>
        <label htmlFor="application-update-name">Display name</label>
        <input
          id="application-update-name"
          name="display_name"
          defaultValue={application.display_name}
          required
          maxLength={128}
          disabled={application.status !== "active"}
        />
        <button type="submit" disabled={application.status !== "active"}>
          Update Application
        </button>
      </form>
      <form className={styles["form"]} onSubmit={(event) => void replaceConfiguration(event)}>
        <h5>Exact browser configuration</h5>
        <label htmlFor="redirect-uris">Redirect URIs, one per line</label>
        <textarea
          id="redirect-uris"
          name="redirect_uris"
          rows={3}
          defaultValue={application.configuration.redirect_uris.join("\n")}
        />
        <label htmlFor="allowed-origins">Allowed origins, one per line</label>
        <textarea
          id="allowed-origins"
          name="allowed_origins"
          rows={3}
          defaultValue={application.configuration.allowed_origins.join("\n")}
        />
        <button type="submit" disabled={application.status !== "active"}>
          Replace configuration
        </button>
      </form>
      <p>Publishable identifiers: {application.configuration.publishable_keys.join(", ")}</p>
    </article>
  );
}

function fieldText(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}

function lines(fields: FormData, name: string): string[] {
  return fieldText(fields, name)
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
}
