import { useRef } from "react";
import type { SyntheticEvent } from "react";

import styles from "./app.module.css";
import {
  type Application,
  type DisposableControlClient,
  IdempotencyAttempt,
  type Project,
  type Provider,
  requireData,
} from "./client";

interface ProviderPanelProps {
  readonly session: DisposableControlClient;
  readonly project: Project;
  readonly applications: Application[];
  readonly providers: Provider[];
  readonly onChanged: () => Promise<void>;
  readonly onError: (error: unknown) => Promise<void>;
  readonly setMessage: (message: string | null) => void;
}

export function ProviderPanel({
  session,
  project,
  applications,
  providers,
  onChanged,
  onError,
  setMessage,
}: ProviderPanelProps) {
  const createAttempt = useRef(new IdempotencyAttempt());

  async function create(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    const idempotencyKey = createAttempt.current.begin();
    if (idempotencyKey === null) return;
    const body = {
      provider_key: fieldText(fields, "provider_key"),
      display_name: fieldText(fields, "display_name"),
      issuer: fieldText(fields, "issuer"),
      client_id: fieldText(fields, "client_id"),
      client_secret: fieldText(fields, "client_secret"),
      expected_project_revision: project.metadata_revision,
    };
    try {
      const result = await session.client.POST("/v1/projects/{project_id}/providers", {
        params: {
          path: { project_id: project.id },
          header: { "Idempotency-Key": idempotencyKey },
        },
        body,
      });
      requireData(result.data, result.error, result.response);
      createAttempt.current.settle();
      body.client_secret = "";
      form.reset();
      await onChanged();
      setMessage("Provider configured; its client secret is write-only.");
    } catch (error) {
      createAttempt.current.settle(error);
      body.client_secret = "";
      if (!createAttempt.current.retainsKey) form.reset();
      await onError(error);
    }
  }

  async function assign(provider: Provider, event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    const application = applications.find(
      (candidate) => candidate.id === fieldText(fields, "application_id"),
    );
    if (application === undefined) return;
    try {
      const result = await session.client.PUT(
        "/v1/projects/{project_id}/providers/{provider_id}/assignments/{application_id}",
        {
          params: {
            path: {
              project_id: project.id,
              provider_id: provider.id,
              application_id: application.id,
            },
          },
          body: { expected_application_revision: application.security_revision },
        },
      );
      requireData(result.data, result.error, result.response);
      await onChanged();
      setMessage("Provider assigned to Application.");
    } catch (error) {
      await onError(error);
    }
  }

  async function unassign(provider: Provider, application: Application) {
    if (!window.confirm(`Remove ${provider.display_name} from ${application.display_name}?`))
      return;
    try {
      const result = await session.client.DELETE(
        "/v1/projects/{project_id}/providers/{provider_id}/assignments/{application_id}",
        {
          params: {
            path: {
              project_id: project.id,
              provider_id: provider.id,
              application_id: application.id,
            },
          },
          body: { expected_application_revision: application.security_revision },
        },
      );
      requireData(result.data, result.error, result.response);
      await onChanged();
      setMessage("Provider unassigned.");
    } catch (error) {
      await onError(error);
    }
  }

  async function disable(provider: Provider) {
    if (!window.confirm(`Disable provider “${provider.display_name}” and its assignments?`)) return;
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/providers/{provider_id}/disable",
        {
          params: { path: { project_id: project.id, provider_id: provider.id } },
          body: { expected_provider_revision: provider.revision },
        },
      );
      requireData(result.data, result.error, result.response);
      await onChanged();
      setMessage("Provider disabled.");
    } catch (error) {
      await onError(error);
    }
  }

  return (
    <section aria-labelledby="providers-heading">
      <h3 id="providers-heading">Identity providers</h3>
      <form className={styles["form"]} onSubmit={(event) => void create(event)}>
        <label htmlFor="provider-key">Provider key</label>
        <input
          id="provider-key"
          name="provider_key"
          required
          pattern="[a-z][a-z0-9_-]*"
          maxLength={64}
        />
        <label htmlFor="provider-name">Display name</label>
        <input id="provider-name" name="display_name" required maxLength={128} />
        <label htmlFor="provider-issuer">Canonical HTTPS issuer</label>
        <input
          id="provider-issuer"
          name="issuer"
          type="url"
          required
          placeholder="Canonical issuer URL"
        />
        <label htmlFor="provider-client-id">Client ID</label>
        <input id="provider-client-id" name="client_id" required maxLength={512} />
        <label htmlFor="provider-client-secret">Client secret (write-only)</label>
        <input
          id="provider-client-secret"
          name="client_secret"
          type="password"
          required
          autoComplete="new-password"
          maxLength={4096}
        />
        <button type="submit" disabled={project.status !== "active"}>
          Configure provider
        </button>
      </form>
      {providers.length === 0 ? (
        <p>No providers.</p>
      ) : (
        <ul className={styles["cards"]}>
          {providers.map((provider) => (
            <li key={provider.id}>
              <div className={styles["sectionHeader"]}>
                <div>
                  <strong>{provider.display_name}</strong> — {provider.status}
                  <p>
                    Key: {provider.provider_key}; callback: <code>{provider.callback_url}</code>
                  </p>
                </div>
                {provider.status === "active" ? (
                  <button
                    className={styles["danger"]}
                    type="button"
                    onClick={() => void disable(provider)}
                  >
                    Disable provider
                  </button>
                ) : null}
              </div>
              {provider.status === "active" &&
              applications.some((app) => app.status === "active") ? (
                <form
                  className={styles["inlineForm"]}
                  onSubmit={(event) => void assign(provider, event)}
                >
                  <label htmlFor={`assignment-${provider.id}`}>Assign to Application</label>
                  <select id={`assignment-${provider.id}`} name="application_id">
                    {applications
                      .filter((application) => application.status === "active")
                      .map((application) => (
                        <option key={application.id} value={application.id}>
                          {application.display_name}
                        </option>
                      ))}
                  </select>
                  <button type="submit">Assign</button>
                </form>
              ) : null}
              <ul>
                {provider.assigned_application_ids.map((applicationId) => {
                  const application = applications.find(
                    (candidate) => candidate.id === applicationId,
                  );
                  return application === undefined ? null : (
                    <li key={applicationId}>
                      {application.display_name}{" "}
                      <button type="button" onClick={() => void unassign(provider, application)}>
                        Unassign
                      </button>
                    </li>
                  );
                })}
              </ul>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function fieldText(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}
