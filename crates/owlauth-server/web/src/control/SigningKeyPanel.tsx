import { useRef } from "react";

import styles from "./app.module.css";
import {
  type DisposableControlClient,
  IdempotencyAttempt,
  type Project,
  type SigningKey,
  requireData,
} from "./client";

interface SigningKeyPanelProps {
  readonly session: DisposableControlClient;
  readonly project: Project;
  readonly keys: SigningKey[];
  readonly onChanged: () => Promise<void>;
  readonly onError: (error: unknown) => Promise<void>;
  readonly setMessage: (message: string | null) => void;
}

export function SigningKeyPanel({
  session,
  project,
  keys,
  onChanged,
  onError,
  setMessage,
}: SigningKeyPanelProps) {
  const provisionAttempt = useRef(new IdempotencyAttempt());

  async function provision() {
    const idempotencyKey = provisionAttempt.current.begin();
    if (idempotencyKey === null) return;
    try {
      const result = await session.client.POST("/v1/projects/{project_id}/signing-keys", {
        params: {
          path: { project_id: project.id },
          header: { "Idempotency-Key": idempotencyKey },
        },
        body: { expected_project_revision: project.metadata_revision },
      });
      requireData(result.data, result.error, result.response);
      provisionAttempt.current.settle();
      await onChanged();
      setMessage("Signing key provisioned and published. Load JWKS in Runtime before activation.");
    } catch (error) {
      provisionAttempt.current.settle(error);
      await onError(error);
    }
  }

  async function reconcile(key: SigningKey) {
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/signing-keys/{key_id}/reconcile",
        {
          params: { path: { project_id: project.id, key_id: key.id } },
          body: { expected_project_revision: project.metadata_revision },
        },
      );
      requireData(result.data, result.error, result.response);
      await onChanged();
      setMessage("Signing key provisioning reconciled.");
    } catch (error) {
      await onError(error);
    }
  }

  async function transition(key: SigningKey, operation: "activate" | "retire" | "revoke") {
    const destructive = operation === "revoke" || operation === "retire";
    const description =
      operation === "revoke" && key.state === "provisioning" && key.public_jwk === null
        ? `abandon incomplete signing key ${key.kid}`
        : `${operation} signing key ${key.kid}`;
    if (destructive && !window.confirm(`${description}?`)) return;
    const path =
      operation === "activate"
        ? ("/v1/projects/{project_id}/signing-keys/{key_id}/activate" as const)
        : operation === "retire"
          ? ("/v1/projects/{project_id}/signing-keys/{key_id}/retire" as const)
          : ("/v1/projects/{project_id}/signing-keys/{key_id}/revoke" as const);
    try {
      const result = await session.client.POST(path, {
        params: { path: { project_id: project.id, key_id: key.id } },
        body: { expected_ring_revision: key.ring_revision },
      });
      requireData(result.data, result.error, result.response);
      await onChanged();
      setMessage(`Signing key ${operation} completed.`);
    } catch (error) {
      await onError(error);
    }
  }

  return (
    <section aria-labelledby="signing-keys-heading">
      <div className={styles["sectionHeader"]}>
        <div>
          <h3 id="signing-keys-heading">Signing keys</h3>
          <p>Activation is fenced by Runtime JWKS publication leases.</p>
        </div>
        <button
          type="button"
          onClick={() => void provision()}
          disabled={project.status !== "active"}
        >
          Provision signing key
        </button>
      </div>
      {keys.length === 0 ? (
        <p>No signing keys.</p>
      ) : (
        <ul className={styles["cards"]}>
          {keys.map((key) => (
            <li key={key.id}>
              <strong>{key.kid}</strong> — {key.algorithm}, {key.state}, ring revision{" "}
              {key.ring_revision}
              <div className={styles["actions"]}>
                {key.state === "provisioning" ? (
                  <button type="button" onClick={() => void reconcile(key)}>
                    Resume provisioning
                  </button>
                ) : null}
                {key.state === "published" ? (
                  <button type="button" onClick={() => void transition(key, "activate")}>
                    Activate
                  </button>
                ) : null}
                {key.state === "retiring" ? (
                  <button type="button" onClick={() => void transition(key, "retire")}>
                    Finalize retirement
                  </button>
                ) : null}
                {!["retired", "revoked", "abandoned", "provisioning"].includes(key.state) ? (
                  <button
                    className={styles["danger"]}
                    type="button"
                    onClick={() => void transition(key, "revoke")}
                  >
                    Emergency revoke
                  </button>
                ) : null}
                {key.state === "provisioning" && key.public_jwk === null ? (
                  <button
                    className={styles["danger"]}
                    type="button"
                    onClick={() => void transition(key, "revoke")}
                  >
                    Abandon incomplete key
                  </button>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
