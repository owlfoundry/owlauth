import { useRef } from "react";

import { Button } from "../../shared/primitives/Button";
import { StatusBadge } from "../../shared/primitives/Feedback";
import { useControlConfirmation } from "../app/Confirmation";
import styles from "./features.module.css";
import {
  type DisposableControlClient,
  IdempotencyAttempt,
  type Project,
  type SigningKey,
  requireData,
} from "../client";

interface SigningKeyManagementProps {
  readonly session: DisposableControlClient;
  readonly project: Project;
  readonly keys: SigningKey[];
  readonly onChanged: () => Promise<void>;
  readonly onError: (error: unknown) => Promise<void>;
  readonly setMessage: (message: string | null) => void;
}

export function SigningKeyManagement({
  session,
  project,
  keys,
  onChanged,
  onError,
  setMessage,
}: SigningKeyManagementProps) {
  const confirm = useControlConfirmation();
  const rotationAttempt = useRef(new IdempotencyAttempt());
  const rotationPending = keys.some((key) => ["provisioning", "published"].includes(key.state));

  async function rotate() {
    const idempotencyKey = rotationAttempt.current.begin();
    if (idempotencyKey === null) return;
    try {
      const result = await session.client.POST("/v1/projects/{project_id}/signing-keys/rotate", {
        params: {
          path: { project_id: project.id },
          header: { "Idempotency-Key": idempotencyKey },
        },
        body: { expected_project_revision: project.metadata_revision },
      });
      requireData(result.data, result.error, result.response);
      rotationAttempt.current.settle();
      await onChanged();
      setMessage("Signing key rotation accepted. OwlAuth will activate it automatically.");
    } catch (error) {
      rotationAttempt.current.settle(error);
      await onError(error);
    }
  }

  async function revoke(key: SigningKey) {
    const incomplete = key.state === "provisioning" && key.public_jwk === null;
    if (
      !(await confirm({
        title: incomplete ? "Cancel incomplete rotation" : "Emergency revoke signing key",
        message: incomplete
          ? `Cancel incomplete signing key rotation ${key.kid}?`
          : `Immediately revoke signing key ${key.kid}?`,
        actionLabel: incomplete ? "Cancel rotation" : "Revoke key",
        destructive: true,
      }))
    )
      return;
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/signing-keys/{key_id}/revoke",
        {
          params: { path: { project_id: project.id, key_id: key.id } },
          body: { expected_ring_revision: key.ring_revision },
        },
      );
      requireData(result.data, result.error, result.response);
      await onChanged();
      setMessage(
        incomplete ? "Incomplete signing key rotation cancelled." : "Signing key revoked.",
      );
    } catch (error) {
      await onError(error);
    }
  }

  return (
    <section aria-labelledby="signing-keys-heading">
      <div className={styles["sectionHeader"]}>
        <div>
          <h2 id="signing-keys-heading">Signing keys</h2>
          <p>OwlAuth provisions, publishes, activates, and retires keys automatically.</p>
        </div>
        <Button
          type="button"
          variant="primary"
          onClick={() => void rotate()}
          disabled={project.status !== "active" || rotationPending}
        >
          Rotate signing key
        </Button>
      </div>
      {keys.length === 0 ? (
        <p>Initial signing key setup is pending.</p>
      ) : (
        <ul className={styles["cards"]}>
          {keys.map((key) => (
            <li key={key.id}>
              <strong>{key.kid}</strong> — {key.algorithm} <StatusBadge status={key.state} />
              <div className={styles["actions"]}>
                {!["retired", "revoked", "abandoned"].includes(key.state) ? (
                  <Button variant="danger" type="button" onClick={() => void revoke(key)}>
                    {key.state === "provisioning" && key.public_jwk === null
                      ? "Cancel incomplete rotation"
                      : "Emergency revoke"}
                  </Button>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
