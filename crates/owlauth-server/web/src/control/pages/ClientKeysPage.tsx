import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { SyntheticEvent } from "react";
import { Link, useParams } from "react-router";

import { DataTable, EmptyState, PageHeader } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Checkbox, Field, Input } from "../../shared/primitives/Field";
import { Dialog } from "../../shared/primitives/Overlay";
import { useControlConfirmation } from "../app/Confirmation";
import { useControl, useProject } from "../app/ControlContext";
import {
  ControlRequestError,
  type CreateProjectClientKeyResponse,
  IdempotencyAttempt,
  type ProjectClientKey,
  isAmbiguousIdempotencyFailure,
  requireData,
} from "../client";
import styles from "./pages.module.css";

const PAGE_SIZE = 100;

type CopyState = "idle" | "copied" | "failed";

interface ClientKeyInventoryPage {
  readonly items: ProjectClientKey[];
  readonly nextCursor: string | null;
  readonly activeUnacknowledgedKey: ProjectClientKey | null;
}

interface DeliveryAcknowledgement {
  readonly key: ProjectClientKey;
  readonly outcome: "acknowledged" | "revoked";
}

function mergeAuthorityKey(
  items: readonly ProjectClientKey[],
  authority: ProjectClientKey | null,
): ProjectClientKey[] {
  if (authority === null) return [...items];
  const existing = items.findIndex((item) => item.id === authority.id);
  if (existing < 0) return [authority, ...items];
  return items.map((item, index) => (index === existing ? authority : item));
}

function isLifecycleConflict(error: unknown): boolean {
  return (
    error instanceof ControlRequestError &&
    error.status === 409 &&
    (error.code === "revision_conflict" || error.code === "invalid_transition")
  );
}

interface UnresolvedCreate {
  readonly label: string;
  readonly baselineKeyIds: readonly string[];
  readonly implicatedKeyIds: readonly string[];
  readonly inventoryState: "loading" | "ready" | "failed";
}

export function ClientKeysPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, handleError, setMessage } = useControl();
  const confirm = useControlConfirmation();
  const [keys, setKeys] = useState<ProjectClientKey[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [activeUnacknowledgedKey, setActiveUnacknowledgedKey] = useState<ProjectClientKey | null>(
    null,
  );
  const [inventoryState, setInventoryState] = useState<"loading" | "ready" | "failed">("loading");
  const [loadingMore, setLoadingMore] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [revealedKey, setRevealedKey] = useState<ProjectClientKey | null>(null);
  const [revealAcknowledged, setRevealAcknowledged] = useState(false);
  const [copyState, setCopyState] = useState<CopyState>("idle");
  const [unresolvedCreate, setUnresolvedCreate] = useState<UnresolvedCreate | null>(null);
  const [acknowledgingKeyId, setAcknowledgingKeyId] = useState<string | null>(null);
  const [acknowledgementError, setAcknowledgementError] = useState<string | null>(null);
  const credential = useRef("");
  const credentialDisplay = useRef<HTMLElement>(null);
  const createAttempt = useRef(new IdempotencyAttempt());
  const createBaselineKeyIds = useRef<readonly string[]>([]);
  const acknowledgeAttempts = useRef(new Map<string, IdempotencyAttempt>());
  const revokeAttempts = useRef(new Map<string, IdempotencyAttempt>());
  const hasUnacknowledgedActiveKey = activeUnacknowledgedKey !== null;

  function commitUnresolvedCreate(next: UnresolvedCreate | null) {
    setUnresolvedCreate(next);
  }

  const refresh = useCallback(async (): Promise<ClientKeyInventoryPage> => {
    if (project === null) return { items: [], nextCursor: null, activeUnacknowledgedKey: null };
    setInventoryState("loading");
    try {
      const result = await session.client.GET("/v1/projects/{project_id}/client-keys", {
        params: {
          path: { project_id: project.id },
          query: { limit: PAGE_SIZE },
        },
      });
      const page = requireData(result.data, result.error, result.response);
      const authority = page.active_unacknowledged_key;
      const items = mergeAuthorityKey(page.items, authority);
      setKeys(items);
      setNextCursor(page.next_cursor ?? null);
      setActiveUnacknowledgedKey(authority);
      setInventoryState("ready");
      return {
        items,
        nextCursor: page.next_cursor ?? null,
        activeUnacknowledgedKey: authority,
      };
    } catch (error) {
      setInventoryState("failed");
      throw error;
    }
  }, [project, session]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setUnresolvedCreate(null);
      void refresh().catch(handleError);
    }, 0);
    return () => {
      window.clearTimeout(timer);
      credential.current = "";
    };
  }, [handleError, project, refresh]);

  useLayoutEffect(() => {
    const node = credentialDisplay.current;
    if (node === null) return;
    node.textContent = revealedKey === null ? "" : credential.current;
    return () => {
      node.textContent = "";
    };
  }, [revealedKey]);

  async function loadMore() {
    if (project === null || nextCursor === null || loadingMore) return;
    setLoadingMore(true);
    try {
      const result = await session.client.GET("/v1/projects/{project_id}/client-keys", {
        params: {
          path: { project_id: project.id },
          query: { cursor: nextCursor, limit: PAGE_SIZE },
        },
      });
      const page = requireData(result.data, result.error, result.response);
      setKeys((current) => {
        const known = new Set(current.map((key) => key.id));
        const merged = [...current, ...page.items.filter((key) => !known.has(key.id))];
        return mergeAuthorityKey(merged, page.active_unacknowledged_key);
      });
      setActiveUnacknowledgedKey(page.active_unacknowledged_key);
      setNextCursor(page.next_cursor ?? null);
    } catch (error) {
      await handleError(error);
    } finally {
      setLoadingMore(false);
    }
  }

  function openCreate() {
    if (
      project?.status !== "active" ||
      inventoryState !== "ready" ||
      unresolvedCreate !== null ||
      creating
    )
      return;
    if (activeUnacknowledgedKey !== null) {
      setMessage(
        "A client key still has unconfirmed credential storage. Acknowledge its delivery or revoke it before creating another key.",
        "warning",
      );
      return;
    }
    createBaselineKeyIds.current = keys.map((key) => key.id);
    createAttempt.current.abandon();
    setCreateOpen(true);
  }

  function closeCreate() {
    if (creating) return;
    createAttempt.current.abandon();
    createBaselineKeyIds.current = [];
    setCreateOpen(false);
  }

  async function issueKey(
    label: string,
    idempotencyKey: string,
  ): Promise<CreateProjectClientKeyResponse> {
    if (project === null) throw new Error("Project context is unavailable");
    const result = await session.client.POST("/v1/projects/{project_id}/client-keys", {
      params: {
        path: { project_id: project.id },
        header: { "Idempotency-Key": idempotencyKey },
      },
      body: { label },
    });
    return requireData(result.data, result.error, result.response);
  }

  async function getClientKey(keyId: string): Promise<ProjectClientKey> {
    if (project === null) throw new Error("Project context is unavailable");
    const result = await session.client.GET("/v1/projects/{project_id}/client-keys/{key_id}", {
      params: { path: { project_id: project.id, key_id: keyId } },
    });
    return requireData(result.data, result.error, result.response);
  }

  async function presentCreatedKey(created: CreateProjectClientKeyResponse) {
    credential.current = created.credential;
    setRevealedKey(created.key);
    setRevealAcknowledged(false);
    setCopyState("idle");
    setAcknowledgementError(null);
    setCreateOpen(false);
    setMessage(
      "Client key created. Store the one-time credential before leaving this dialog.",
      "success",
    );
    try {
      await refresh();
    } catch (refreshError) {
      await handleError(refreshError);
    }
  }

  async function loadUnresolvedInventory(
    label: string,
    baselineKeyIds: readonly string[],
  ): Promise<boolean> {
    const knownImplicatedKeyIds =
      unresolvedCreate?.label === label ? unresolvedCreate.implicatedKeyIds : [];
    commitUnresolvedCreate({
      label,
      baselineKeyIds,
      implicatedKeyIds: knownImplicatedKeyIds,
      inventoryState: "loading",
    });
    try {
      const page = await refresh();
      const gate = page.activeUnacknowledgedKey;
      const baseline = new Set(baselineKeyIds);
      const newlyImplicated =
        gate !== null && gate.label === label && !baseline.has(gate.id) ? [gate.id] : [];
      const knownStillActive = knownImplicatedKeyIds.filter((id) => gate?.id === id);
      const knownObservations = await Promise.all(
        knownImplicatedKeyIds.map((id) =>
          gate?.id === id ? Promise.resolve(gate) : getClientKey(id),
        ),
      );
      const knownAreAuthoritativelyResolved =
        knownObservations.length > 0 &&
        knownObservations.every(
          (key) => key.status === "revoked" || key.credential_acknowledged_at != null,
        );
      const implicatedKeyIds = [...new Set([...knownStillActive, ...newlyImplicated])];
      if (implicatedKeyIds.length === 0 && knownAreAuthoritativelyResolved) {
        commitUnresolvedCreate(null);
        setMessage(
          "The implicated client-key delivery is resolved and replacement creation is unlocked.",
          "success",
        );
        return true;
      }
      commitUnresolvedCreate({
        label,
        baselineKeyIds,
        implicatedKeyIds,
        inventoryState: "ready",
      });
      setMessage(
        "The authoritative delivery gate was loaded. Replacement creation remains blocked until every newly implicated active key is revoked.",
        "warning",
      );
      return true;
    } catch (refreshError) {
      setInventoryState("failed");
      commitUnresolvedCreate({
        label,
        baselineKeyIds,
        implicatedKeyIds: knownImplicatedKeyIds,
        inventoryState: "failed",
      });
      await handleError(refreshError);
      return false;
    }
  }

  async function blockReplacementAfterUnresolvedCreate(
    label: string,
    baselineKeyIds: readonly string[],
    error: unknown,
  ) {
    credential.current = "";
    setCreateOpen(false);
    const inventoryLoaded = await loadUnresolvedInventory(label, baselineKeyIds);
    const prefix =
      error instanceof ControlRequestError && error.code === "secret_unavailable"
        ? error.message
        : "The create outcome is uncertain and no credential can be recovered.";
    setMessage(
      inventoryLoaded
        ? `${prefix} Creation is blocked until every newly implicated active key is revoked.`
        : `${prefix} The authoritative delivery gate could not be refreshed, so creation remains blocked. Retry the gate before resolving the implicated key.`,
      "warning",
    );
  }

  async function reconcileUncertainCreate(label: string, baselineKeyIds: readonly string[]) {
    const idempotencyKey = createAttempt.current.begin();
    if (idempotencyKey === null) return;
    try {
      const created = await issueKey(label, idempotencyKey);
      createAttempt.current.settle();
      await presentCreatedKey(created);
    } catch (error) {
      createAttempt.current.settle(error);
      createAttempt.current.abandon();
      await blockReplacementAfterUnresolvedCreate(label, baselineKeyIds, error);
    }
  }

  async function createKey(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null || inventoryState !== "ready" || unresolvedCreate !== null) return;
    const fields = new FormData(event.currentTarget);
    const labelValue = fields.get("label");
    const label = typeof labelValue === "string" ? labelValue : "";
    const baselineKeyIds = createBaselineKeyIds.current;
    const idempotencyKey = createAttempt.current.begin();
    if (idempotencyKey === null) return;
    setCreating(true);
    try {
      const created = await issueKey(label, idempotencyKey);
      createAttempt.current.settle();
      await presentCreatedKey(created);
    } catch (error) {
      createAttempt.current.settle(error);
      if (isAmbiguousIdempotencyFailure(error)) {
        // Reconcile exactly once with the retained idempotency identity. This either returns the
        // original successful response when no commit occurred, or identifies the committed safe
        // record as secret_unavailable without pretending the credential can be recovered.
        await reconcileUncertainCreate(label, baselineKeyIds);
      } else if (error instanceof ControlRequestError && error.code === "secret_unavailable") {
        createAttempt.current.abandon();
        await blockReplacementAfterUnresolvedCreate(label, baselineKeyIds, error);
      } else {
        await handleError(error, async () => {
          await refresh();
        });
      }
    } finally {
      setCreating(false);
    }
  }

  async function copyCredential() {
    if (credential.current === "") return;
    try {
      await navigator.clipboard.writeText(credential.current);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  function clearReveal() {
    credential.current = "";
    setRevealedKey(null);
    setRevealAcknowledged(false);
    setCopyState("idle");
    setAcknowledgementError(null);
  }

  function commitObservedKey(observed: ProjectClientKey) {
    setKeys((current) => mergeAuthorityKey(current, observed));
    setActiveUnacknowledgedKey((current) => {
      if (observed.status === "active" && observed.credential_acknowledged_at == null)
        return observed;
      return current?.id === observed.id ? null : current;
    });
    setRevealedKey((current) => (current?.id === observed.id ? observed : current));
  }

  async function acknowledgeDelivery(key: ProjectClientKey): Promise<DeliveryAcknowledgement> {
    if (project === null || key.status !== "active" || key.credential_acknowledged_at != null) {
      throw new Error("Client-key delivery is not awaiting acknowledgement");
    }
    let attempt = acknowledgeAttempts.current.get(key.id);
    if (attempt === undefined) {
      attempt = new IdempotencyAttempt();
      acknowledgeAttempts.current.set(key.id, attempt);
    }
    const idempotencyKey = attempt.begin();
    if (idempotencyKey === null)
      throw new Error("Client-key acknowledgement is already in progress");
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/client-keys/{key_id}/acknowledge",
        {
          params: {
            path: { project_id: project.id, key_id: key.id },
            header: { "Idempotency-Key": idempotencyKey },
          },
          body: { confirm_stored: true, expected_revision: key.revision },
        },
      );
      const acknowledged = requireData(result.data, result.error, result.response);
      attempt.settle();
      acknowledgeAttempts.current.delete(key.id);
      commitObservedKey(acknowledged);
      return { key: acknowledged, outcome: "acknowledged" };
    } catch (error) {
      attempt.settle(error);
      if (isAmbiguousIdempotencyFailure(error) || isLifecycleConflict(error)) {
        try {
          const observed = await getClientKey(key.id);
          commitObservedKey(observed);
          if (observed.status === "revoked" || observed.credential_acknowledged_at != null) {
            attempt.abandon();
            acknowledgeAttempts.current.delete(key.id);
            return {
              key: observed,
              outcome: observed.status === "revoked" ? "revoked" : "acknowledged",
            };
          }
          if (isLifecycleConflict(error) && observed.revision !== key.revision) {
            attempt.abandon();
            acknowledgeAttempts.current.delete(key.id);
          }
        } catch (reconciliationError) {
          if (
            reconciliationError instanceof ControlRequestError &&
            reconciliationError.status === 401
          )
            throw reconciliationError;
          // Preserve the original outcome and idempotency identity when safe metadata is unavailable.
        }
      }
      throw error;
    }
  }

  async function acknowledgeReveal() {
    if (revealedKey === null || !revealAcknowledged || acknowledgingKeyId !== null) return;
    setAcknowledgingKeyId(revealedKey.id);
    setAcknowledgementError(null);
    try {
      const resolution = await acknowledgeDelivery(revealedKey);
      clearReveal();
      setMessage(
        resolution.outcome === "acknowledged"
          ? "Client-key storage was acknowledged and the one-time credential was cleared from the Console page."
          : "This client key was revoked by another operator. Its obsolete credential was cleared from the Console page.",
        resolution.outcome === "acknowledged" ? "success" : "warning",
      );
    } catch (error) {
      if (error instanceof ControlRequestError && error.status === 401) {
        clearReveal();
        await handleError(error);
        return;
      }
      setAcknowledgementError(
        error instanceof ControlRequestError
          ? error.message
          : "Storage acknowledgement could not be confirmed. The credential remains visible; retry without creating another key.",
      );
    } finally {
      setAcknowledgingKeyId(null);
    }
  }

  async function acknowledgeRetainedCredential(key: ProjectClientKey) {
    if (
      project === null ||
      key.credential_acknowledged_at != null ||
      unresolvedCreate?.implicatedKeyIds.includes(key.id) === true
    )
      return;
    const accepted = await confirm({
      title: "Confirm credential storage",
      message: (
        <>
          Confirm only if the one-time credential for <strong>{key.label}</strong> is already stored
          in the customer backend&apos;s secret manager. OwlAuth cannot recover or verify the
          secret. Otherwise, revoke this key.
        </>
      ),
      actionLabel: "Confirm stored credential",
    });
    if (!accepted) return;
    setAcknowledgingKeyId(key.id);
    try {
      const resolution = await acknowledgeDelivery(key);
      setMessage(
        resolution.outcome === "acknowledged"
          ? `Credential storage for ${key.label} was acknowledged.`
          : `Client key ${key.label} was already revoked by another operator.`,
        resolution.outcome === "acknowledged" ? "success" : "warning",
      );
    } catch (error) {
      await handleError(error, async () => {
        await refresh();
      });
    } finally {
      setAcknowledgingKeyId(null);
    }
  }

  async function revokeKey(key: ProjectClientKey) {
    if (project === null || key.status !== "active") return;
    const accepted = await confirm({
      title: "Revoke client key",
      message: (
        <>
          Revoke <strong>{key.label}</strong> ({key.display_prefix}) immediately? Customer backends
          still using this credential will be denied. This action cannot be reversed.
        </>
      ),
      actionLabel: "Revoke client key",
      destructive: true,
    });
    if (!accepted) return;

    let attempt = revokeAttempts.current.get(key.id);
    if (attempt === undefined) {
      attempt = new IdempotencyAttempt();
      revokeAttempts.current.set(key.id, attempt);
    }
    const idempotencyKey = attempt.begin();
    if (idempotencyKey === null) return;
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/client-keys/{key_id}/revoke",
        {
          params: {
            path: { project_id: project.id, key_id: key.id },
            header: { "Idempotency-Key": idempotencyKey },
          },
          body: { confirm: true, expected_revision: key.revision },
        },
      );
      const revoked = requireData(result.data, result.error, result.response);
      attempt.settle();
      revokeAttempts.current.delete(key.id);
      setKeys((current) => current.map((item) => (item.id === key.id ? revoked : item)));
      setActiveUnacknowledgedKey((current) => (current?.id === key.id ? null : current));
      const resolvedImplicatedKey = unresolvedCreate?.implicatedKeyIds.includes(key.id) === true;
      if (resolvedImplicatedKey) {
        // The revision-fenced revoke response is authoritative. Remove the safety gate before the
        // display refresh so a transient read failure cannot resurrect an already-revoked key.
        const remaining = unresolvedCreate.implicatedKeyIds.filter((id) => id !== key.id);
        commitUnresolvedCreate(
          remaining.length === 0 ? null : { ...unresolvedCreate, implicatedKeyIds: remaining },
        );
      }
      await refresh();
      setMessage(
        resolvedImplicatedKey && unresolvedCreate.implicatedKeyIds.length === 1
          ? `Client key ${key.label} was revoked. Replacement creation is unlocked.`
          : `Client key ${key.label} was revoked.`,
        "success",
      );
    } catch (error) {
      attempt.settle(error);
      await handleError(error, async () => {
        await refresh();
      });
    }
  }

  if (project === null) {
    return (
      <EmptyState
        level={1}
        title="Project not found"
        description="Select an existing Project before managing client keys."
        action={<Link to="/">Return to Projects</Link>}
      />
    );
  }

  return (
    <div className={styles["page"]}>
      <PageHeader
        title="Client API keys"
        description="Issue independently revocable credentials for customer backends that call this Project's Client API."
        actions={
          <Button
            type="button"
            variant="primary"
            busy={creating && !createOpen}
            disabled={
              project.status !== "active" ||
              inventoryState !== "ready" ||
              unresolvedCreate !== null ||
              hasUnacknowledgedActiveKey
            }
            onClick={openCreate}
          >
            Create client key
          </Button>
        }
      />
      <InlineAlert tone="info">
        <strong>Rotate with overlap.</strong> Create a replacement, deploy it to the customer
        backend, verify traffic, and only then revoke the predecessor. Client keys never unlock the
        Console and are not browser credentials.
      </InlineAlert>

      {project.status === "active" ? null : (
        <InlineAlert tone="warning">
          Client keys cannot be created while this Project is {project.status}.
        </InlineAlert>
      )}
      {unresolvedCreate === null ? null : (
        <InlineAlert tone="warning" role="alert">
          <p>
            Replacement creation is blocked for the unresolved{" "}
            <strong>{unresolvedCreate.label}</strong> request until its authoritative delivery gate
            is loaded and every newly implicated active key is revoked.
          </p>
          {unresolvedCreate.inventoryState === "loading" ? (
            <p role="status">Loading the client-key delivery gate</p>
          ) : null}
          {unresolvedCreate.inventoryState === "loading" ? null : (
            <Button
              type="button"
              onClick={() =>
                void loadUnresolvedInventory(
                  unresolvedCreate.label,
                  unresolvedCreate.baselineKeyIds,
                )
              }
            >
              Reconcile delivery gate
            </Button>
          )}
          {unresolvedCreate.inventoryState === "ready" &&
          unresolvedCreate.implicatedKeyIds.length === 0 ? (
            <p>
              No newly implicated active key is visible in the authoritative delivery gate. Creation
              remains blocked; refresh the gate and investigate before issuing another credential.
            </p>
          ) : null}
        </InlineAlert>
      )}
      {inventoryState === "loading" ? <p role="status">Loading client keys</p> : null}
      {inventoryState === "failed" ? (
        <InlineAlert tone="danger" role="alert">
          <p>The client-key inventory could not be loaded.</p>
          <Button type="button" onClick={() => void refresh().catch(handleError)}>
            Retry inventory
          </Button>
        </InlineAlert>
      ) : null}
      {inventoryState === "ready" && keys.length === 0 ? (
        <EmptyState
          title="No client keys"
          description="Create a key when a customer backend is ready to use the Project-scoped Client API."
          action={
            <Button
              type="button"
              variant="primary"
              busy={creating && !createOpen}
              disabled={
                project.status !== "active" ||
                unresolvedCreate !== null ||
                hasUnacknowledgedActiveKey
              }
              onClick={openCreate}
            >
              Create client key
            </Button>
          }
        />
      ) : null}
      {keys.length > 0 ? (
        <>
          <DataTable
            caption="Project client keys"
            headings={["Key", "Status", "Created", "Last used", "Revision", "Actions"]}
          >
            {keys.map((key) => (
              <tr key={key.id}>
                <td>
                  <strong>{key.label}</strong>
                  <span className={styles["machineValue"]}>{key.display_prefix}</span>
                  <span className={styles["machineValue"]}>Public ID: {key.public_key_id}</span>
                </td>
                <td>
                  <StatusBadge status={key.status} />
                  {unresolvedCreate?.implicatedKeyIds.includes(key.id) === true ? (
                    <span className={styles["muted"]}>
                      Unresolved create — credential was never revealed; revoke this key
                    </span>
                  ) : key.status === "active" && key.credential_acknowledged_at == null ? (
                    <span className={styles["muted"]}>Storage unconfirmed — creation blocked</span>
                  ) : key.credential_acknowledged_at == null ? null : (
                    <span className={styles["muted"]}>
                      Storage confirmed {readableTime(key.credential_acknowledged_at)}
                    </span>
                  )}
                  {key.revoked_at === null || key.revoked_at === undefined ? null : (
                    <span className={styles["muted"]}>Revoked {readableTime(key.revoked_at)}</span>
                  )}
                </td>
                <td>{readableTime(key.created_at)}</td>
                <td>
                  {key.last_used_at === null || key.last_used_at === undefined
                    ? "Never recorded"
                    : readableTime(key.last_used_at)}
                </td>
                <td>{String(key.revision)}</td>
                <td>
                  {key.status === "active" ? (
                    <div className={styles["actions"]}>
                      {key.credential_acknowledged_at == null &&
                      unresolvedCreate?.implicatedKeyIds.includes(key.id) !== true ? (
                        <Button
                          type="button"
                          busy={acknowledgingKeyId === key.id}
                          onClick={() => void acknowledgeRetainedCredential(key)}
                        >
                          Confirm stored credential
                        </Button>
                      ) : null}
                      <Button type="button" variant="danger" onClick={() => void revokeKey(key)}>
                        {unresolvedCreate?.implicatedKeyIds.includes(key.id) === true
                          ? "Revoke implicated key"
                          : "Revoke"}
                      </Button>
                    </div>
                  ) : (
                    <span className={styles["muted"]}>No actions</span>
                  )}
                </td>
              </tr>
            ))}
          </DataTable>
          {nextCursor === null ? null : (
            <div className={styles["formActions"]}>
              <Button type="button" busy={loadingMore} onClick={() => void loadMore()}>
                Load more keys
              </Button>
            </div>
          )}
        </>
      ) : null}

      <Dialog
        open={createOpen}
        title="Create client key"
        onClose={closeCreate}
        actions={
          <>
            <Button type="button" variant="quiet" disabled={creating} onClick={closeCreate}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" form="create-client-key-form" busy={creating}>
              Create client key
            </Button>
          </>
        }
      >
        <form
          id="create-client-key-form"
          className={styles["form"]}
          onSubmit={(event) => void createKey(event)}
        >
          <Field
            label="Key label"
            htmlFor="client-key-label"
            description="Name the backend or deployment that will hold this credential."
          >
            <Input
              id="client-key-label"
              name="label"
              required
              minLength={1}
              maxLength={64}
              autoComplete="off"
              data-owl-initial-focus
            />
          </Field>
        </form>
      </Dialog>

      <Dialog
        open={revealedKey !== null}
        title="Store this client key now"
        dismissible={false}
        onClose={() => undefined}
        actions={
          <Button
            type="button"
            variant="primary"
            disabled={!revealAcknowledged}
            busy={acknowledgingKeyId === revealedKey?.id}
            onClick={() => void acknowledgeReveal()}
          >
            I saved this key
          </Button>
        }
      >
        <div className={styles["stack"]}>
          <InlineAlert tone="warning" role="alert">
            This credential is shown once. OwlAuth cannot recover it after you acknowledge and close
            this dialog.
          </InlineAlert>
          <div>
            <strong>{revealedKey?.label}</strong>
            <code
              ref={credentialDisplay}
              className={styles["credential"]}
              data-testid="one-time-client-credential"
            />
          </div>
          <div className={styles["actions"]}>
            <Button type="button" onClick={() => void copyCredential()}>
              Copy credential
            </Button>
            <span role="status" aria-live="polite">
              {copyState === "copied"
                ? "Credential copied."
                : copyState === "failed"
                  ? "Copy was unavailable. Select the credential and copy it manually."
                  : ""}
            </span>
          </div>
          {acknowledgementError === null ? null : (
            <InlineAlert tone="danger" role="alert">
              {acknowledgementError}
            </InlineAlert>
          )}
          <Checkbox
            checked={revealAcknowledged}
            onChange={(event) => {
              setRevealAcknowledged(event.target.checked);
            }}
          >
            I stored this credential in the customer backend's secret manager.
          </Checkbox>
        </div>
      </Dialog>
    </div>
  );
}

function readableTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(parsed);
}
