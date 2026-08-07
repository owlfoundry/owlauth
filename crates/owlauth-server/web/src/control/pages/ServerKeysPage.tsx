import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { SyntheticEvent } from "react";
import { Link, useParams } from "react-router";

import { CopyValue } from "../../shared/compositions/CopyValue";
import { DataTable, EmptyState, LoadingState, PageHeader } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Checkbox, Field, Input } from "../../shared/primitives/Field";
import { Dialog } from "../../shared/primitives/Overlay";
import { useControlConfirmation } from "../app/Confirmation";
import { useControl, useProject } from "../app/ControlContext";
import {
  ControlRequestError,
  type CreateProjectServerKeyResponse,
  IdempotencyAttempt,
  type ProjectServerKey,
  isAmbiguousIdempotencyFailure,
  requireData,
} from "../client";
import styles from "./pages.module.css";

const PAGE_SIZE = 100;

type CopyState = "idle" | "copied" | "failed";

interface ServerKeyInventoryPage {
  readonly items: ProjectServerKey[];
  readonly nextCursor: string | null;
  readonly activeUnacknowledgedKey: ProjectServerKey | null;
}

interface DeliveryAcknowledgement {
  readonly key: ProjectServerKey;
  readonly outcome: "acknowledged" | "revoked";
}

function mergeAuthorityKey(
  items: readonly ProjectServerKey[],
  authority: ProjectServerKey | null,
): ProjectServerKey[] {
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

export function ServerKeysPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, handleError, setMessage } = useControl();
  const confirm = useControlConfirmation();
  const [keys, setKeys] = useState<ProjectServerKey[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [activeUnacknowledgedKey, setActiveUnacknowledgedKey] = useState<ProjectServerKey | null>(
    null,
  );
  const [inventoryState, setInventoryState] = useState<"loading" | "ready" | "failed">("loading");
  const [loadingMore, setLoadingMore] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [revealedKey, setRevealedKey] = useState<ProjectServerKey | null>(null);
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
  const loadMoreController = useRef<AbortController | null>(null);
  const mounted = useRef(true);
  const hasUnacknowledgedActiveKey = activeUnacknowledgedKey !== null;

  const ownsProject = useCallback(
    (ownerProjectId: string): boolean => mounted.current && project?.id === ownerProjectId,
    [project?.id],
  );

  function commitUnresolvedCreate(next: UnresolvedCreate | null) {
    setUnresolvedCreate(next);
  }

  const refresh = useCallback(
    async (signal?: AbortSignal): Promise<ServerKeyInventoryPage> => {
      if (project === null) return { items: [], nextCursor: null, activeUnacknowledgedKey: null };
      const ownerProjectId = project.id;
      setInventoryState("loading");
      try {
        const result = await session.client.GET("/v1/projects/{project_id}/server-keys", {
          params: {
            path: { project_id: project.id },
            query: { limit: PAGE_SIZE },
          },
          signal: signal ?? null,
        });
        const page = requireData(result.data, result.error, result.response);
        const authority = page.active_unacknowledged_key;
        const items = mergeAuthorityKey(page.items, authority);
        if (signal?.aborted !== true && ownsProject(ownerProjectId)) {
          setKeys(items);
          setNextCursor(page.next_cursor ?? null);
          setActiveUnacknowledgedKey(authority);
          setInventoryState("ready");
        }
        return {
          items,
          nextCursor: page.next_cursor ?? null,
          activeUnacknowledgedKey: authority,
        };
      } catch (error) {
        if (signal?.aborted !== true && ownsProject(ownerProjectId)) setInventoryState("failed");
        throw error;
      }
    },
    [ownsProject, project, session],
  );

  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    const ownedCreateAttempt = createAttempt.current;
    const ownedAcknowledgeAttempts = acknowledgeAttempts.current;
    const ownedRevokeAttempts = revokeAttempts.current;
    const timer = window.setTimeout(() => {
      setUnresolvedCreate(null);
      void refresh(controller.signal).catch((error: unknown) => {
        if (!controller.signal.aborted) void handleError(error);
      });
    }, 0);
    return () => {
      mounted.current = false;
      window.clearTimeout(timer);
      controller.abort();
      loadMoreController.current?.abort();
      loadMoreController.current = null;
      credential.current = "";
      ownedCreateAttempt.abandon();
      ownedAcknowledgeAttempts.clear();
      ownedRevokeAttempts.clear();
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
    const ownerProjectId = project.id;
    const cursor = nextCursor;
    const controller = new AbortController();
    loadMoreController.current?.abort();
    loadMoreController.current = controller;
    setLoadingMore(true);
    try {
      const result = await session.client.GET("/v1/projects/{project_id}/server-keys", {
        params: {
          path: { project_id: ownerProjectId },
          query: { cursor, limit: PAGE_SIZE },
        },
        signal: controller.signal,
      });
      const page = requireData(result.data, result.error, result.response);
      if (controller.signal.aborted || !ownsProject(ownerProjectId)) return;
      setKeys((current) => {
        const known = new Set(current.map((key) => key.id));
        const merged = [...current, ...page.items.filter((key) => !known.has(key.id))];
        return mergeAuthorityKey(merged, page.active_unacknowledged_key);
      });
      setActiveUnacknowledgedKey(page.active_unacknowledged_key);
      setNextCursor(page.next_cursor ?? null);
    } catch (error) {
      if (!controller.signal.aborted && ownsProject(ownerProjectId)) await handleError(error);
    } finally {
      if (loadMoreController.current === controller) loadMoreController.current = null;
      if (ownsProject(ownerProjectId)) setLoadingMore(false);
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
        "A Project secret key still has unconfirmed credential storage. Acknowledge its delivery or revoke it before creating another key.",
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
    ownerProjectId: string,
  ): Promise<CreateProjectServerKeyResponse> {
    const result = await session.client.POST("/v1/projects/{project_id}/server-keys", {
      params: {
        path: { project_id: ownerProjectId },
        header: { "Idempotency-Key": idempotencyKey },
      },
      body: { label },
    });
    return requireData(result.data, result.error, result.response);
  }

  async function getServerKey(
    keyId: string,
    ownerProjectId = project?.id,
  ): Promise<ProjectServerKey> {
    if (ownerProjectId === undefined) throw new Error("Project context is unavailable");
    const result = await session.client.GET("/v1/projects/{project_id}/server-keys/{key_id}", {
      params: { path: { project_id: ownerProjectId, key_id: keyId } },
    });
    return requireData(result.data, result.error, result.response);
  }

  async function presentCreatedKey(
    created: CreateProjectServerKeyResponse,
    ownerProjectId: string,
  ) {
    if (!ownsProject(ownerProjectId)) return;
    credential.current = created.credential;
    setRevealedKey(created.key);
    setRevealAcknowledged(false);
    setCopyState("idle");
    setAcknowledgementError(null);
    setCreateOpen(false);
    setMessage(
      "Project secret key created. Store the one-time credential before leaving this dialog.",
      "success",
    );
    try {
      await refresh();
    } catch (refreshError) {
      if (ownsProject(ownerProjectId)) await handleError(refreshError);
    }
  }

  async function loadUnresolvedInventory(
    label: string,
    baselineKeyIds: readonly string[],
    ownerProjectId = project?.id,
  ): Promise<boolean> {
    if (ownerProjectId === undefined || !ownsProject(ownerProjectId)) return false;
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
      if (!ownsProject(ownerProjectId)) return false;
      const gate = page.activeUnacknowledgedKey;
      const baseline = new Set(baselineKeyIds);
      const newlyImplicated =
        gate !== null && gate.label === label && !baseline.has(gate.id) ? [gate.id] : [];
      const knownStillActive = knownImplicatedKeyIds.filter((id) => gate?.id === id);
      const knownObservations = await Promise.all(
        knownImplicatedKeyIds.map((id) =>
          gate?.id === id ? Promise.resolve(gate) : getServerKey(id, ownerProjectId),
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
          "The implicated Project secret key delivery is resolved and replacement creation is unlocked.",
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
      if (!ownsProject(ownerProjectId)) return false;
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
    ownerProjectId: string,
  ) {
    if (!ownsProject(ownerProjectId)) return;
    credential.current = "";
    setCreateOpen(false);
    const inventoryLoaded = await loadUnresolvedInventory(label, baselineKeyIds, ownerProjectId);
    if (!ownsProject(ownerProjectId)) return;
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

  async function reconcileUncertainCreate(
    label: string,
    baselineKeyIds: readonly string[],
    ownerProjectId: string,
  ) {
    if (!ownsProject(ownerProjectId)) return;
    const idempotencyKey = createAttempt.current.begin();
    if (idempotencyKey === null) return;
    try {
      const created = await issueKey(label, idempotencyKey, ownerProjectId);
      if (!ownsProject(ownerProjectId)) return;
      createAttempt.current.settle();
      await presentCreatedKey(created, ownerProjectId);
    } catch (error) {
      if (!ownsProject(ownerProjectId)) return;
      createAttempt.current.settle(error);
      createAttempt.current.abandon();
      await blockReplacementAfterUnresolvedCreate(label, baselineKeyIds, error, ownerProjectId);
    }
  }

  async function createKey(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null || inventoryState !== "ready" || unresolvedCreate !== null) return;
    const fields = new FormData(event.currentTarget);
    const labelValue = fields.get("label");
    const label = typeof labelValue === "string" ? labelValue : "";
    const ownerProjectId = project.id;
    const baselineKeyIds = createBaselineKeyIds.current;
    const idempotencyKey = createAttempt.current.begin();
    if (idempotencyKey === null) return;
    setCreating(true);
    try {
      const created = await issueKey(label, idempotencyKey, ownerProjectId);
      if (!ownsProject(ownerProjectId)) return;
      createAttempt.current.settle();
      await presentCreatedKey(created, ownerProjectId);
    } catch (error) {
      if (!ownsProject(ownerProjectId)) return;
      createAttempt.current.settle(error);
      if (isAmbiguousIdempotencyFailure(error)) {
        // Reconcile exactly once with the retained idempotency identity. This either returns the
        // original successful response when no commit occurred, or identifies the committed safe
        // record as secret_unavailable without pretending the credential can be recovered.
        await reconcileUncertainCreate(label, baselineKeyIds, ownerProjectId);
      } else if (error instanceof ControlRequestError && error.code === "secret_unavailable") {
        createAttempt.current.abandon();
        await blockReplacementAfterUnresolvedCreate(label, baselineKeyIds, error, ownerProjectId);
      } else {
        await handleError(error, async () => {
          await refresh();
        });
      }
    } finally {
      if (ownsProject(ownerProjectId)) setCreating(false);
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

  function commitObservedKey(observed: ProjectServerKey) {
    setKeys((current) => mergeAuthorityKey(current, observed));
    setActiveUnacknowledgedKey((current) => {
      if (observed.status === "active" && observed.credential_acknowledged_at == null)
        return observed;
      return current?.id === observed.id ? null : current;
    });
    setRevealedKey((current) => (current?.id === observed.id ? observed : current));
  }

  async function acknowledgeDelivery(key: ProjectServerKey): Promise<DeliveryAcknowledgement> {
    if (project === null || key.status !== "active" || key.credential_acknowledged_at != null) {
      throw new Error("Project secret key delivery is not awaiting acknowledgement");
    }
    let attempt = acknowledgeAttempts.current.get(key.id);
    if (attempt === undefined) {
      attempt = new IdempotencyAttempt();
      acknowledgeAttempts.current.set(key.id, attempt);
    }
    const idempotencyKey = attempt.begin();
    if (idempotencyKey === null)
      throw new Error("Project secret key acknowledgement is already in progress");
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/server-keys/{key_id}/acknowledge",
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
          const observed = await getServerKey(key.id);
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
          ? "Project secret key storage was acknowledged and the one-time credential was cleared from the Console page."
          : "This Project secret key was revoked by another operator. Its obsolete credential was cleared from the Console page.",
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

  async function acknowledgeRetainedCredential(key: ProjectServerKey) {
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
          : `Project secret key ${key.label} was already revoked by another operator.`,
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

  async function revokeKey(key: ProjectServerKey) {
    if (project === null || key.status !== "active") return;
    const accepted = await confirm({
      title: "Revoke Project secret key",
      message: (
        <>
          Revoke <strong>{key.label}</strong> ({key.display_prefix}) immediately? Customer backends
          still using this credential will be denied. This action cannot be reversed.
        </>
      ),
      actionLabel: "Revoke Project secret key",
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
        "/v1/projects/{project_id}/server-keys/{key_id}/revoke",
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
          ? `Project secret key ${key.label} was revoked. Replacement creation is unlocked.`
          : `Project secret key ${key.label} was revoked.`,
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
        description="Select an existing Project before managing Project secret keys."
        action={<Link to="/">Return to Projects</Link>}
      />
    );
  }

  return (
    <div className={styles["page"]}>
      <PageHeader
        title="Project secret keys"
        description="Create independently revocable, Project-scoped secret keys for trusted backends calling the OwlAuth Server API."
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
            Create secret key
          </Button>
        }
      />
      <div className={styles["stack"]}>
        <InlineAlert tone="info">
          <strong>Rotate with overlap.</strong> Create a replacement, deploy it to the customer
          backend, verify traffic, and only then revoke the predecessor. Project secret keys never
          unlock the Console and are not browser credentials.
        </InlineAlert>

        {project.status === "active" ? null : (
          <InlineAlert tone="warning">
            Project secret keys cannot be created while this Project is {project.status}.
          </InlineAlert>
        )}
        {unresolvedCreate === null ? null : (
          <InlineAlert tone="warning" role="alert">
            <p>
              Replacement creation is blocked for the unresolved{" "}
              <strong>{unresolvedCreate.label}</strong> request until its authoritative delivery
              gate is loaded and every newly implicated active key is revoked.
            </p>
            {unresolvedCreate.inventoryState === "loading" ? (
              <p role="status">Loading the Project secret key delivery gate</p>
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
                No newly implicated active key is visible in the authoritative delivery gate.
                Creation remains blocked; refresh the gate and investigate before issuing another
                credential.
              </p>
            ) : null}
          </InlineAlert>
        )}
        {inventoryState === "loading" ? (
          <LoadingState>Loading Project secret keys</LoadingState>
        ) : null}
        {inventoryState === "failed" ? (
          <InlineAlert tone="danger" role="alert">
            <p>The Project secret key inventory could not be loaded.</p>
            <Button type="button" onClick={() => void refresh().catch(handleError)}>
              Retry inventory
            </Button>
          </InlineAlert>
        ) : null}
        {inventoryState === "ready" && keys.length === 0 ? (
          <EmptyState
            title="No Project secret keys"
            description="Create a secret key when a trusted backend is ready to use the Project-scoped Server API."
          />
        ) : null}
        {keys.length > 0 ? (
          <>
            <DataTable
              caption="Project secret keys"
              headings={["Key", "Status", "Created", "Last used", "Actions"]}
            >
              {keys.map((key) => (
                <tr key={key.id}>
                  <td>
                    <strong>{key.label}</strong>
                    <span className={styles["machineValue"]}>{key.display_prefix}</span>
                    <CopyValue
                      value={key.public_key_id}
                      label="Project secret key public ID"
                      onCopied={(message) => {
                        setMessage(message, "success");
                      }}
                    />
                  </td>
                  <td>
                    <StatusBadge status={key.status} />
                    {unresolvedCreate?.implicatedKeyIds.includes(key.id) === true ? (
                      <span className={styles["muted"]}>
                        Unresolved create — credential was never revealed; revoke this key
                      </span>
                    ) : key.status === "active" && key.credential_acknowledged_at == null ? (
                      <span className={styles["muted"]}>
                        Storage unconfirmed — creation blocked
                      </span>
                    ) : key.credential_acknowledged_at == null ? null : (
                      <span className={styles["muted"]}>
                        Storage confirmed {readableTime(key.credential_acknowledged_at)}
                      </span>
                    )}
                    {key.revoked_at === null || key.revoked_at === undefined ? null : (
                      <span className={styles["muted"]}>
                        Revoked {readableTime(key.revoked_at)}
                      </span>
                    )}
                  </td>
                  <td>{readableTime(key.created_at)}</td>
                  <td>
                    {key.last_used_at === null || key.last_used_at === undefined
                      ? "Never recorded"
                      : readableTime(key.last_used_at)}
                  </td>
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
      </div>

      <Dialog
        open={createOpen}
        title="Create Project secret key"
        onClose={closeCreate}
        actions={
          <>
            <Button type="button" variant="quiet" disabled={creating} onClick={closeCreate}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" form="create-server-key-form" busy={creating}>
              Create secret key
            </Button>
          </>
        }
      >
        <form
          id="create-server-key-form"
          className={styles["form"]}
          onSubmit={(event) => void createKey(event)}
        >
          <Field
            label="Key label"
            htmlFor="server-key-label"
            description="Name the backend or deployment that will hold this credential."
          >
            <Input
              id="server-key-label"
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
        title="Store this Project secret key now"
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
              data-testid="one-time-server-credential"
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
