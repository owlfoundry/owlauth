import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router";

import { Timestamp } from "../../shared/compositions/Timestamp";
import { EmptyState, LoadingState } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Field, Input, Select } from "../../shared/primitives/Field";
import { useControlConfirmation } from "../app/Confirmation";
import { safeHostedTarget } from "../safe-target";
import styles from "./features.module.css";
import {
  type Application,
  type ApplicationSession,
  type BrowserSession,
  ControlRequestError,
  type DisposableControlClient,
  IdempotencyAttempt,
  type ManagedProviderConnection,
  type Project,
  type ProjectUser,
  type ProjectUserIdentity,
  type ProjectUserSessions,
  type Provider,
  requireData,
} from "../client";
import { IdentityOperations, validateSafeIdentityInventory } from "./IdentityOperations";

interface UserManagementProps {
  readonly session: DisposableControlClient;
  readonly project: Project;
  readonly applications?: Application[];
  readonly providers?: Provider[];
  readonly initialUserId?: string;
  readonly detailOnly?: boolean;
  readonly onUserSelected?: (userId: string) => void;
  readonly onError: (error: unknown) => Promise<void>;
  readonly setMessage: (message: string | null) => void;
}

type LoadState = "idle" | "loading" | "ready" | "failed";
type UserStatusFilter = "all" | "active" | "disabled" | "merged";
type UserIdentityFilter = "all" | "email" | `provider:${string}`;
type UserSort = "created_newest" | "created_oldest";

const EMPTY_SESSIONS: ProjectUserSessions = {
  application_sessions: [],
  browser_sessions: [],
};

function validateUserSearch(value: string): string | null {
  const maximum = value.includes("@") ? 320 : 128;
  if (Array.from(value).length <= maximum) return null;
  return value.includes("@")
    ? "Exact email lookup is limited to 320 characters."
    : "User prefix search is limited to 128 characters.";
}

export function UserManagement({
  session,
  project,
  applications = [],
  providers = [],
  initialUserId,
  detailOnly = false,
  onUserSelected,
  onError,
  setMessage,
}: UserManagementProps) {
  const confirm = useControlConfirmation();
  const [loadState, setLoadState] = useState<LoadState>("idle");
  const [users, setUsers] = useState<ProjectUser[]>([]);
  const [mergeCandidates, setMergeCandidates] = useState<ProjectUser[]>([]);
  const [mergeNextCursor, setMergeNextCursor] = useState<string | null>(null);
  const [loadingMergeCandidates, setLoadingMergeCandidates] = useState(false);
  const [mergeCandidateError, setMergeCandidateError] = useState(false);
  const [statusFilter, setStatusFilter] = useState<UserStatusFilter>("all");
  const [identityFilter, setIdentityFilter] = useState<UserIdentityFilter>("all");
  const [sort, setSort] = useState<UserSort>("created_newest");
  const [searchDraft, setSearchDraft] = useState("");
  const [search, setSearch] = useState("");
  const [searchError, setSearchError] = useState<string | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [selectedUser, setSelectedUser] = useState<ProjectUser | null>(null);
  const [sessions, setSessions] = useState<ProjectUserSessions | null>(null);
  const [connections, setConnections] = useState<ManagedProviderConnection[] | null>(null);
  const [identities, setIdentities] = useState<ProjectUserIdentity[] | null>(null);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [reauthorizationFallback, setReauthorizationFallback] = useState<string | null>(null);
  const reauthorizationAttempt = useRef(new IdempotencyAttempt());
  const reauthorizationAttemptOwner = useRef<string | null>(null);
  const userListGeneration = useRef(0);
  const userDetailGeneration = useRef(0);
  const mergeCandidateGeneration = useRef(0);
  const loadMoreController = useRef<AbortController | null>(null);
  const mergeLoadMoreController = useRef<AbortController | null>(null);

  const loadUsers = useCallback(
    async (
      preferredUserId?: string,
      cursor?: string,
      append = false,
      signal?: AbortSignal,
      requestGeneration = ++userListGeneration.current,
    ): Promise<ProjectUser | null> => {
      const providerKey = identityFilter.startsWith("provider:")
        ? identityFilter.slice("provider:".length)
        : undefined;
      let page: { items: ProjectUser[]; next_cursor?: string | null };
      if (search.includes("@")) {
        if (append) return null;
        const lookupResult = await session.client.POST("/v1/projects/{project_id}/users/lookup", {
          params: { path: { project_id: project.id } },
          body: { email: search },
          signal: signal ?? null,
        });
        const lookup = requireData(lookupResult.data, lookupResult.error, lookupResult.response);
        const exactUser = lookup.user ?? null;
        let items: ProjectUser[] = exactUser === null ? [] : [exactUser];
        if (statusFilter !== "all") {
          items = items.filter((user) => user.status === statusFilter);
        }
        if (items.length === 1 && identityFilter !== "all") {
          const user = items[0];
          if (user !== undefined) {
            const identityResult = await session.client.GET(
              "/v1/projects/{project_id}/users/{user_id}/identities",
              {
                params: { path: { project_id: project.id, user_id: user.id } },
                signal: signal ?? null,
              },
            );
            const identityPage = requireData(
              identityResult.data,
              identityResult.error,
              identityResult.response,
            );
            const matches = identityPage.items.some(
              (identity) =>
                identity.status === "active" &&
                (identityFilter === "email"
                  ? identity.identity_kind === "email"
                  : identity.identity_kind === "provider" && identity.provider_key === providerKey),
            );
            if (!matches) items = [];
          }
        }
        page = { items, next_cursor: null };
      } else {
        const result = await session.client.GET("/v1/projects/{project_id}/users", {
          params: {
            path: { project_id: project.id },
            query: {
              ...(statusFilter === "all" ? {} : { status: statusFilter }),
              ...(search === "" ? {} : { search }),
              ...(identityFilter === "all"
                ? {}
                : identityFilter === "email"
                  ? { identity_kind: "email" as const }
                  : {
                      identity_kind: "provider" as const,
                      ...(providerKey === undefined ? {} : { provider_key: providerKey }),
                    }),
              sort,
              ...(cursor === undefined ? {} : { cursor }),
              limit: 50,
            },
          },
          signal: signal ?? null,
        });
        page = requireData(result.data, result.error, result.response);
      }
      if (signal?.aborted === true || requestGeneration !== userListGeneration.current) return null;
      setNextCursor(page.next_cursor ?? null);
      setLoadState("ready");
      if (append) {
        setUsers((current) => {
          const merged = new Map(current.map((user) => [user.id, user]));
          for (const user of page.items) merged.set(user.id, user);
          return [...merged.values()];
        });
        return null;
      }
      setUsers(page.items);
      const preferred =
        preferredUserId === undefined
          ? null
          : (page.items.find((user) => user.id === preferredUserId) ?? null);
      setSelectedUser(preferred);
      if (preferred === null) setSessions(EMPTY_SESSIONS);
      return preferred;
    },
    [identityFilter, project.id, search, session, sort, statusFilter],
  );

  const loadMergeCandidates = useCallback(
    async (
      cursor?: string,
      append = false,
      signal?: AbortSignal,
      requestGeneration = ++mergeCandidateGeneration.current,
    ) => {
      const result = await session.client.GET("/v1/projects/{project_id}/users", {
        params: {
          path: { project_id: project.id },
          query: { status: "active", ...(cursor === undefined ? {} : { cursor }), limit: 50 },
        },
        signal: signal ?? null,
      });
      if (signal?.aborted === true || requestGeneration !== mergeCandidateGeneration.current)
        return;
      const page = requireData(result.data, result.error, result.response);
      setMergeCandidateError(false);
      setMergeNextCursor(page.next_cursor ?? null);
      if (append) {
        setMergeCandidates((current) => {
          const merged = new Map(current.map((candidate) => [candidate.id, candidate]));
          for (const candidate of page.items) merged.set(candidate.id, candidate);
          return [...merged.values()];
        });
      } else {
        setMergeCandidates(page.items);
      }
    },
    [project.id, session],
  );

  const loadUser = useCallback(
    async (userId: string, signal?: AbortSignal): Promise<boolean> => {
      const listGeneration = userListGeneration.current;
      const detailGeneration = ++userDetailGeneration.current;
      const isStale = () =>
        signal?.aborted === true ||
        listGeneration !== userListGeneration.current ||
        detailGeneration !== userDetailGeneration.current;
      setPendingAction(`load:${userId}`);
      setIdentities(null);
      try {
        const [userResult, sessionResult, connectionResult, identityResult] = await Promise.all([
          session.client.GET("/v1/projects/{project_id}/users/{user_id}", {
            params: { path: { project_id: project.id, user_id: userId } },
            signal: signal ?? null,
          }),
          session.client.GET("/v1/projects/{project_id}/users/{user_id}/sessions", {
            params: { path: { project_id: project.id, user_id: userId } },
            signal: signal ?? null,
          }),
          session.client.GET(
            "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections",
            {
              params: { path: { project_id: project.id, user_id: userId } },
              signal: signal ?? null,
            },
          ),
          session.client.GET("/v1/projects/{project_id}/users/{user_id}/identities", {
            params: { path: { project_id: project.id, user_id: userId } },
            signal: signal ?? null,
          }),
        ]);
        if (isStale()) return false;
        const user = requireData(userResult.data, userResult.error, userResult.response);
        const nextSessions = requireData(
          sessionResult.data,
          sessionResult.error,
          sessionResult.response,
        );
        setUsers((current) =>
          current.some((item) => item.id === user.id)
            ? current.map((item) => (item.id === user.id ? user : item))
            : [user],
        );
        setSelectedUser(user);
        setSessions(nextSessions);
        setConnections(
          requireData(connectionResult.data, connectionResult.error, connectionResult.response)
            .items,
        );
        const nextIdentities = requireData(
          identityResult.data,
          identityResult.error,
          identityResult.response,
        ).items;
        if (!validateSafeIdentityInventory(nextIdentities)) {
          throw new Error("Unsafe identity inventory response");
        }
        setIdentities(nextIdentities);
        return true;
      } catch (error) {
        if (isStale()) return false;
        if (error instanceof ControlRequestError && error.status === 404) {
          setSelectedUser(null);
          setSessions(EMPTY_SESSIONS);
          setConnections([]);
          setIdentities([]);
          return true;
        }
        await onError(error);
        return false;
      } finally {
        if (detailGeneration === userDetailGeneration.current) setPendingAction(null);
      }
    },
    [onError, project.id, session],
  );

  const beginLoad = useCallback(
    async (signal?: AbortSignal) => {
      loadMoreController.current?.abort();
      loadMoreController.current = null;
      mergeLoadMoreController.current?.abort();
      mergeLoadMoreController.current = null;
      mergeCandidateGeneration.current += 1;
      setMergeCandidates([]);
      setMergeNextCursor(null);
      setLoadingMore(false);
      setLoadingMergeCandidates(false);
      const requestGeneration = ++userListGeneration.current;
      userDetailGeneration.current += 1;
      setPendingAction(null);
      setLoadState("loading");
      setMessage(null);
      try {
        if (detailOnly && initialUserId !== undefined) {
          const candidateController = new AbortController();
          const candidateGeneration = mergeCandidateGeneration.current;
          const abortCandidates = () => {
            candidateController.abort();
          };
          mergeLoadMoreController.current = candidateController;
          if (signal?.aborted === true) candidateController.abort();
          else signal?.addEventListener("abort", abortCandidates, { once: true });
          setMergeCandidateError(false);
          setLoadingMergeCandidates(true);
          void loadMergeCandidates(
            undefined,
            false,
            candidateController.signal,
            candidateGeneration,
          )
            .catch(async (error: unknown) => {
              if (
                !candidateController.signal.aborted &&
                mergeLoadMoreController.current === candidateController &&
                mergeCandidateGeneration.current === candidateGeneration
              ) {
                setMergeCandidateError(true);
                await onError(error);
              }
            })
            .finally(() => {
              signal?.removeEventListener("abort", abortCandidates);
              if (
                mergeLoadMoreController.current === candidateController &&
                mergeCandidateGeneration.current === candidateGeneration
              ) {
                mergeLoadMoreController.current = null;
                setLoadingMergeCandidates(false);
              }
            });
          const loaded = await loadUser(initialUserId, signal);
          if (signal?.aborted !== true) setLoadState(loaded ? "ready" : "failed");
          return;
        }
        const selected = await loadUsers(
          initialUserId,
          undefined,
          false,
          signal,
          requestGeneration,
        );
        if (selected !== null) await loadUser(selected.id, signal);
      } catch (error) {
        if (signal?.aborted !== true) {
          setLoadState("failed");
          await onError(error);
        }
      }
    },
    [detailOnly, initialUserId, loadMergeCandidates, loadUser, loadUsers, onError, setMessage],
  );

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      void beginLoad(controller.signal);
    }, 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [beginLoad]);

  useEffect(
    () => () => {
      loadMoreController.current?.abort();
      mergeLoadMoreController.current?.abort();
    },
    [],
  );

  async function loadMoreUsers() {
    if (nextCursor === null || loadingMore) return;
    const controller = new AbortController();
    loadMoreController.current?.abort();
    loadMoreController.current = controller;
    const requestGeneration = userListGeneration.current;
    setLoadingMore(true);
    try {
      await loadUsers(undefined, nextCursor, true, controller.signal, requestGeneration);
    } catch (error) {
      if (!controller.signal.aborted) await onError(error);
    } finally {
      if (loadMoreController.current === controller) {
        loadMoreController.current = null;
        setLoadingMore(false);
      }
    }
  }

  async function retryMergeCandidates() {
    if (loadingMergeCandidates) return;
    const controller = new AbortController();
    mergeLoadMoreController.current?.abort();
    mergeLoadMoreController.current = controller;
    setMergeCandidates([]);
    setMergeNextCursor(null);
    setLoadingMergeCandidates(true);
    setMergeCandidateError(false);
    try {
      await loadMergeCandidates(undefined, false, controller.signal);
    } catch (error) {
      if (!controller.signal.aborted) {
        setMergeCandidateError(true);
        await onError(error);
      }
    } finally {
      if (mergeLoadMoreController.current === controller) {
        mergeLoadMoreController.current = null;
        setLoadingMergeCandidates(false);
      }
    }
  }

  async function loadMoreMergeCandidates() {
    if (mergeNextCursor === null || loadingMergeCandidates) return;
    const controller = new AbortController();
    mergeLoadMoreController.current?.abort();
    mergeLoadMoreController.current = controller;
    const requestGeneration = mergeCandidateGeneration.current;
    setLoadingMergeCandidates(true);
    try {
      await loadMergeCandidates(mergeNextCursor, true, controller.signal, requestGeneration);
    } catch (error) {
      if (!controller.signal.aborted) {
        setMergeCandidateError(true);
        await onError(error);
      }
    } finally {
      if (mergeLoadMoreController.current === controller) {
        mergeLoadMoreController.current = null;
        setLoadingMergeCandidates(false);
      }
    }
  }

  async function refreshAfterConflict(error: unknown) {
    if (error instanceof ControlRequestError && error.status === 409 && selectedUser !== null) {
      try {
        await loadUser(selectedUser.id);
      } catch (refreshError) {
        await onError(refreshError);
        return;
      }
    }
    await onError(error);
  }

  async function disableSelectedUser() {
    if (selectedUser === null) return;
    const label = selectedUser.display_name ?? selectedUser.public_id;
    if (
      !(await confirm({
        title: "Disable Project user",
        message: `Disable ${label} and block new authentication for this Project user?`,
        actionLabel: "Disable user",
        destructive: true,
      }))
    )
      return;
    setPendingAction(`disable:${selectedUser.id}`);
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/users/{user_id}/disable",
        {
          params: { path: { project_id: project.id, user_id: selectedUser.id } },
          body: { expected_security_revision: selectedUser.security_revision },
        },
      );
      const updated = requireData(result.data, result.error, result.response);
      setUsers((current) => current.map((user) => (user.id === updated.id ? updated : user)));
      setSelectedUser(updated);
      setMessage("Project user disabled.");
    } catch (error) {
      await refreshAfterConflict(error);
    } finally {
      setPendingAction(null);
    }
  }

  async function enableSelectedUser() {
    if (selectedUser?.status !== "disabled") return;
    const label = selectedUser.display_name ?? selectedUser.public_id;
    if (
      !(await confirm({
        title: "Enable Project user",
        message: `Enable ${label} for fresh authentication? Credentials issued before disable remain invalid.`,
        actionLabel: "Enable user",
      }))
    )
      return;
    setPendingAction(`enable:${selectedUser.id}`);
    try {
      const result = await session.client.POST("/v1/projects/{project_id}/users/{user_id}/enable", {
        params: { path: { project_id: project.id, user_id: selectedUser.id } },
        body: { expected_security_revision: selectedUser.security_revision },
      });
      const updated = requireData(result.data, result.error, result.response);
      setUsers((current) => current.map((user) => (user.id === updated.id ? updated : user)));
      setSelectedUser(updated);
      setMessage("Project user enabled for fresh authentication.");
    } catch (error) {
      await refreshAfterConflict(error);
    } finally {
      setPendingAction(null);
    }
  }

  async function revokeApplicationSession(item: ApplicationSession) {
    if (
      !(await confirm({
        title: "Revoke Application session",
        message: `Revoke the session for ${item.application_display_name}?`,
        actionLabel: "Revoke session",
        destructive: true,
      }))
    )
      return;
    setPendingAction(`application:${item.id}`);
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/users/{user_id}/application-sessions/{session_id}/revoke",
        {
          params: {
            path: { project_id: project.id, user_id: item.user_id, session_id: item.id },
          },
          body: { expected_session_revision: item.session_revision },
        },
      );
      const updated = requireData(result.data, result.error, result.response);
      setSessions((current) => ({
        ...(current ?? EMPTY_SESSIONS),
        application_sessions: (current?.application_sessions ?? []).map((sessionItem) =>
          sessionItem.id === updated.id ? updated : sessionItem,
        ),
      }));
      setMessage("Application session revoked.");
    } catch (error) {
      await refreshAfterConflict(error);
    } finally {
      setPendingAction(null);
    }
  }

  async function runConnectionAction(
    item: ManagedProviderConnection,
    action: "synchronize" | "reauthorize" | "revoke" | "disconnect",
    reauthorizationApplicationId?: string,
  ) {
    const destructive = action === "revoke" || action === "disconnect";
    if (
      destructive &&
      !(await confirm({
        title: action === "revoke" ? "Revoke managed credential" : "Disconnect managed connection",
        message:
          action === "revoke"
            ? "Request authoritative provider revocation for this managed connection?"
            : "Disconnect this managed connection and make its credential inaccessible?",
        actionLabel: action === "revoke" ? "Request revocation" : "Disconnect",
        destructive: true,
      }))
    )
      return;
    setPendingAction(`connection:${item.id}:${action}`);
    let reauthorizationPopup: Window | null = null;
    try {
      if (action === "reauthorize") {
        if (
          reauthorizationApplicationId === undefined ||
          !item.reauthorization_application_ids.includes(reauthorizationApplicationId)
        ) {
          throw new Error("Select an eligible Application for this reauthorization.");
        }
        // Reserve a browsing context while this trusted click still has user activation. The
        // create endpoint is intentionally asynchronous and its one-time target is recoverable
        // through the explicit operator link if the popup is denied or cannot be navigated.
        reauthorizationPopup = window.open("about:blank", "_blank");
        if (reauthorizationPopup !== null) reauthorizationPopup.opener = null;
        const attemptOwner = [
          project.id,
          item.user_id,
          item.id,
          String(item.revision),
          String(item.generation),
          String(item.credential_generation),
          reauthorizationApplicationId,
        ].join(":");
        if (
          reauthorizationAttemptOwner.current !== null &&
          reauthorizationAttemptOwner.current !== attemptOwner
        ) {
          reauthorizationAttempt.current.abandon();
        }
        reauthorizationAttemptOwner.current = attemptOwner;
        const idempotencyKey = reauthorizationAttempt.current.begin();
        if (idempotencyKey === null) {
          reauthorizationPopup?.close();
          return;
        }
        setReauthorizationFallback(null);
        const result = await session.client.POST(
          "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/reauthorizations",
          {
            params: {
              path: {
                project_id: project.id,
                user_id: item.user_id,
                connection_id: item.id,
              },
              header: { "Idempotency-Key": idempotencyKey },
            },
            body: {
              application_id: reauthorizationApplicationId,
              expected_connection_revision: item.revision,
              expected_connection_generation: item.generation,
              expected_credential_generation: item.credential_generation,
            },
          },
        );
        const created = requireData(result.data, result.error, result.response);
        reauthorizationAttempt.current.settle();
        reauthorizationAttemptOwner.current = null;
        const hostedTarget = safeHostedTarget(created.hosted_target);
        if (
          created.hosted_target !== null &&
          created.hosted_target !== undefined &&
          hostedTarget === null
        ) {
          throw new Error("Managed reauthorization returned an invalid Hosted target.");
        }
        if (hostedTarget !== null) {
          if (reauthorizationPopup === null) {
            setReauthorizationFallback(hostedTarget);
          } else {
            try {
              reauthorizationPopup.location.replace(hostedTarget);
            } catch {
              reauthorizationPopup.close();
              setReauthorizationFallback(hostedTarget);
            }
          }
        } else {
          reauthorizationPopup?.close();
        }
        setMessage(`Managed reauthorization ${created.status}.`);
        return;
      }
      const result = await session.client.POST(
        `/v1/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/${action}`,
        {
          params: {
            path: {
              project_id: project.id,
              user_id: item.user_id,
              connection_id: item.id,
            },
          },
          body: {
            expected_revision: item.revision,
            expected_generation: item.generation,
            confirm: destructive,
          },
        },
      );
      const updated = requireData(result.data, result.error, result.response);
      setConnections((current) =>
        (current ?? []).map((connection) => (connection.id === updated.id ? updated : connection)),
      );
      setMessage(
        action === "synchronize"
          ? "Managed profile synchronization queued."
          : updated.state === "revoked"
            ? "Managed connection revocation completed by the provider."
            : updated.state === "disconnected"
              ? "Managed connection disconnect completed."
              : action === "revoke"
                ? `Provider revocation queued (${updated.last_safe_outcome}).`
                : `Disconnect queued (${updated.last_safe_outcome}).`,
      );
    } catch (error) {
      reauthorizationPopup?.close();
      if (action === "reauthorize") {
        reauthorizationAttempt.current.settle(error);
        if (!reauthorizationAttempt.current.retainsKey) reauthorizationAttemptOwner.current = null;
      }
      await refreshAfterConflict(error);
    } finally {
      setPendingAction(null);
    }
  }

  async function revokeBrowserSession(item: BrowserSession) {
    if (
      !(await confirm({
        title: "Revoke Project browser session",
        message: "Revoke this browser session and access derived from it?",
        actionLabel: "Revoke session",
        destructive: true,
      }))
    )
      return;
    setPendingAction(`browser:${item.id}`);
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/users/{user_id}/browser-sessions/{session_id}/revoke",
        {
          params: {
            path: { project_id: project.id, user_id: item.user_id, session_id: item.id },
          },
          body: { expected_session_revision: item.session_revision },
        },
      );
      const updated = requireData(result.data, result.error, result.response);
      setSessions((current) => ({
        ...(current ?? EMPTY_SESSIONS),
        browser_sessions: (current?.browser_sessions ?? []).map((sessionItem) =>
          sessionItem.id === updated.id ? updated : sessionItem,
        ),
      }));
      setMessage("Project browser session revoked.");
    } catch (error) {
      await refreshAfterConflict(error);
    } finally {
      setPendingAction(null);
    }
  }

  return (
    <section
      className={detailOnly ? undefined : styles["userInventory"]}
      {...(detailOnly
        ? { "aria-labelledby": "project-users-heading" }
        : { "aria-label": "Project users" })}
    >
      {detailOnly ? (
        <div className={styles["sectionHeader"]}>
          <div>
            <h2 id="project-users-heading">Authority inventory</h2>
            <p>Current user state, sessions, managed connections, and identity provenance.</p>
          </div>
          <Button
            type="button"
            variant="secondary"
            onClick={() => void beginLoad()}
            disabled={loadState === "loading" || loadingMore || pendingAction !== null}
          >
            {loadState === "loading" ? "Loading user" : "Refresh user"}
          </Button>
        </div>
      ) : (
        <form
          className={styles["filterToolbar"]}
          aria-label="Filter Project users"
          onSubmit={(event) => {
            event.preventDefault();
            const candidate = searchDraft.trim();
            const validationError = validateUserSearch(candidate);
            setSearchError(validationError);
            if (validationError === null) setSearch(candidate);
          }}
        >
          <div className={styles["filterFields"]}>
            <div className={styles["searchField"]}>
              <label htmlFor="user-search">Search</label>
              <Input
                id="user-search"
                type="search"
                value={searchDraft}
                placeholder="Name, user ID, or exact email"
                aria-invalid={searchError === null ? undefined : true}
                aria-errormessage={searchError === null ? undefined : "user-search-error"}
                onChange={(event) => {
                  setSearchDraft(event.currentTarget.value);
                  setSearchError(null);
                }}
                disabled={loadState === "loading" || loadingMore || pendingAction !== null}
              />
              {searchError === null ? null : (
                <span id="user-search-error" className={styles["filterError"]} role="alert">
                  {searchError}
                </span>
              )}
            </div>
            <label className={styles["filterField"]} htmlFor="user-status-filter">
              <span>Status</span>
              <Select
                id="user-status-filter"
                value={statusFilter}
                onChange={(event) => {
                  setStatusFilter(event.currentTarget.value as UserStatusFilter);
                }}
                disabled={loadState === "loading" || loadingMore || pendingAction !== null}
              >
                <option value="all">Any status</option>
                <option value="active">Active</option>
                <option value="disabled">Disabled</option>
                <option value="merged">Merged</option>
              </Select>
            </label>
            <label className={styles["filterField"]} htmlFor="user-identity-filter">
              <span>Identity</span>
              <Select
                id="user-identity-filter"
                value={identityFilter}
                onChange={(event) => {
                  setIdentityFilter(event.currentTarget.value as UserIdentityFilter);
                }}
                disabled={loadState === "loading" || loadingMore || pendingAction !== null}
              >
                <option value="all">Any identity</option>
                <option value="email">Email</option>
                {providers.map((provider) => (
                  <option key={provider.id} value={`provider:${provider.provider_key}`}>
                    {provider.display_name}
                  </option>
                ))}
              </Select>
            </label>
            <label className={styles["filterField"]} htmlFor="user-sort">
              <span>Sort</span>
              <Select
                id="user-sort"
                value={sort}
                onChange={(event) => {
                  setSort(event.currentTarget.value as UserSort);
                }}
                disabled={loadState === "loading" || loadingMore || pendingAction !== null}
              >
                <option value="created_newest">Newest first</option>
                <option value="created_oldest">Oldest first</option>
              </Select>
            </label>
          </div>
          <div className={styles["filterActions"]}>
            <Button
              type="submit"
              disabled={loadState === "loading" || loadingMore || pendingAction !== null}
            >
              Search
            </Button>
            {search === "" && statusFilter === "all" && identityFilter === "all" ? null : (
              <Button
                type="button"
                variant="quiet"
                onClick={() => {
                  setSearchDraft("");
                  setSearch("");
                  setSearchError(null);
                  setStatusFilter("all");
                  setIdentityFilter("all");
                }}
                disabled={loadState === "loading" || loadingMore || pendingAction !== null}
              >
                Clear filters
              </Button>
            )}
            <Button
              type="button"
              variant="secondary"
              onClick={() => void beginLoad()}
              disabled={loadState === "loading" || loadingMore || pendingAction !== null}
            >
              {loadState === "loading" ? "Loading users" : "Refresh"}
            </Button>
          </div>
        </form>
      )}

      {loadState === "idle" || loadState === "loading" ? (
        <LoadingState>{detailOnly ? "Loading user authority" : "Loading users"}</LoadingState>
      ) : loadState === "failed" ? (
        <InlineAlert tone="danger" role="alert">
          <p>Project users could not be loaded.</p>
          <Button type="button" variant="secondary" onClick={() => void beginLoad()}>
            Retry users
          </Button>
        </InlineAlert>
      ) : users.length === 0 && !detailOnly ? (
        <EmptyState
          title={
            search === "" && statusFilter === "all" && identityFilter === "all"
              ? "No users yet"
              : "No matching users"
          }
          description={
            search === "" && statusFilter === "all" && identityFilter === "all"
              ? "Users will appear here after they first authenticate with this Project."
              : "No users match the current search and filters. Clear or change the criteria to review the directory."
          }
        />
      ) : detailOnly && selectedUser === null ? (
        <EmptyState
          level={3}
          title="User not found"
          description="The requested user is not available in this Project. Return to the user inventory and select another user."
        />
      ) : (
        <div
          className={
            detailOnly
              ? styles["workspace"]
              : onUserSelected === undefined
                ? styles["userGrid"]
                : styles["userInventory"]
          }
        >
          {detailOnly ? null : (
            <ul className={styles["list"]} aria-label="Project users">
              {users.map((user) => (
                <li key={user.id}>
                  {onUserSelected === undefined ? (
                    <button
                      type="button"
                      aria-pressed={selectedUser?.id === user.id}
                      onClick={() => void loadUser(user.id)}
                      disabled={pendingAction !== null}
                    >
                      <span className={styles["userName"]}>
                        {user.display_name ?? user.public_id}
                      </span>
                      <StatusBadge status={user.status} />
                    </button>
                  ) : (
                    <Link to={`/projects/${project.id}/users/${user.id}`}>
                      <span className={styles["userName"]}>
                        {user.display_name ?? user.public_id}
                      </span>
                      <StatusBadge status={user.status} />
                    </Link>
                  )}
                </li>
              ))}
              {nextCursor === null ? null : (
                <li>
                  <button
                    type="button"
                    disabled={pendingAction !== null || loadingMore}
                    onClick={() => void loadMoreUsers()}
                  >
                    {loadingMore ? "Loading more users" : "Load more users"}
                  </button>
                </li>
              )}
            </ul>
          )}
          {selectedUser === null ? null : (
            <article className={styles["panel"]} aria-labelledby="selected-user-heading">
              <div className={styles["sectionHeader"]}>
                <div>
                  <h3 id="selected-user-heading">
                    {selectedUser.display_name ?? selectedUser.public_id}
                  </h3>
                  <p>
                    User ID: <code>{selectedUser.public_id}</code>
                  </p>
                  <p>Status: {selectedUser.status}</p>
                </div>
                {selectedUser.status === "active" ? (
                  <Button
                    variant="danger"
                    type="button"
                    onClick={() => void disableSelectedUser()}
                    disabled={pendingAction !== null}
                  >
                    Disable Project user
                  </Button>
                ) : selectedUser.status === "disabled" ? (
                  <Button
                    variant="secondary"
                    type="button"
                    onClick={() => void enableSelectedUser()}
                    disabled={pendingAction !== null}
                  >
                    Enable Project user
                  </Button>
                ) : null}
              </div>
              {selectedUser.status === "disabled" ? (
                <p>
                  Existing sessions remain listed for audit history, but they cannot be used.
                  Enabling this user permits only fresh sign-in.
                </p>
              ) : null}
              {pendingAction !== null && !pendingAction.startsWith("load:") ? (
                <p role="status">Applying the requested user authority change…</p>
              ) : null}
              {pendingAction === `load:${selectedUser.id}` || sessions === null ? (
                <p role="status">Loading user sessions…</p>
              ) : (
                <SessionLists
                  sessions={sessions}
                  pendingAction={pendingAction}
                  revokeApplicationSession={revokeApplicationSession}
                  revokeBrowserSession={revokeBrowserSession}
                />
              )}
              {reauthorizationFallback === null ? null : (
                <p role="status">
                  The reauthorization window was blocked.{" "}
                  <a href={reauthorizationFallback} target="_blank" rel="noopener noreferrer">
                    Continue managed reauthorization
                  </a>
                </p>
              )}
              {connections === null ? null : (
                <ManagedConnectionList
                  connections={connections}
                  applications={applications}
                  pendingAction={pendingAction}
                  runAction={runConnectionAction}
                />
              )}
              {loadingMergeCandidates && !mergeCandidateError ? (
                <p role="status">Loading merge candidate inventory…</p>
              ) : null}
              {mergeCandidateError ? (
                <InlineAlert tone="danger" role="alert">
                  <p>
                    The merge candidate inventory could not be refreshed. User details and other
                    identity or session actions remain available.
                  </p>
                  <Button
                    type="button"
                    variant="secondary"
                    disabled={loadingMergeCandidates}
                    onClick={() => void retryMergeCandidates()}
                  >
                    {loadingMergeCandidates
                      ? "Retrying merge candidates"
                      : "Retry merge candidates"}
                  </Button>
                </InlineAlert>
              ) : null}
              {identities === null ? null : (
                <IdentityOperations
                  key={selectedUser.id}
                  session={session}
                  project={project}
                  selectedUser={selectedUser}
                  users={detailOnly ? [selectedUser, ...mergeCandidates] : users}
                  identities={identities}
                  applications={applications}
                  providers={providers}
                  hasMoreUsers={detailOnly ? mergeNextCursor !== null : nextCursor !== null}
                  loadingMoreUsers={detailOnly ? loadingMergeCandidates : loadingMore}
                  loadMoreUsers={detailOnly ? loadMoreMergeCandidates : loadMoreUsers}
                  reloadSelectedUser={async () => {
                    await loadUser(selectedUser.id);
                  }}
                  onError={onError}
                  setMessage={setMessage}
                />
              )}
            </article>
          )}
        </div>
      )}
    </section>
  );
}

interface SessionListsProps {
  readonly sessions: ProjectUserSessions;
  readonly pendingAction: string | null;
  readonly revokeApplicationSession: (session: ApplicationSession) => Promise<void>;
  readonly revokeBrowserSession: (session: BrowserSession) => Promise<void>;
}

function SessionLists({
  sessions,
  pendingAction,
  revokeApplicationSession,
  revokeBrowserSession,
}: SessionListsProps) {
  return (
    <div className={styles["sessionColumns"]}>
      <section aria-labelledby="application-sessions-heading">
        <h4 id="application-sessions-heading">Application sessions</h4>
        {sessions.application_sessions.length === 0 ? (
          <p className={styles["emptyNote"]}>No Application sessions.</p>
        ) : (
          <ul className={styles["cards"]}>
            {sessions.application_sessions.map((session) => (
              <li key={session.id}>
                <strong>{session.application_display_name}</strong>
                <span>Status: {session.status}</span>
                <span>
                  Expires <Timestamp value={session.absolute_expires_at} />
                </span>
                {session.status === "active" ? (
                  <Button
                    variant="danger"
                    type="button"
                    onClick={() => void revokeApplicationSession(session)}
                    disabled={pendingAction !== null}
                  >
                    Revoke Application session
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section aria-labelledby="browser-sessions-heading">
        <h4 id="browser-sessions-heading">Project browser sessions</h4>
        {sessions.browser_sessions.length === 0 ? (
          <p className={styles["emptyNote"]}>No Project browser sessions.</p>
        ) : (
          <ul className={styles["cards"]}>
            {sessions.browser_sessions.map((session) => (
              <li key={session.id}>
                <span>Status: {session.status}</span>
                <span>
                  Last activity <Timestamp value={session.last_activity_at} />
                </span>
                <span>
                  Expires <Timestamp value={session.absolute_expires_at} />
                </span>
                {session.status === "active" ? (
                  <Button
                    variant="danger"
                    type="button"
                    onClick={() => void revokeBrowserSession(session)}
                    disabled={pendingAction !== null}
                  >
                    Revoke Project browser session
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

interface ManagedConnectionListProps {
  readonly connections: ManagedProviderConnection[];
  readonly applications: Application[];
  readonly pendingAction: string | null;
  readonly runAction: (
    connection: ManagedProviderConnection,
    action: "synchronize" | "reauthorize" | "revoke" | "disconnect",
    reauthorizationApplicationId?: string,
  ) => Promise<void>;
}

function ManagedConnectionList({
  connections,
  applications,
  pendingAction,
  runAction,
}: ManagedConnectionListProps) {
  const [reauthorizationApplications, setReauthorizationApplications] = useState<
    Record<string, string>
  >({});
  return (
    <section aria-labelledby="managed-connections-heading">
      <h4 id="managed-connections-heading">Managed provider connections</h4>
      <p>Credentials are never displayed. Actions always use the latest loaded connection state.</p>
      {connections.length === 0 ? (
        <p className={styles["emptyNote"]}>No managed provider connections.</p>
      ) : (
        <ul className={styles["cards"]}>
          {connections.map((connection) => (
            <li key={connection.id}>
              <strong>{connection.capability_key}</strong>
              <span>Status: {connection.state}</span>
              <span>Source schema: {connection.source_schema}</span>
              <span>Required scopes: {connection.required_scopes.join(" ")}</span>
              <span>Last safe outcome: {connection.last_safe_outcome}</span>
              <span>
                Last synchronized:{" "}
                <Timestamp value={connection.last_synchronized_at} empty="never" />; next sync:{" "}
                <Timestamp value={connection.next_synchronize_at} empty="not scheduled" />; next
                renewal: <Timestamp value={connection.next_renewal_at} empty="not scheduled" />;
                failures: {String(connection.consecutive_failures)}
              </span>
              {connection.state === "active" ? (
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => void runAction(connection, "synchronize")}
                  disabled={pendingAction !== null}
                >
                  Synchronize profile
                </Button>
              ) : null}
              {connection.reauthorization_application_ids.length > 0 ? (
                <>
                  <Field
                    label="Reauthorization Application"
                    htmlFor={`reauthorization-application-${connection.id}`}
                  >
                    <Select
                      id={`reauthorization-application-${connection.id}`}
                      value={reauthorizationApplications[connection.id] ?? ""}
                      onChange={(event) => {
                        setReauthorizationApplications((current) => ({
                          ...current,
                          [connection.id]: event.target.value,
                        }));
                      }}
                    >
                      <option value="">Select an eligible Application</option>
                      {applications
                        .filter((application) =>
                          connection.reauthorization_application_ids.includes(application.id),
                        )
                        .map((application) => (
                          <option key={application.id} value={application.id}>
                            {application.display_name}
                          </option>
                        ))}
                    </Select>
                  </Field>
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={() =>
                      void runAction(
                        connection,
                        "reauthorize",
                        reauthorizationApplications[connection.id],
                      )
                    }
                    disabled={
                      pendingAction !== null ||
                      (reauthorizationApplications[connection.id] ?? "") === ""
                    }
                  >
                    Reauthorize with selected Application
                  </Button>
                </>
              ) : null}
              {connection.supports_revocation &&
              connection.state !== "revoked" &&
              connection.state !== "disconnected" ? (
                <Button
                  variant="danger"
                  type="button"
                  onClick={() => void runAction(connection, "revoke")}
                  disabled={pendingAction !== null}
                >
                  Revoke at provider
                </Button>
              ) : null}
              {connection.state !== "disconnected" ? (
                <Button
                  variant="danger"
                  type="button"
                  onClick={() => void runAction(connection, "disconnect")}
                  disabled={pendingAction !== null}
                >
                  Disconnect locally
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
