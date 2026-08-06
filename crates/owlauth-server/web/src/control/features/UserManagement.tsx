import { useCallback, useEffect, useRef, useState } from "react";

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

type LoadState = "idle" | "loading" | "ready";

const EMPTY_SESSIONS: ProjectUserSessions = {
  application_sessions: [],
  browser_sessions: [],
};

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
  const [selectedUser, setSelectedUser] = useState<ProjectUser | null>(null);
  const [sessions, setSessions] = useState<ProjectUserSessions | null>(null);
  const [connections, setConnections] = useState<ManagedProviderConnection[] | null>(null);
  const [identities, setIdentities] = useState<ProjectUserIdentity[] | null>(null);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [reauthorizationFallback, setReauthorizationFallback] = useState<string | null>(null);
  const reauthorizationAttempt = useRef(new IdempotencyAttempt());
  const reauthorizationAttemptOwner = useRef<string | null>(null);

  const loadUsers = useCallback(
    async (preferredUserId?: string): Promise<ProjectUser | null> => {
      const result = await session.client.GET("/v1/projects/{project_id}/users", {
        params: { path: { project_id: project.id } },
      });
      const nextUsers = requireData(result.data, result.error, result.response).items;
      setUsers(nextUsers);
      setLoadState("ready");
      const preferred =
        preferredUserId === undefined
          ? null
          : (nextUsers.find((user) => user.id === preferredUserId) ?? null);
      setSelectedUser(preferred);
      if (preferred === null) setSessions(EMPTY_SESSIONS);
      return preferred;
    },
    [project.id, session],
  );

  const loadUser = useCallback(
    async (userId: string) => {
      setPendingAction(`load:${userId}`);
      setIdentities(null);
      try {
        const [userResult, sessionResult, connectionResult, identityResult] = await Promise.all([
          session.client.GET("/v1/projects/{project_id}/users/{user_id}", {
            params: { path: { project_id: project.id, user_id: userId } },
          }),
          session.client.GET("/v1/projects/{project_id}/users/{user_id}/sessions", {
            params: { path: { project_id: project.id, user_id: userId } },
          }),
          session.client.GET(
            "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections",
            { params: { path: { project_id: project.id, user_id: userId } } },
          ),
          session.client.GET("/v1/projects/{project_id}/users/{user_id}/identities", {
            params: { path: { project_id: project.id, user_id: userId } },
          }),
        ]);
        const user = requireData(userResult.data, userResult.error, userResult.response);
        const nextSessions = requireData(
          sessionResult.data,
          sessionResult.error,
          sessionResult.response,
        );
        setUsers((current) => current.map((item) => (item.id === user.id ? user : item)));
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
      } catch (error) {
        await onError(error);
      } finally {
        setPendingAction(null);
      }
    },
    [onError, project.id, session],
  );

  const beginLoad = useCallback(async () => {
    setLoadState("loading");
    setMessage(null);
    try {
      const selected = await loadUsers(initialUserId);
      if (selected !== null) await loadUser(selected.id);
    } catch (error) {
      setLoadState("idle");
      await onError(error);
    }
  }, [initialUserId, loadUser, loadUsers, onError, setMessage]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void beginLoad();
    }, 0);
    return () => {
      window.clearTimeout(timer);
    };
  }, [beginLoad]);

  async function refreshAfterConflict(error: unknown) {
    if (error instanceof ControlRequestError && error.status === 409 && selectedUser !== null) {
      try {
        const current = await loadUsers(selectedUser.id);
        if (current !== null) await loadUser(current.id);
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
        setMessage(
          `Managed reauthorization ${created.status}; revision ${String(created.revision)}.`,
        );
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
    <section aria-labelledby="project-users-heading">
      <div className={styles["sectionHeader"]}>
        <div>
          <h2 id="project-users-heading">
            {detailOnly ? "User authority and sessions" : "Project users"}
          </h2>
          <p>
            {detailOnly
              ? "Inspect bounded user provenance and perform exact session, connection, and identity operations."
              : "Select one bounded Project user to review its authority on a dedicated detail page."}
          </p>
        </div>
        <button type="button" onClick={() => void beginLoad()} disabled={loadState === "loading"}>
          {loadState === "loading" ? "Loading users" : "Refresh users"}
        </button>
      </div>

      {loadState === "idle" ? (
        <p>User records are loaded only when requested.</p>
      ) : loadState === "loading" ? (
        <p role="status">Loading Project users…</p>
      ) : users.length === 0 ? (
        <p>No Project users yet.</p>
      ) : detailOnly && selectedUser === null ? (
        <p>The requested Project user was not found.</p>
      ) : (
        <div className={detailOnly ? styles["workspace"] : styles["userGrid"]}>
          {detailOnly ? null : (
            <ul className={styles["list"]} aria-label="Project users">
              {users.map((user) => (
                <li key={user.id}>
                  <button
                    type="button"
                    aria-pressed={selectedUser?.id === user.id}
                    onClick={() => {
                      if (onUserSelected === undefined) void loadUser(user.id);
                      else onUserSelected(user.id);
                    }}
                    disabled={pendingAction !== null}
                  >
                    {user.display_name ?? user.public_id} <span>{user.status}</span>
                  </button>
                </li>
              ))}
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
                  <p>
                    Status: {selectedUser.status}; user revision{" "}
                    {String(selectedUser.user_revision)}; security revision{" "}
                    {String(selectedUser.security_revision)}
                  </p>
                </div>
                {selectedUser.status === "active" ? (
                  <button
                    className={styles["danger"]}
                    type="button"
                    onClick={() => void disableSelectedUser()}
                    disabled={pendingAction !== null}
                  >
                    Disable Project user
                  </button>
                ) : null}
              </div>
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
              {identities === null ? null : (
                <IdentityOperations
                  key={selectedUser.id}
                  session={session}
                  project={project}
                  selectedUser={selectedUser}
                  users={users}
                  identities={identities}
                  applications={applications}
                  providers={providers}
                  reloadSelectedUser={() => loadUser(selectedUser.id)}
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
          <p>No Application sessions.</p>
        ) : (
          <ul className={styles["cards"]}>
            {sessions.application_sessions.map((session) => (
              <li key={session.id}>
                <strong>{session.application_display_name}</strong>
                <span>
                  {session.status}; revision {String(session.session_revision)}
                </span>
                <span>Expires {session.absolute_expires_at}</span>
                {session.status === "active" ? (
                  <button
                    className={styles["danger"]}
                    type="button"
                    onClick={() => void revokeApplicationSession(session)}
                    disabled={pendingAction !== null}
                  >
                    Revoke Application session
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section aria-labelledby="browser-sessions-heading">
        <h4 id="browser-sessions-heading">Project browser sessions</h4>
        {sessions.browser_sessions.length === 0 ? (
          <p>No Project browser sessions.</p>
        ) : (
          <ul className={styles["cards"]}>
            {sessions.browser_sessions.map((session) => (
              <li key={session.id}>
                <span>
                  {session.status}; revision {String(session.session_revision)}
                </span>
                <span>Last activity {session.last_activity_at}</span>
                <span>Expires {session.absolute_expires_at}</span>
                {session.status === "active" ? (
                  <button
                    className={styles["danger"]}
                    type="button"
                    onClick={() => void revokeBrowserSession(session)}
                    disabled={pendingAction !== null}
                  >
                    Revoke Project browser session
                  </button>
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
      <p>
        Credentials are never displayed. Actions are bound to the shown revision and generation.
      </p>
      {connections.length === 0 ? (
        <p>No managed provider connections.</p>
      ) : (
        <ul className={styles["cards"]}>
          {connections.map((connection) => (
            <li key={connection.id}>
              <strong>{connection.capability_key}</strong>
              <span>
                {connection.state}; revision {String(connection.revision)}; generation{" "}
                {String(connection.generation)}; credential generation{" "}
                {String(connection.credential_generation)}
              </span>
              <span>Source schema: {connection.source_schema}</span>
              <span>Required scopes: {connection.required_scopes.join(" ")}</span>
              <span>Last safe outcome: {connection.last_safe_outcome}</span>
              <span>
                Last synchronized: {connection.last_synchronized_at ?? "never"}; next sync:{" "}
                {connection.next_synchronize_at ?? "not scheduled"}; next renewal:{" "}
                {connection.next_renewal_at ?? "not scheduled"}; failures:{" "}
                {String(connection.consecutive_failures)}
              </span>
              {connection.state === "active" ? (
                <button
                  type="button"
                  onClick={() => void runAction(connection, "synchronize")}
                  disabled={pendingAction !== null}
                >
                  Synchronize profile
                </button>
              ) : null}
              {connection.reauthorization_application_ids.length > 0 ? (
                <>
                  <label htmlFor={`reauthorization-application-${connection.id}`}>
                    Reauthorization Application
                  </label>
                  <select
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
                  </select>
                  <button
                    type="button"
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
                  </button>
                </>
              ) : null}
              {connection.supports_revocation &&
              connection.state !== "revoked" &&
              connection.state !== "disconnected" ? (
                <button
                  className={styles["danger"]}
                  type="button"
                  onClick={() => void runAction(connection, "revoke")}
                  disabled={pendingAction !== null}
                >
                  Revoke at provider
                </button>
              ) : null}
              {connection.state !== "disconnected" ? (
                <button
                  className={styles["danger"]}
                  type="button"
                  onClick={() => void runAction(connection, "disconnect")}
                  disabled={pendingAction !== null}
                >
                  Disconnect locally
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
