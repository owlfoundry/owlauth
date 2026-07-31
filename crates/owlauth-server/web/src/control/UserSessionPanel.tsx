import { useCallback, useState } from "react";

import styles from "./app.module.css";
import {
  type ApplicationSession,
  type BrowserSession,
  ControlRequestError,
  type DisposableControlClient,
  type Project,
  type ProjectUser,
  type ProjectUserSessions,
  requireData,
} from "./client";

interface UserSessionPanelProps {
  readonly session: DisposableControlClient;
  readonly project: Project;
  readonly onError: (error: unknown) => Promise<void>;
  readonly setMessage: (message: string | null) => void;
}

type LoadState = "idle" | "loading" | "ready";

const EMPTY_SESSIONS: ProjectUserSessions = {
  application_sessions: [],
  browser_sessions: [],
};

export function UserSessionPanel({ session, project, onError, setMessage }: UserSessionPanelProps) {
  const [loadState, setLoadState] = useState<LoadState>("idle");
  const [users, setUsers] = useState<ProjectUser[]>([]);
  const [selectedUser, setSelectedUser] = useState<ProjectUser | null>(null);
  const [sessions, setSessions] = useState<ProjectUserSessions | null>(null);
  const [pendingAction, setPendingAction] = useState<string | null>(null);

  const loadUsers = useCallback(
    async (preferredUserId?: string): Promise<ProjectUser | null> => {
      const result = await session.client.GET("/v1/projects/{project_id}/users", {
        params: { path: { project_id: project.id } },
      });
      const nextUsers = requireData(result.data, result.error, result.response).items;
      setUsers(nextUsers);
      setLoadState("ready");
      const preferred =
        nextUsers.find((user) => user.id === preferredUserId) ?? nextUsers.at(0) ?? null;
      setSelectedUser(preferred);
      if (preferred === null) setSessions(EMPTY_SESSIONS);
      return preferred;
    },
    [project.id, session],
  );

  const loadUser = useCallback(
    async (userId: string) => {
      setPendingAction(`load:${userId}`);
      try {
        const [userResult, sessionResult] = await Promise.all([
          session.client.GET("/v1/projects/{project_id}/users/{user_id}", {
            params: { path: { project_id: project.id, user_id: userId } },
          }),
          session.client.GET("/v1/projects/{project_id}/users/{user_id}/sessions", {
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
      } catch (error) {
        await onError(error);
      } finally {
        setPendingAction(null);
      }
    },
    [onError, project.id, session],
  );

  async function beginLoad() {
    setLoadState("loading");
    setMessage(null);
    try {
      const first = await loadUsers(selectedUser?.id);
      if (first !== null) await loadUser(first.id);
    } catch (error) {
      setLoadState("idle");
      await onError(error);
    }
  }

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
    if (!window.confirm(`Disable Project user “${label}”?`)) return;
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
    if (!window.confirm(`Revoke the Application session for “${item.application_display_name}”?`)) {
      return;
    }
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

  async function revokeBrowserSession(item: BrowserSession) {
    if (!window.confirm("Revoke this Project browser session and its derived access?")) return;
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
          <h3 id="project-users-heading">Project users and sessions</h3>
          <p>Inspect bounded user metadata and revoke exact sessions.</p>
        </div>
        <button type="button" onClick={() => void beginLoad()} disabled={loadState === "loading"}>
          {loadState === "loading" ? "Loading users…" : "Load Project users"}
        </button>
      </div>

      {loadState === "idle" ? (
        <p>User records are loaded only when requested.</p>
      ) : loadState === "loading" ? (
        <p role="status">Loading Project users…</p>
      ) : users.length === 0 ? (
        <p>No Project users yet.</p>
      ) : (
        <div className={styles["userGrid"]}>
          <ul className={styles["list"]} aria-label="Project users">
            {users.map((user) => (
              <li key={user.id}>
                <button
                  type="button"
                  aria-pressed={selectedUser?.id === user.id}
                  onClick={() => void loadUser(user.id)}
                  disabled={pendingAction !== null}
                >
                  {user.display_name ?? user.public_id} <span>{user.status}</span>
                </button>
              </li>
            ))}
          </ul>
          {selectedUser === null ? null : (
            <article className={styles["panel"]} aria-labelledby="selected-user-heading">
              <div className={styles["sectionHeader"]}>
                <div>
                  <h4 id="selected-user-heading">
                    {selectedUser.display_name ?? selectedUser.public_id}
                  </h4>
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
        <h5 id="application-sessions-heading">Application sessions</h5>
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
        <h5 id="browser-sessions-heading">Project browser sessions</h5>
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
