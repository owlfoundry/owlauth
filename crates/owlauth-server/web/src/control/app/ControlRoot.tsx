import { useCallback, useEffect, useRef, useState } from "react";
import { Link, Route, Routes, useNavigate } from "react-router";

import { EmptyState } from "../../shared/layout/Layout";
import { ControlProvider } from "./ControlContext";
import { ControlConfirmationProvider } from "./Confirmation";
import { LockedEntry, VerifiedBootstrapFailure } from "./LockedEntry";
import { WorkspaceShell } from "./WorkspaceShell";
import {
  ControlRequestError,
  type DisposableControlClient,
  type Project,
  requireData,
  verifyControlKey,
} from "../client";
import { ApplicationDetailPage } from "../pages/ApplicationDetailPage";
import { ApplicationsPage } from "../pages/ApplicationsPage";
import { ClientKeysPage } from "../pages/ClientKeysPage";
import { EmailPage } from "../pages/EmailPage";
import { ProjectOverviewPage } from "../pages/ProjectOverviewPage";
import { ProjectsPage } from "../pages/ProjectsPage";
import { ProjectSettingsPage } from "../pages/ProjectSettingsPage";
import { ProvidersPage } from "../pages/ProvidersPage";
import { SigningKeysPage } from "../pages/SigningKeysPage";
import { UserDetailPage } from "../pages/UserDetailPage";
import { UsersPage } from "../pages/UsersPage";
import { readConfiguredBase } from "../../shared/configured-base";

type ConsoleState =
  "locked" | "verifying" | "unlocked" | "denied" | "projects-unavailable" | "retrying-projects";

export function ControlRoot() {
  const [state, setState] = useState<ConsoleState>("locked");
  const [active, setActive] = useState<{
    readonly session: DisposableControlClient;
    readonly projects: readonly Project[];
  } | null>(null);
  const client = useRef<DisposableControlClient | null>(null);
  const verification = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const navigate = useNavigate();

  const lock = useCallback(() => {
    generation.current += 1;
    verification.current?.abort();
    verification.current = null;
    client.current?.dispose();
    client.current = null;
    setActive(null);
    setState("locked");
    void navigate("/", { replace: true });
  }, [navigate]);

  useEffect(() => {
    const clearForLifecycle = () => {
      generation.current += 1;
      verification.current?.abort();
      verification.current = null;
      client.current?.dispose();
      client.current = null;
      setActive(null);
      setState("locked");
    };
    const restoreFromCache = (event: PageTransitionEvent) => {
      if (event.persisted) clearForLifecycle();
    };
    window.addEventListener("pagehide", clearForLifecycle);
    window.addEventListener("pageshow", restoreFromCache);
    return () => {
      window.removeEventListener("pagehide", clearForLifecycle);
      window.removeEventListener("pageshow", restoreFromCache);
      clearForLifecycle();
    };
  }, []);

  async function loadProjectDirectory(
    session: DisposableControlClient,
    attempt: number,
    controller: AbortController,
  ) {
    try {
      const result = await session.client.GET("/v1/projects", { signal: controller.signal });
      const projects = requireData(result.data, result.error, result.response).items;
      if (generation.current !== attempt || controller.signal.aborted) return;
      verification.current = null;
      setActive({ session, projects });
      setState("unlocked");
    } catch (error) {
      if (generation.current !== attempt || controller.signal.aborted) return;
      verification.current = null;
      if (error instanceof ControlRequestError && error.status === 401) {
        session.dispose();
        if (client.current === session) client.current = null;
        setActive(null);
        setState("denied");
        return;
      }
      setActive({ session, projects: [] });
      setState("projects-unavailable");
    }
  }

  function retryProjectDirectory() {
    const session = client.current;
    if (session === null) {
      lock();
      return;
    }
    const attempt = generation.current + 1;
    generation.current = attempt;
    verification.current?.abort();
    const controller = new AbortController();
    verification.current = controller;
    setState("retrying-projects");
    void loadProjectDirectory(session, attempt, controller);
  }

  function unlock(operatorKey: string) {
    const attempt = generation.current + 1;
    generation.current = attempt;
    verification.current?.abort();
    const controller = new AbortController();
    verification.current = controller;
    let submittedKey = operatorKey;
    setState("verifying");
    void (async () => {
      let verified: DisposableControlClient | null = null;
      try {
        verified = await verifyControlKey(
          readConfiguredBase("control"),
          submittedKey,
          fetch,
          controller.signal,
        );
        if (generation.current !== attempt || controller.signal.aborted) {
          verified.dispose();
          return;
        }
        client.current?.dispose();
        client.current = verified;
        setActive({ session: verified, projects: [] });
        const session = verified;
        verified = null;
        await loadProjectDirectory(session, attempt, controller);
      } catch {
        verified?.dispose();
        if (generation.current !== attempt || controller.signal.aborted) return;
        client.current?.dispose();
        client.current = null;
        verification.current = null;
        setActive(null);
        setState("denied");
      } finally {
        submittedKey = "";
      }
    })();
  }

  if ((state === "projects-unavailable" || state === "retrying-projects") && active !== null) {
    return (
      <VerifiedBootstrapFailure
        retrying={state === "retrying-projects"}
        onRetry={retryProjectDirectory}
        onLock={lock}
      />
    );
  }

  if (state !== "unlocked" || active === null) {
    return (
      <LockedEntry
        verifying={state === "verifying"}
        denied={state === "denied"}
        onUnlock={unlock}
      />
    );
  }

  return (
    <ControlProvider session={active.session} initialProjects={active.projects} lock={lock}>
      <ControlConfirmationProvider>
        <Routes>
          <Route element={<WorkspaceShell />}>
            <Route index element={<ProjectsPage />} />
            <Route path="projects/:projectId" element={<ProjectOverviewPage />} />
            <Route path="projects/:projectId/applications" element={<ApplicationsPage />} />
            <Route
              path="projects/:projectId/applications/:applicationId"
              element={<ApplicationDetailPage />}
            />
            <Route
              path="projects/:projectId/authentication/providers"
              element={<ProvidersPage />}
            />
            <Route path="projects/:projectId/authentication/email" element={<EmailPage />} />
            <Route path="projects/:projectId/users" element={<UsersPage />} />
            <Route path="projects/:projectId/users/:userId" element={<UserDetailPage />} />
            <Route path="projects/:projectId/security/signing-keys" element={<SigningKeysPage />} />
            <Route path="projects/:projectId/security/client-keys" element={<ClientKeysPage />} />
            <Route path="projects/:projectId/settings" element={<ProjectSettingsPage />} />
            <Route
              path="*"
              element={
                <EmptyState
                  level={1}
                  title="Page not found"
                  description="This route is not part of the Management Console."
                  action={<Link to="/">Return to Projects</Link>}
                />
              }
            />
          </Route>
        </Routes>
      </ControlConfirmationProvider>
    </ControlProvider>
  );
}
