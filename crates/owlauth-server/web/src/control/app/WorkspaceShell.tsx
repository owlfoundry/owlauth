import { useEffect, useId, useLayoutEffect, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation, useParams } from "react-router";

import { CopyButton } from "../../shared/compositions/CopyValue";
import { ArrowLeftIcon } from "../../shared/icons/Icons";
import { Breadcrumbs } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { NotificationRegion, ToastRegion } from "../../shared/primitives/Feedback";
import { SideSheet } from "../../shared/primitives/Overlay";
import { useControl, useProject } from "./ControlContext";
import styles from "./control-shell.module.css";
import { OwlAuthWordmark } from "./LockedEntry";

export function WorkspaceShell() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { message, messageTone, toasts, dismissToast, clearFeedback, lock } = useControl();
  const [navigationOpen, setNavigationOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    clearFeedback();
  }, [clearFeedback, location.key]);

  useLayoutEffect(() => {
    document.querySelector<HTMLElement>("#console-main h1")?.focus();
  }, [location.pathname]);

  const navigation = (
    <Navigation
      project={project}
      onNavigate={() => {
        setNavigationOpen(false);
      }}
    />
  );
  const section = currentSection(location.pathname, projectId);

  return (
    <div className={styles["workspace"]}>
      <a className={styles["skipLink"]} href="#console-main">
        Skip to main content
      </a>
      <aside className={styles["sidebar"]} aria-label="Console navigation">
        <OwlAuthWordmark />
        {navigation}
        <ConsoleLockAction onLock={lock} />
      </aside>
      <header className={styles["topbar"]}>
        <span className={styles["menuButton"]}>
          <Button
            type="button"
            variant="quiet"
            iconOnly
            aria-label="Open navigation"
            aria-expanded={navigationOpen}
            onClick={() => {
              setNavigationOpen(true);
            }}
          >
            <MenuIcon />
          </Button>
        </span>
        <Breadcrumbs>
          {project === null ? (
            <li aria-current="page">Projects</li>
          ) : (
            <>
              <li>
                <NavLink to="/">Projects</NavLink>
              </li>
              {section === "Overview" ? (
                <li aria-current="page">{project.display_name}</li>
              ) : (
                <>
                  <li>
                    <NavLink to={`/projects/${project.id}`}>{project.display_name}</NavLink>
                  </li>
                  <li aria-current="page">{section}</li>
                </>
              )}
            </>
          )}
        </Breadcrumbs>
        <span className={styles["mobileOnly"]}>
          <Button type="button" variant="quiet" onClick={lock}>
            Exit
          </Button>
        </span>
      </header>
      <main id="console-main" className={styles["main"]}>
        <NotificationRegion message={message} tone={messageTone} />
        <Outlet />
      </main>
      <ToastRegion toasts={toasts} onDismiss={dismissToast} />
      <SideSheet
        open={navigationOpen}
        title="Console navigation"
        onClose={() => {
          setNavigationOpen(false);
        }}
      >
        {navigation}
        <ConsoleLockAction onLock={lock} />
      </SideSheet>
    </div>
  );
}

function Navigation({
  project,
  onNavigate,
}: {
  readonly project: {
    readonly id: string;
    readonly display_name: string;
    readonly status: "active" | "disabled" | "deleting";
  } | null;
  readonly onNavigate: () => void;
}) {
  const base = project === null || project.status === "deleting" ? null : `/projects/${project.id}`;
  const navigationId = useId();
  return (
    <nav className={styles["navigation"]} aria-label="Resources">
      <div className={styles["workspaceNavigation"]} role="group" aria-label="Workspace">
        {project === null ? null : (
          <ConsoleNavLink to="/" end onNavigate={onNavigate}>
            <ArrowLeftIcon />
            Back to projects
          </ConsoleNavLink>
        )}
        {project === null ? null : (
          <div className={styles["currentProject"]} role="group" aria-label="Current project">
            <strong title={project.display_name}>{project.display_name}</strong>
            <CopyButton value={project.id} label="Project ID">
              Copy ID
            </CopyButton>
          </div>
        )}
      </div>
      {base === null || project === null ? null : (
        <>
          <div
            className={styles["navigationGroup"]}
            role="group"
            aria-labelledby={`${navigationId}-project`}
          >
            <span id={`${navigationId}-project`} className={styles["navigationLabel"]}>
              Project
            </span>
            <ConsoleNavLink to={base} end onNavigate={onNavigate}>
              Overview
            </ConsoleNavLink>
            <ConsoleNavLink to={`${base}/applications`} onNavigate={onNavigate}>
              Applications
            </ConsoleNavLink>
          </div>
          <div
            className={styles["navigationGroup"]}
            role="group"
            aria-labelledby={`${navigationId}-authentication`}
          >
            <span id={`${navigationId}-authentication`} className={styles["navigationLabel"]}>
              Authentication
            </span>
            <ConsoleNavLink to={`${base}/authentication/providers`} onNavigate={onNavigate}>
              Providers
            </ConsoleNavLink>
            <ConsoleNavLink to={`${base}/authentication/email`} onNavigate={onNavigate}>
              Passwordless email
            </ConsoleNavLink>
          </div>
          <div
            className={styles["navigationGroup"]}
            role="group"
            aria-labelledby={`${navigationId}-manage`}
          >
            <span id={`${navigationId}-manage`} className={styles["navigationLabel"]}>
              Manage
            </span>
            <ConsoleNavLink to={`${base}/users`} onNavigate={onNavigate}>
              Users
            </ConsoleNavLink>
          </div>
          <div
            className={styles["navigationGroup"]}
            role="group"
            aria-labelledby={`${navigationId}-security`}
          >
            <span id={`${navigationId}-security`} className={styles["navigationLabel"]}>
              Security
            </span>
            <ConsoleNavLink to={`${base}/security/signing-keys`} onNavigate={onNavigate}>
              Signing keys
            </ConsoleNavLink>
            <ConsoleNavLink to={`${base}/security/server-keys`} onNavigate={onNavigate}>
              Project secret keys
            </ConsoleNavLink>
          </div>
          <div className={styles["settingsNavigation"]} role="group" aria-label="Project settings">
            <ConsoleNavLink to={`${base}/settings`} onNavigate={onNavigate}>
              Settings
            </ConsoleNavLink>
          </div>
        </>
      )}
    </nav>
  );
}

function ConsoleLockAction({ onLock }: { readonly onLock: () => void }) {
  return (
    <div className={styles["sidebarFooter"]}>
      <Button type="button" variant="secondary" fullWidth onClick={onLock}>
        Exit console
      </Button>
    </div>
  );
}

function ConsoleNavLink({
  children,
  onNavigate,
  ...props
}: {
  readonly to: string;
  readonly end?: boolean;
  readonly onNavigate: () => void;
  readonly children: ReactNode;
}) {
  return (
    <NavLink {...props} onClick={onNavigate}>
      {children}
    </NavLink>
  );
}

function currentSection(pathname: string, projectId: string | undefined): string {
  if (projectId === undefined) return "Directory";
  if (pathname.includes("/applications/")) return "Application detail";
  if (pathname.endsWith("/applications")) return "Applications";
  if (pathname.endsWith("/authentication/providers")) return "Providers";
  if (pathname.endsWith("/authentication/email")) return "Passwordless email";
  if (pathname.includes("/users/")) return "User detail";
  if (pathname.endsWith("/users")) return "Users";
  if (pathname.endsWith("/security/signing-keys")) return "Signing keys";
  if (pathname.endsWith("/security/server-keys")) return "Project secret keys";
  if (pathname.endsWith("/settings")) return "Settings";
  return "Overview";
}

function MenuIcon() {
  return (
    <svg aria-hidden="true" width="20" height="20" viewBox="0 0 20 20" fill="none">
      <path d="M3 5h14M3 10h14M3 15h14" stroke="currentColor" strokeWidth="2" />
    </svg>
  );
}
