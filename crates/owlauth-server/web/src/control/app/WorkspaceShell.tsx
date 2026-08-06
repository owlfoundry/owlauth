import { useEffect, useId, useState } from "react";
import type { ReactNode } from "react";
import { NavLink, Outlet, useLocation, useNavigate, useParams } from "react-router";

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
  const { projects, message, messageTone, toasts, dismissToast, clearFeedback, lock } =
    useControl();
  const [navigationOpen, setNavigationOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    clearFeedback();
  }, [clearFeedback, location.key]);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      document.querySelector<HTMLElement>("#console-main h1")?.focus();
    });
    return () => {
      window.cancelAnimationFrame(frame);
    };
  }, [location.pathname]);

  const navigation = (
    <Navigation
      projectId={projectId}
      onNavigate={() => {
        setNavigationOpen(false);
      }}
    />
  );

  return (
    <div className={styles["workspace"]}>
      <a className={styles["skipLink"]} href="#console-main">
        Skip to main content
      </a>
      <aside className={styles["sidebar"]} aria-label="Console navigation">
        <OwlAuthWordmark />
        <ProjectSwitcher
          projectId={projectId}
          projects={projects}
          onChange={(id) => {
            void navigate(id === "" ? "/" : `/projects/${id}`);
          }}
        />
        {navigation}
        <div className={styles["sidebarFooter"]}>
          <Button type="button" variant="quiet" fullWidth onClick={lock}>
            Lock console
          </Button>
        </div>
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
          <li>
            <NavLink to="/">Projects</NavLink>
          </li>
          {project === null ? null : (
            <li>
              <NavLink to={`/projects/${project.id}`}>{project.display_name}</NavLink>
            </li>
          )}
          <li aria-current="page">{currentSection(location.pathname, projectId)}</li>
        </Breadcrumbs>
        <span className={styles["mobileOnly"]}>
          <Button type="button" variant="quiet" onClick={lock}>
            Lock
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
        <ProjectSwitcher
          projectId={projectId}
          projects={projects}
          onChange={(id) => {
            void navigate(id === "" ? "/" : `/projects/${id}`);
            setNavigationOpen(false);
          }}
        />
        {navigation}
        <div className={styles["sidebarFooter"]}>
          <Button type="button" variant="quiet" fullWidth onClick={lock}>
            Lock console
          </Button>
        </div>
      </SideSheet>
    </div>
  );
}

function ProjectSwitcher({
  projectId,
  projects,
  onChange,
}: {
  readonly projectId: string | undefined;
  readonly projects: readonly { readonly id: string; readonly display_name: string }[];
  readonly onChange: (id: string) => void;
}) {
  const selectId = useId();
  return (
    <div className={styles["projectContext"]}>
      <label htmlFor={selectId}>Project context</label>
      <select
        id={selectId}
        className={styles["projectSelect"]}
        value={projectId ?? ""}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      >
        <option value="">All Projects</option>
        {projects.map((project) => (
          <option key={project.id} value={project.id}>
            {project.display_name}
          </option>
        ))}
      </select>
    </div>
  );
}

function Navigation({
  projectId,
  onNavigate,
}: {
  readonly projectId: string | undefined;
  readonly onNavigate: () => void;
}) {
  const base = projectId === undefined ? null : `/projects/${projectId}`;
  return (
    <nav className={styles["navigation"]} aria-label="Resources">
      <ConsoleNavLink to="/" end onNavigate={onNavigate}>
        Projects
      </ConsoleNavLink>
      {base === null ? null : (
        <>
          <div className={styles["navigationGroup"]}>
            <span className={styles["navigationLabel"]}>Project</span>
            <ConsoleNavLink to={base} end onNavigate={onNavigate}>
              Overview
            </ConsoleNavLink>
            <ConsoleNavLink to={`${base}/applications`} onNavigate={onNavigate}>
              Applications
            </ConsoleNavLink>
          </div>
          <div className={styles["navigationGroup"]}>
            <span className={styles["navigationLabel"]}>Authentication</span>
            <ConsoleNavLink to={`${base}/authentication/providers`} onNavigate={onNavigate}>
              Providers
            </ConsoleNavLink>
            <ConsoleNavLink to={`${base}/authentication/email`} onNavigate={onNavigate}>
              Passwordless email
            </ConsoleNavLink>
          </div>
          <div className={styles["navigationGroup"]}>
            <span className={styles["navigationLabel"]}>User management</span>
            <ConsoleNavLink to={`${base}/users`} onNavigate={onNavigate}>
              Users
            </ConsoleNavLink>
          </div>
          <div className={styles["navigationGroup"]}>
            <span className={styles["navigationLabel"]}>Security</span>
            <ConsoleNavLink to={`${base}/security/signing-keys`} onNavigate={onNavigate}>
              Signing keys
            </ConsoleNavLink>
            <ConsoleNavLink to={`${base}/security/client-keys`} onNavigate={onNavigate}>
              Client API keys
            </ConsoleNavLink>
          </div>
          <div className={styles["navigationGroup"]}>
            <ConsoleNavLink to={`${base}/settings`} onNavigate={onNavigate}>
              Settings
            </ConsoleNavLink>
          </div>
        </>
      )}
    </nav>
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
  if (pathname.endsWith("/security/client-keys")) return "Client API keys";
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
