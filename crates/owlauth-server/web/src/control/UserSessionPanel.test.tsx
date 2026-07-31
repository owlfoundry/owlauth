import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import {
  type DisposableControlClient,
  type Project,
  type ProjectUser,
  type ProjectUserSessions,
  ControlRequestError,
} from "./client";
import { UserSessionPanel } from "./UserSessionPanel";

const project: Project = {
  id: "11111111-1111-4111-8111-111111111111",
  public_id: "prj_public123",
  display_name: "Production",
  belongs_to: null,
  status: "active",
  metadata_revision: 1,
  security_revision: 1,
};

const user: ProjectUser = {
  id: "22222222-2222-4222-8222-222222222222",
  project_id: project.id,
  public_id: "usr_public123",
  display_name: "Ada Lovelace",
  picture_url: null,
  status: "active",
  user_revision: 3,
  security_revision: 4,
  created_at: "2026-07-30T00:00:00Z",
  updated_at: "2026-07-31T00:00:00Z",
};

const sessions: ProjectUserSessions = {
  application_sessions: [
    {
      id: "33333333-3333-4333-8333-333333333333",
      project_id: project.id,
      user_id: user.id,
      application_id: "44444444-4444-4444-8444-444444444444",
      application_public_id: "app_public123",
      application_display_name: "Dashboard",
      browser_session_id: "55555555-5555-4555-8555-555555555555",
      status: "active",
      session_revision: 7,
      authenticated_at: "2026-07-31T00:00:00Z",
      absolute_expires_at: "2026-08-30T00:00:00Z",
      revoked_at: null,
      created_at: "2026-07-31T00:00:00Z",
      updated_at: "2026-07-31T00:00:00Z",
    },
  ],
  browser_sessions: [
    {
      id: "55555555-5555-4555-8555-555555555555",
      project_id: project.id,
      user_id: user.id,
      status: "active",
      session_revision: 9,
      authenticated_at: "2026-07-31T00:00:00Z",
      last_activity_at: "2026-07-31T01:00:00Z",
      idle_expires_at: "2026-07-31T09:00:00Z",
      absolute_expires_at: "2026-08-01T00:00:00Z",
      terminated_at: null,
      created_at: "2026-07-31T00:00:00Z",
      updated_at: "2026-07-31T01:00:00Z",
    },
  ],
};

function successful<T>(data: T) {
  return { data, error: undefined, response: Response.json(data) };
}

function renderPanel(options?: {
  post?: (...args: unknown[]) => Promise<unknown>;
  onError?: (error: unknown) => Promise<void>;
}) {
  const get = vi.fn((path: string) => {
    if (path.endsWith("/sessions")) return Promise.resolve(successful(sessions));
    if (path.endsWith("/{user_id}")) {
      return Promise.resolve(
        successful({ ...user, provider_credentials: "never-render-provider-secret" }),
      );
    }
    return Promise.resolve(
      successful({
        items: [{ ...user, source_payload: "never-render-source-payload" }],
      }),
    );
  });
  const post =
    options?.post ??
    vi.fn((path: string) => {
      if (path.endsWith("/disable")) {
        return Promise.resolve(successful({ ...user, status: "disabled", security_revision: 5 }));
      }
      if (path.includes("application-sessions")) {
        return Promise.resolve(
          successful({
            ...sessions.application_sessions[0],
            status: "revoked",
            session_revision: 8,
          }),
        );
      }
      return Promise.resolve(
        successful({
          ...sessions.browser_sessions[0],
          status: "revoked",
          session_revision: 10,
        }),
      );
    });
  const onError: (error: unknown) => Promise<void> =
    options?.onError ?? vi.fn(() => Promise.resolve());
  const setMessage = vi.fn();
  const session = {
    client: { GET: get, POST: post },
    dispose: vi.fn(),
  } as unknown as DisposableControlClient;
  render(
    <UserSessionPanel
      session={session}
      project={project}
      onError={onError}
      setMessage={setMessage}
    />,
  );
  return { get, post, setMessage };
}

async function loadUserPanel() {
  fireEvent.click(screen.getByRole("button", { name: "Load Project users" }));
  expect(await screen.findByRole("heading", { name: "Ada Lovelace" })).toBeVisible();
  expect(await screen.findByRole("heading", { name: "Application sessions" })).toBeVisible();
}

describe("Project user and session lifecycle", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("loads bounded user/session views without rendering private source fields", async () => {
    const { get } = renderPanel();
    expect(get).not.toHaveBeenCalled();

    await loadUserPanel();

    expect(screen.getByText(/security revision 4/u)).toBeVisible();
    expect(screen.getByText("Dashboard")).toBeVisible();
    expect(screen.getByRole("heading", { name: "Project browser sessions" })).toBeVisible();
    expect(document.body.textContent).not.toContain("never-render-provider-secret");
    expect(document.body.textContent).not.toContain("never-render-source-payload");
    expect(get).toHaveBeenCalledWith(
      "/v1/projects/{project_id}/users/{user_id}/sessions",
      expect.objectContaining({
        params: { path: { project_id: project.id, user_id: user.id } },
      }),
    );
  });

  it("requires confirmation and submits exact user/session revisions", async () => {
    const confirm = vi.spyOn(window, "confirm");
    confirm.mockReturnValueOnce(false).mockReturnValue(true);
    const { post, setMessage } = renderPanel();
    await loadUserPanel();

    fireEvent.click(screen.getByRole("button", { name: "Disable Project user" }));
    expect(post).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Disable Project user" }));
    await waitFor(() => {
      expect(post).toHaveBeenCalledWith(
        "/v1/projects/{project_id}/users/{user_id}/disable",
        expect.objectContaining({ body: { expected_security_revision: 4 } }),
      );
    });
    expect(setMessage).toHaveBeenCalledWith("Project user disabled.");

    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "Revoke Application session" }));
    await waitFor(() => {
      expect(post).toHaveBeenCalledWith(
        expect.stringContaining("application-sessions"),
        expect.objectContaining({ body: { expected_session_revision: 7 } }),
      );
    });
    expect(screen.getByText(/revoked; revision 8/u)).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Revoke Project browser session" }));
    await waitFor(() => {
      expect(post).toHaveBeenCalledWith(
        expect.stringContaining("browser-sessions"),
        expect.objectContaining({ body: { expected_session_revision: 9 } }),
      );
    });
    expect(screen.getByText(/revoked; revision 10/u)).toBeVisible();
  });

  it("refreshes lifecycle state and reports a stale-revision conflict", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const conflict = new ControlRequestError(
      {
        type: "about:blank",
        title: "Revision conflict",
        status: 409,
        code: "revision_conflict",
        detail: "The expected revision is stale.",
        request_id: "req",
      },
      409,
    );
    const post = vi.fn(() => Promise.reject(conflict));
    const onError = vi.fn(() => Promise.resolve());
    const { get } = renderPanel({ post, onError });
    await loadUserPanel();

    fireEvent.click(screen.getByRole("button", { name: "Disable Project user" }));

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(conflict);
    });
    expect(get.mock.calls.filter(([path]) => path.endsWith("/users"))).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Disable Project user" })).toBeEnabled();
  });
});
