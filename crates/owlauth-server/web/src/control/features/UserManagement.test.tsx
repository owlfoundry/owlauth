import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router";

import {
  type Application,
  type DisposableControlClient,
  type ManagedProviderConnection,
  type Project,
  type ProjectUser,
  type Provider,
  type ProjectUserSessions,
  ControlRequestError,
} from "../client";
import { ControlConfirmationProvider } from "../app/Confirmation";
import { UserManagement } from "./UserManagement";

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

const reauthorizationApplication: Application = {
  id: "99999999-9999-4999-8999-999999999999",
  project_id: project.id,
  public_id: "app_reauthorization",
  display_name: "Identity recovery",
  application_type: "web",
  status: "active",
  metadata_revision: 1,
  security_revision: 1,
  configuration: {
    redirect_uris: ["https://application.example/callback"],
    allowed_origins: ["https://application.example"],
    publishable_keys: ["publishable"],
  },
};

const provider: Provider = {
  id: "77777777-7777-4777-8777-777777777777",
  project_id: project.id,
  provider_key: "workforce",
  display_name: "Workforce SSO",
  kind: "oidc",
  issuer: "https://issuer.example",
  client_id: "public-client-label",
  callback_url: "https://runtime.example/callback",
  status: "active",
  revision: 5,
  login_supported: true,
  identity_proof_supported: true,
  assigned_application_ids: [reauthorizationApplication.id],
  managed_profile: {
    enabled: false,
    exact_scopes: [],
    profile_schema: "unsupported",
    read_retry_safe: false,
    renewal_idempotent_replay: false,
    supported: false,
    supports_revocation: false,
  },
};

const connection: ManagedProviderConnection = {
  id: "66666666-6666-4666-8666-666666666666",
  project_id: project.id,
  user_id: user.id,
  provider_id: "77777777-7777-4777-8777-777777777777",
  identity_id: "88888888-8888-4888-8888-888888888888",
  state: "active",
  revision: 5,
  generation: 3,
  credential_generation: 2,
  capability_key: "controlled_oidc_profile_v1",
  required_scopes: ["offline_access", "openid", "profile"],
  source_schema: "oidc_userinfo_v1",
  last_safe_outcome: "callback_committed",
  last_synchronized_at: null,
  next_synchronize_at: "2026-08-01T01:00:00Z",
  consecutive_failures: 0,
  supports_revocation: true,
  reauthorization_application_ids: ["99999999-9999-4999-8999-999999999999"],
};

function successful<T>(data: T) {
  return { data, error: undefined, response: Response.json(data) };
}

function requestedSearch(call: readonly unknown[]): unknown {
  const options = call[1];
  if (typeof options !== "object" || options === null) return undefined;
  const params = (options as Record<string, unknown>)["params"];
  if (typeof params !== "object" || params === null) return undefined;
  const query = (params as Record<string, unknown>)["query"];
  if (typeof query !== "object" || query === null) return undefined;
  return (query as Record<string, unknown>)["search"];
}

function renderPanel(options?: {
  get?: (...args: unknown[]) => Promise<unknown>;
  post?: (...args: unknown[]) => Promise<unknown>;
  onError?: (error: unknown) => Promise<void>;
  connections?: ManagedProviderConnection[];
  detailOnly?: boolean;
  initialUserId?: string;
  listUsers?: ProjectUser[];
  providers?: Provider[];
  routedInventory?: boolean;
}) {
  const get = vi.fn((...args: unknown[]) => {
    if (options?.get !== undefined) return options.get(...args);
    const path = args[0];
    if (typeof path !== "string") throw new Error("GET path is not a string");
    if (path.endsWith("/identities")) return Promise.resolve(successful({ items: [] }));
    if (path.endsWith("/managed-provider-connections")) {
      return Promise.resolve(successful({ items: options?.connections ?? [] }));
    }
    if (path.endsWith("/sessions")) return Promise.resolve(successful(sessions));
    if (path.endsWith("/{user_id}")) {
      return Promise.resolve(
        successful({ ...user, provider_credentials: "never-render-provider-secret" }),
      );
    }
    return Promise.resolve(
      successful({
        items: (options?.listUsers ?? [user]).map((item) => ({
          ...item,
          source_payload: "never-render-source-payload",
        })),
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
    <MemoryRouter>
      <ControlConfirmationProvider>
        <UserManagement
          session={session}
          project={project}
          applications={[reauthorizationApplication]}
          providers={options?.providers ?? []}
          {...(options?.detailOnly === undefined ? {} : { detailOnly: options.detailOnly })}
          {...(options?.initialUserId === undefined
            ? {}
            : { initialUserId: options.initialUserId })}
          {...(options?.routedInventory === true ? { onUserSelected: vi.fn() } : {})}
          onError={onError}
          setMessage={setMessage}
        />
        <LocationProbe />
      </ControlConfirmationProvider>
    </MemoryRouter>,
  );
  return { get, post, setMessage };
}

function LocationProbe() {
  return <output data-testid="location-pathname">{useLocation().pathname}</output>;
}

async function loadUserPanel() {
  fireEvent.click(await screen.findByRole("button", { name: /Ada Lovelace/u }));
  expect(await screen.findByRole("heading", { name: "Ada Lovelace" })).toBeVisible();
  expect(await screen.findByRole("heading", { name: "Application sessions" })).toBeVisible();
}

function selectReauthorizationApplication() {
  fireEvent.change(screen.getByLabelText("Reauthorization Application"), {
    target: { value: reauthorizationApplication.id },
  });
  return screen.getByRole("button", { name: "Reauthorize with selected Application" });
}

function confirmDialog(actionName: string) {
  const dialog = screen.getByRole("dialog");
  fireEvent.click(within(dialog).getByRole("button", { name: actionName }));
}

describe("Project user and session lifecycle", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("loads bounded merge candidates on a routed user detail", async () => {
    const losingUser: ProjectUser = {
      ...user,
      id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      public_id: "usr_losing123",
      display_name: "Grace Hopper",
    };
    const get = vi.fn((path: unknown) => {
      if (typeof path !== "string") throw new Error("GET path is not a string");
      if (path.endsWith("/users")) {
        return Promise.resolve(successful({ items: [losingUser], next_cursor: null }));
      }
      if (path.endsWith("/{user_id}")) return Promise.resolve(successful(user));
      if (path.endsWith("/sessions")) return Promise.resolve(successful(sessions));
      if (path.endsWith("/managed-provider-connections")) {
        return Promise.resolve(successful({ items: [] }));
      }
      if (path.endsWith("/identities")) return Promise.resolve(successful({ items: [] }));
      throw new Error(`Unexpected GET path: ${path}`);
    });
    renderPanel({ get, detailOnly: true, initialUserId: user.id });

    expect(await screen.findByRole("heading", { name: "Ada Lovelace" })).toBeVisible();
    fireEvent.change(screen.getByLabelText("Operation"), { target: { value: "merge" } });
    expect(screen.getByRole("option", { name: /Grace Hopper/u })).toBeVisible();
    expect(screen.queryByRole("option", { name: /Ada Lovelace/u })).toBeNull();
  });

  it("keeps routed user actions available while merge candidates stall or fail", async () => {
    const onError = vi.fn(() => Promise.resolve());
    let rejectCandidates: ((reason: Error) => void) | undefined;
    const get = vi.fn((path: unknown) => {
      if (typeof path !== "string") throw new Error("GET path is not a string");
      if (path.endsWith("/users")) {
        return new Promise((_resolve, reject) => {
          rejectCandidates = reject;
        });
      }
      if (path.endsWith("/{user_id}")) return Promise.resolve(successful(user));
      if (path.endsWith("/sessions")) return Promise.resolve(successful(sessions));
      if (path.endsWith("/managed-provider-connections")) {
        return Promise.resolve(successful({ items: [] }));
      }
      if (path.endsWith("/identities")) return Promise.resolve(successful({ items: [] }));
      throw new Error(`Unexpected GET path: ${path}`);
    });
    renderPanel({ get, onError, detailOnly: true, initialUserId: user.id });

    expect(await screen.findByRole("heading", { name: "Ada Lovelace" })).toBeVisible();
    expect(screen.getByLabelText("Operation")).toBeEnabled();
    expect(screen.getByText("Loading merge candidate inventory…")).toBeVisible();
    await act(async () => {
      rejectCandidates?.(new Error("candidate inventory failed"));
      await Promise.resolve();
    });
    expect(await screen.findByRole("button", { name: "Retry merge candidates" })).toBeEnabled();
    expect(screen.getByText(/other identity or session actions remain available/u)).toBeVisible();
    expect(onError).toHaveBeenCalledWith(
      expect.objectContaining({ message: "candidate inventory failed" }),
    );
  });

  it("ignores a superseded merge-candidate failure after refresh", async () => {
    const losingUser: ProjectUser = {
      ...user,
      id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      public_id: "usr_replacement",
      display_name: "Replacement candidate",
    };
    let candidateCalls = 0;
    let rejectFirstCandidates: ((reason: Error) => void) | undefined;
    const get = vi.fn((path: unknown) => {
      if (typeof path !== "string") throw new Error("GET path is not a string");
      if (path.endsWith("/users")) {
        candidateCalls += 1;
        if (candidateCalls === 1) {
          return new Promise((_resolve, reject) => {
            rejectFirstCandidates = reject;
          });
        }
        return Promise.resolve(successful({ items: [losingUser], next_cursor: null }));
      }
      if (path.endsWith("/{user_id}")) return Promise.resolve(successful(user));
      if (path.endsWith("/sessions")) return Promise.resolve(successful(sessions));
      if (path.endsWith("/managed-provider-connections")) {
        return Promise.resolve(successful({ items: [] }));
      }
      if (path.endsWith("/identities")) return Promise.resolve(successful({ items: [] }));
      throw new Error(`Unexpected GET path: ${path}`);
    });
    renderPanel({ get, detailOnly: true, initialUserId: user.id });

    expect(await screen.findByRole("heading", { name: "Ada Lovelace" })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Refresh user" }));
    expect(await screen.findByRole("heading", { name: "Ada Lovelace" })).toBeVisible();
    fireEvent.change(screen.getByLabelText("Operation"), { target: { value: "merge" } });
    expect(await screen.findByRole("option", { name: /Replacement candidate/u })).toBeVisible();

    await act(async () => {
      rejectFirstCandidates?.(new Error("superseded candidate failure"));
      await Promise.resolve();
    });
    expect(screen.queryByRole("button", { name: "Retry merge candidates" })).toBeNull();
    expect(screen.getByRole("option", { name: /Replacement candidate/u })).toBeVisible();
  });

  it("loads bounded user/session views without rendering private source fields", async () => {
    const { get } = renderPanel();

    await loadUserPanel();

    expect(screen.getAllByText("Status: active").length).toBeGreaterThan(0);
    expect(screen.queryByText(/security revision/u)).toBeNull();
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

  it("sends search, status, provider provenance, sort, and reset pagination to Control", async () => {
    const get = vi.fn(() =>
      Promise.resolve(successful({ items: [user], next_cursor: "next-page" })),
    );
    renderPanel({ get, providers: [provider] });

    expect(await screen.findByRole("button", { name: /Ada Lovelace/u })).toBeVisible();
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "disabled" } });
    fireEvent.change(screen.getByLabelText("Identity"), {
      target: { value: "provider:workforce" },
    });
    fireEvent.change(screen.getByLabelText("Sort"), { target: { value: "created_oldest" } });
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "  Ada  " } });
    fireEvent.click(screen.getByRole("button", { name: "Search" }));

    await waitFor(() => {
      expect(get).toHaveBeenCalledWith(
        "/v1/projects/{project_id}/users",
        expect.objectContaining({
          params: {
            path: { project_id: project.id },
            query: {
              status: "disabled",
              search: "Ada",
              identity_kind: "provider",
              provider_key: "workforce",
              sort: "created_oldest",
              limit: 50,
            },
          },
        }),
      );
    });
  });

  it("routes a user inventory link to the dedicated authority page", async () => {
    renderPanel({ routedInventory: true });

    const userLink = await screen.findByRole("link", { name: /Ada Lovelace/u });
    expect(userLink).toHaveAttribute("href", `/projects/${project.id}/users/${user.id}`);
    fireEvent.click(userLink);
    expect(screen.getByTestId("location-pathname")).toHaveTextContent(
      `/projects/${project.id}/users/${user.id}`,
    );
  });

  it("enforces prefix search bounds by Unicode code point before dispatch", async () => {
    const get = vi.fn((...args: unknown[]) => {
      void args;
      return Promise.resolve(successful({ items: [user], next_cursor: null }));
    });
    renderPanel({ get });

    expect(await screen.findByRole("button", { name: /Ada Lovelace/u })).toBeVisible();
    const search = screen.getByLabelText("Search");
    const submit = screen.getByRole("button", { name: "Search" });

    const bmpBoundary = "界".repeat(128);
    fireEvent.change(search, { target: { value: bmpBoundary } });
    fireEvent.click(submit);
    await waitFor(() => {
      expect(get.mock.calls.map(requestedSearch)).toContain(bmpBoundary);
    });

    const requestsAfterBmpBoundary = get.mock.calls.length;
    fireEvent.change(search, { target: { value: "界".repeat(129) } });
    fireEvent.click(submit);
    expect(screen.getByRole("alert")).toHaveTextContent(
      "User prefix search is limited to 128 characters.",
    );
    expect(get).toHaveBeenCalledTimes(requestsAfterBmpBoundary);

    const astralBoundary = "𐐀".repeat(128);
    fireEvent.change(search, { target: { value: astralBoundary } });
    fireEvent.click(submit);
    await waitFor(() => {
      expect(get.mock.calls.map(requestedSearch)).toContain(astralBoundary);
    });

    const requestsAfterAstralBoundary = get.mock.calls.length;
    fireEvent.change(search, { target: { value: "𐐀".repeat(129) } });
    fireEvent.click(submit);
    expect(screen.getByRole("alert")).toHaveTextContent(
      "User prefix search is limited to 128 characters.",
    );
    expect(get).toHaveBeenCalledTimes(requestsAfterAstralBoundary);
  });

  it("uses exact email lookup and authoritative identity inventory for combined filters", async () => {
    const get = vi.fn((path: unknown) => {
      if (typeof path !== "string") throw new Error("GET path is not a string");
      if (path.endsWith("/identities")) {
        return Promise.resolve(
          successful({
            items: [
              {
                id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                project_id: project.id,
                user_id: user.id,
                identity_kind: "provider",
                provider_key: provider.provider_key,
                status: "active",
                identity_revision: 2,
                is_primary_source: true,
                verified_or_observed_at: "2026-07-30T00:00:00Z",
                created_at: "2026-07-30T00:00:00Z",
                updated_at: "2026-07-30T00:00:00Z",
              },
            ],
          }),
        );
      }
      return Promise.resolve(successful({ items: [user], next_cursor: null }));
    });
    const post = vi.fn((...args: unknown[]) => {
      const path = args[0];
      if (typeof path !== "string") throw new Error("POST path is not a string");
      if (path.endsWith("/users/lookup")) {
        return Promise.resolve(successful({ user }));
      }
      throw new Error(`Unexpected POST path: ${path}`);
    });
    renderPanel({ get, post, providers: [provider] });

    expect(await screen.findByRole("button", { name: /Ada Lovelace/u })).toBeVisible();
    fireEvent.change(screen.getByLabelText("Identity"), {
      target: { value: "provider:workforce" },
    });
    fireEvent.change(screen.getByLabelText("Search"), {
      target: { value: "ADA@Example.Test" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Search" }));

    await waitFor(() => {
      expect(post).toHaveBeenCalledWith(
        "/v1/projects/{project_id}/users/lookup",
        expect.objectContaining({
          params: { path: { project_id: project.id } },
          body: { email: "ADA@Example.Test" },
        }),
      );
    });
    expect(get).toHaveBeenCalledWith(
      "/v1/projects/{project_id}/users/{user_id}/identities",
      expect.objectContaining({
        params: { path: { project_id: project.id, user_id: user.id } },
      }),
    );
    expect(screen.getByRole("button", { name: /Ada Lovelace/u })).toBeVisible();
  });

  it("clears applied directory filters and restores the unfiltered query", async () => {
    const get = vi.fn(() => Promise.resolve(successful({ items: [], next_cursor: null })));
    renderPanel({ get, providers: [provider] });

    expect(await screen.findByText("No users yet")).toBeVisible();
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "merged" } });
    fireEvent.change(screen.getByLabelText("Identity"), { target: { value: "email" } });
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "missing" } });
    fireEvent.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByText("No matching users")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));

    await waitFor(() => {
      expect(screen.getByText("No users yet")).toBeVisible();
      expect(get).toHaveBeenLastCalledWith(
        "/v1/projects/{project_id}/users",
        expect.objectContaining({
          params: {
            path: { project_id: project.id },
            query: { sort: "created_newest", limit: 50 },
          },
        }),
      );
    });
    expect(screen.getByLabelText("Search")).toHaveValue("");
    expect(screen.getByLabelText("Status")).toHaveValue("all");
    expect(screen.getByLabelText("Identity")).toHaveValue("all");
  });

  it("serializes pagination and deduplicates repeated users", async () => {
    let resolveNextPage: (() => void) | undefined;
    const get = vi.fn((path: unknown, options: unknown) => {
      expect(path).toBe("/v1/projects/{project_id}/users");
      const cursor = (options as { params: { query: { cursor?: string } } }).params.query.cursor;
      if (cursor === undefined) {
        return Promise.resolve(successful({ items: [user], next_cursor: "next-page" }));
      }
      expect(cursor).toBe("next-page");
      return new Promise((resolve) => {
        resolveNextPage = () => {
          resolve(successful({ items: [user], next_cursor: null }));
        };
      });
    });
    renderPanel({ get });

    const loadMore = await screen.findByRole("button", { name: "Load more users" });
    fireEvent.click(loadMore);
    fireEvent.click(loadMore);

    expect(get).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("button", { name: "Loading more users" })).toBeDisabled();
    expect(screen.getByLabelText("Status")).toBeDisabled();
    resolveNextPage?.();
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Loading more users" })).toBeNull();
    });
    expect(screen.getAllByRole("button", { name: /Ada Lovelace/u })).toHaveLength(1);
  });

  it("does not let a stale detail response pollute a newer status filter", async () => {
    const disabledUser: ProjectUser = {
      ...user,
      id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      public_id: "usr_disabled123",
      display_name: "Grace Hopper",
      status: "disabled",
    };
    let resolveDetail: (() => void) | undefined;
    const get = vi.fn((path: unknown, options: unknown) => {
      if (typeof path !== "string") throw new Error("GET path is not a string");
      if (path.endsWith("/users")) {
        const status = (options as { params: { query: { status?: string } } }).params.query.status;
        return Promise.resolve(
          successful({ items: [status === "disabled" ? disabledUser : user], next_cursor: null }),
        );
      }
      if (path.endsWith("/{user_id}")) {
        return new Promise((resolve) => {
          resolveDetail = () => {
            resolve(successful(user));
          };
        });
      }
      if (path.endsWith("/sessions")) return Promise.resolve(successful(sessions));
      if (path.endsWith("/managed-provider-connections")) {
        return Promise.resolve(successful({ items: [] }));
      }
      if (path.endsWith("/identities")) return Promise.resolve(successful({ items: [] }));
      throw new Error(`Unexpected GET path: ${path}`);
    });
    renderPanel({ get });

    fireEvent.click(await screen.findByRole("button", { name: /Ada Lovelace/u }));
    const status = screen.getByLabelText("Status");
    expect(status).toBeDisabled();
    fireEvent.change(status, { target: { value: "disabled" } });
    expect(await screen.findByRole("button", { name: /Grace Hopper/u })).toBeVisible();

    resolveDetail?.();
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: /Ada Lovelace/u })).toBeNull();
    });
    expect(screen.queryByRole("heading", { name: "Ada Lovelace" })).toBeNull();
    expect(screen.getByRole("button", { name: /Grace Hopper/u })).toBeVisible();
  });

  it("renders safe managed metadata and sends generation-fenced actions", async () => {
    const post = vi.fn(() =>
      Promise.resolve(
        successful({ ...connection, revision: 6, last_safe_outcome: "sync_requested" }),
      ),
    );
    renderPanel({ post, connections: [connection] });
    await loadUserPanel();

    expect(screen.getByRole("heading", { name: "Managed provider connections" })).toBeVisible();
    expect(screen.getByText(/offline_access openid profile/u)).toBeVisible();
    expect(screen.getAllByText("Status: active").length).toBeGreaterThan(0);
    expect(screen.queryByText(/credential generation/u)).toBeNull();
    expect(
      screen.getByRole("button", { name: "Reauthorize with selected Application" }),
    ).toBeDisabled();
    expect(screen.getByRole("button", { name: "Revoke at provider" })).toBeVisible();
    expect(document.body.textContent).not.toMatch(/refresh[_ -]?token|credential payload/iu);
    fireEvent.click(screen.getByRole("button", { name: "Synchronize profile" }));
    await waitFor(() => {
      expect(post).toHaveBeenCalledWith(
        "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/synchronize",
        expect.objectContaining({
          body: { expected_revision: 5, expected_generation: 3, confirm: false },
        }),
      );
    });
  });

  it("keeps explicit reauthorization available for a disconnected connection", async () => {
    renderPanel({
      connections: [
        {
          ...connection,
          state: "disconnected",
          last_safe_outcome: "locally_disconnected",
        },
      ],
    });
    await loadUserPanel();

    const reauthorize = selectReauthorizationApplication();
    expect(reauthorize).toBeVisible();
    expect(reauthorize).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Synchronize profile" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Revoke at provider" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Disconnect locally" })).toBeNull();
  });

  it("reserves a popup before a delayed reauthorization create and navigates the exact target", async () => {
    let resolveCreate: ((value: unknown) => void) | undefined;
    const post = vi.fn((...args: unknown[]) => {
      void args;
      return new Promise<unknown>((resolve) => {
        resolveCreate = resolve;
      });
    });
    const replace = vi.fn();
    const close = vi.fn();
    const popup = { opener: window, location: { replace }, close } as unknown as Window;
    const open = vi.spyOn(window, "open").mockReturnValue(popup);
    renderPanel({ post, connections: [connection] });
    await loadUserPanel();

    fireEvent.click(selectReauthorizationApplication());
    expect(open).toHaveBeenCalledWith("about:blank", "_blank");
    expect(replace).not.toHaveBeenCalled();
    expect(post).toHaveBeenCalledTimes(1);
    resolveCreate?.(
      successful({
        id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        status: "awaiting_browser_binding",
        revision: 1,
        hosted_target: "https://runtime.example/auth/managed-reauthorizations/exact-target",
      }),
    );
    await waitFor(() => {
      expect(replace).toHaveBeenCalledWith(
        "https://runtime.example/auth/managed-reauthorizations/exact-target",
      );
    });
    expect(close).not.toHaveBeenCalled();
    expect(
      (post.mock.calls[0]?.[1] as { params?: { header?: Record<string, string> } }).params
        ?.header?.["Idempotency-Key"],
    ).toMatch(/^console_/u);
  });

  it("rejects an unsafe Hosted target without navigating or rendering a fallback", async () => {
    const post = vi.fn(() =>
      Promise.resolve(
        successful({
          id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
          status: "awaiting_browser_binding",
          revision: 1,
          hosted_target: "https://operator:credential@runtime.example/reauthorize",
        }),
      ),
    );
    const replace = vi.fn();
    const close = vi.fn();
    const popup = { opener: window, location: { replace }, close } as unknown as Window;
    vi.spyOn(window, "open").mockReturnValue(popup);
    const onError = vi.fn(() => Promise.resolve());
    renderPanel({ post, onError, connections: [connection] });
    await loadUserPanel();

    fireEvent.click(selectReauthorizationApplication());

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({
          message: "Managed reauthorization returned an invalid Hosted target.",
        }),
      );
    });
    expect(close).toHaveBeenCalledTimes(1);
    expect(replace).not.toHaveBeenCalled();
    expect(screen.queryByRole("link", { name: "Continue managed reauthorization" })).toBeNull();
  });

  it("retries an ambiguous create with one key and renders the blocked-popup exact target", async () => {
    const keys: string[] = [];
    const post = vi.fn((...args: unknown[]) => {
      const options = args[1];
      const key = (options as { params: { header: { "Idempotency-Key": string } } }).params.header[
        "Idempotency-Key"
      ];
      keys.push(key);
      if (keys.length === 1) return Promise.reject(new ControlRequestError(undefined, 503));
      return Promise.resolve(
        successful({
          id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
          status: "awaiting_browser_binding",
          revision: 1,
          hosted_target:
            "https://runtime.example/auth/managed-reauthorizations/recovered-exact-target",
        }),
      );
    });
    const onError = vi.fn(() => Promise.resolve());
    vi.spyOn(window, "open").mockReturnValue(null);
    renderPanel({ post, onError, connections: [connection] });
    await loadUserPanel();

    fireEvent.click(selectReauthorizationApplication());
    await waitFor(() => {
      expect(onError).toHaveBeenCalledTimes(1);
    });
    fireEvent.click(selectReauthorizationApplication());
    const fallback = await screen.findByRole("link", {
      name: "Continue managed reauthorization",
    });
    expect(fallback).toHaveAttribute(
      "href",
      "https://runtime.example/auth/managed-reauthorizations/recovered-exact-target",
    );
    expect(fallback).toHaveAttribute("rel", "noopener noreferrer");
    expect(keys).toHaveLength(2);
    expect(keys[1]).toBe(keys[0]);
  });

  it("reports queued provider revocation without claiming terminal completion", async () => {
    const post = vi.fn(() =>
      Promise.resolve(
        successful({
          ...connection,
          revision: 6,
          state: "active" as const,
          last_safe_outcome: "revocation_requested",
        }),
      ),
    );
    const { setMessage } = renderPanel({ post, connections: [connection] });
    await loadUserPanel();

    fireEvent.click(screen.getByRole("button", { name: "Revoke at provider" }));
    confirmDialog("Request revocation");
    await waitFor(() => {
      expect(setMessage).toHaveBeenCalledWith("Provider revocation queued (revocation_requested).");
    });
    expect(setMessage).not.toHaveBeenCalledWith(
      expect.stringMatching(/completed|revoked by the provider/iu),
    );
  });

  it("requires confirmation and submits exact user/session revisions", async () => {
    const { post, setMessage } = renderPanel();
    await loadUserPanel();

    fireEvent.click(screen.getByRole("button", { name: "Disable Project user" }));
    confirmDialog("Cancel");
    expect(post).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Disable Project user" }));
    confirmDialog("Disable user");
    await waitFor(() => {
      expect(post).toHaveBeenCalledWith(
        "/v1/projects/{project_id}/users/{user_id}/disable",
        expect.objectContaining({ body: { expected_security_revision: 4 } }),
      );
    });
    expect(setMessage).toHaveBeenCalledWith("Project user disabled.");

    fireEvent.click(screen.getByRole("button", { name: "Revoke Application session" }));
    confirmDialog("Revoke session");
    await waitFor(() => {
      expect(post).toHaveBeenCalledWith(
        expect.stringContaining("application-sessions"),
        expect.objectContaining({ body: { expected_session_revision: 7 } }),
      );
    });
    expect(screen.getAllByText("Status: revoked")).toHaveLength(1);

    fireEvent.click(screen.getByRole("button", { name: "Revoke Project browser session" }));
    confirmDialog("Revoke session");
    await waitFor(() => {
      expect(post).toHaveBeenCalledWith(
        expect.stringContaining("browser-sessions"),
        expect.objectContaining({ body: { expected_session_revision: 9 } }),
      );
    });
    expect(screen.getAllByText("Status: revoked")).toHaveLength(2);
  });

  it("refreshes lifecycle state and reports a stale-revision conflict", async () => {
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
    const { get } = renderPanel({
      post,
      onError,
      detailOnly: true,
      initialUserId: user.id,
      listUsers: [],
    });
    expect(await screen.findByRole("heading", { name: "Ada Lovelace" })).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Disable Project user" }));
    confirmDialog("Disable user");

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(conflict);
    });
    expect(
      get.mock.calls.filter(
        ([path]) => typeof path === "string" && path.endsWith("/users/{user_id}"),
      ).length,
    ).toBeGreaterThanOrEqual(2);
    expect(screen.getByRole("heading", { name: "Ada Lovelace" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Disable Project user" })).toBeEnabled();
  });
});
