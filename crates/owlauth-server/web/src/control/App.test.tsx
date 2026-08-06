import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";

import { ControlApp } from "./App";
import type { ProjectClientKey } from "./client";

function requestUrl(input: RequestInfo | URL): string {
  return input instanceof Request ? input.url : String(input);
}

function systemResponse() {
  return Response.json({
    product: "owlauth-server",
    provisioning: true,
    login_readiness: true,
    federated_project_auth: false,
  });
}

const project = {
  id: "project-1",
  public_id: "project_public_1",
  display_name: "Provider Project",
  belongs_to: null,
  status: "active",
  metadata_revision: 1,
  security_revision: 1,
} as const;

const application = {
  id: "application-1",
  project_id: project.id,
  public_id: "application_public_1",
  display_name: "Provider Application",
  application_type: "web",
  status: "active",
  metadata_revision: 1,
  security_revision: 1,
  configuration: { redirect_uris: [], allowed_origins: [], publishable_keys: ["publishable"] },
} as const;

function renderConsole(path = "/") {
  const router = createMemoryRouter([{ path: "*", element: <ControlApp /> }], {
    initialEntries: [path],
  });
  return render(<RouterProvider router={router} />);
}

async function unlock(key = "owl_ctrl_v1_test", heading = "Projects") {
  const input = screen.getByLabelText("Operator API key");
  fireEvent.change(input, { target: { value: key } });
  fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));
  await screen.findByRole("heading", { name: heading });
  return input as HTMLInputElement;
}

describe("Control application shell", () => {
  beforeEach(() => {
    document.head.innerHTML = '<meta name="owlauth-control-base" content="/admin/">';
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders a credential-free connection page before generic key verification", () => {
    renderConsole("/projects/private-resource");

    expect(screen.getByRole("heading", { name: "Connect to this deployment" })).toBeVisible();
    expect(screen.getByLabelText("Operator API key")).toHaveFocus();
    expect(screen.queryByRole("navigation", { name: "Resources" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("private-resource");
  });

  it("keeps the key out of rendered and persistent state and disposes it on lock", async () => {
    const requests: Request[] = [];
    const fetchImplementation = vi.fn<typeof fetch>((input) => {
      const request = input as Request;
      requests.push(request);
      return Promise.resolve(
        request.url.endsWith("/v1/system") ? systemResponse() : Response.json({ items: [] }),
      );
    });
    vi.stubGlobal("fetch", fetchImplementation);
    renderConsole();

    const input = await unlock();
    expect(input.value).toBe("");
    expect(document.body.textContent).not.toContain("owl_ctrl_v1_test");
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
    expect(requests).toHaveLength(2);
    expect(
      requests.every(
        (request) => request.headers.get("authorization") === "Bearer owl_ctrl_v1_test",
      ),
    ).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Lock console" }));
    expect(screen.getByRole("heading", { name: "Connect to this deployment" })).toBeVisible();
    expect(requests.every((request) => request.signal.aborted)).toBe(true);
  });

  it("keeps a verified key for a safe Project-directory retry without reporting denial", async () => {
    let projectReads = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const url = requestUrl(input);
        if (url.endsWith("/v1/system")) return Promise.resolve(systemResponse());
        projectReads += 1;
        return Promise.resolve(
          projectReads === 1
            ? Response.json(
                { code: "service_unavailable", detail: "temporary Project failure" },
                { status: 503 },
              )
            : Response.json({ items: [] }),
        );
      }),
    );
    renderConsole();
    fireEvent.change(screen.getByLabelText("Operator API key"), {
      target: { value: "verified-secret" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));

    expect(await screen.findByRole("heading", { name: "Projects are unavailable" })).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent("The operator key was verified");
    expect(screen.queryByLabelText("Operator API key")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("verified-secret");

    fireEvent.click(screen.getByRole("button", { name: "Retry Project directory" }));
    expect(await screen.findByRole("heading", { name: /^Projects$/u })).toBeVisible();
    expect(projectReads).toBe(2);
  });

  it("clears authenticated DOM on pagehide and persisted pageshow", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) =>
        Promise.resolve(
          requestUrl(input).endsWith("/v1/system")
            ? systemResponse()
            : Response.json({ items: [] }),
        ),
      ),
    );
    renderConsole();
    await unlock();

    act(() => {
      window.dispatchEvent(new Event("pagehide"));
    });
    expect(screen.getByRole("heading", { name: "Connect to this deployment" })).toBeVisible();

    const pageShow = new Event("pageshow");
    Object.defineProperty(pageShow, "persisted", { value: true });
    act(() => {
      window.dispatchEvent(pageShow);
    });
    expect(screen.queryByRole("navigation", { name: "Resources" })).not.toBeInTheDocument();
  });

  it("uses one bounded authentication failure and disposes denied credentials", async () => {
    let deniedRequest: Request | null = null;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        deniedRequest = input as Request;
        return Promise.resolve(
          Response.json(
            { code: "secret_server_reason", detail: "vendor detail must not render" },
            { status: 401 },
          ),
        );
      }),
    );
    renderConsole();
    fireEvent.change(screen.getByLabelText("Operator API key"), {
      target: { value: "denied-secret" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The API key could not be verified.",
    );
    expect(document.body.textContent).not.toContain("vendor detail");
    expect(document.body.textContent).not.toContain("denied-secret");
    await waitFor(() => {
      expect(deniedRequest?.signal.aborted).toBe(true);
    });
  });

  it("keeps polling serialized signing maintenance until the key becomes active", async () => {
    let signingKeyReads = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const request = input as Request;
        const url = new URL(request.url);
        if (url.pathname.endsWith("/v1/system")) return Promise.resolve(systemResponse());
        if (url.pathname.endsWith("/v1/projects") && request.method === "GET") {
          return Promise.resolve(Response.json({ items: [project] }));
        }
        if (url.pathname.endsWith(`/v1/projects/${project.id}/signing-keys`)) {
          signingKeyReads += 1;
          return Promise.resolve(
            Response.json({
              items: [
                {
                  id: "signing-key-1",
                  project_id: project.id,
                  kid: "kid_polling_regression",
                  algorithm: "EdDSA",
                  state: signingKeyReads < 3 ? "provisioning" : "active",
                  ring_revision: signingKeyReads < 3 ? 1 : 2,
                  signing_epoch: 1,
                  sign_not_before: null,
                  verify_not_after: null,
                  public_jwk: signingKeyReads < 3 ? null : { kid: "kid_polling_regression" },
                },
              ],
            }),
          );
        }
        return Promise.resolve(Response.json({ items: [] }));
      }),
    );

    renderConsole(`/projects/${project.id}/security/signing-keys`);
    await unlock("owl_ctrl_v1_test", "Signing keys");
    expect(await screen.findByText("provisioning")).toBeVisible();
    expect(await screen.findByText("active", {}, { timeout: 2_000 })).toBeVisible();
    expect(signingKeyReads).toBe(3);
    expect(screen.getByRole("button", { name: "Rotate signing key" })).toBeEnabled();
  });

  it("aborts a stale signing inventory read and never renders it in another Project", async () => {
    const otherProject = {
      ...project,
      id: "project-2",
      public_id: "project_public_2",
      display_name: "Second Project",
    };
    let staleRequest: Request | undefined;
    let resolveStale: ((response: Response) => void) | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const request = input as Request;
        const url = new URL(request.url);
        if (url.pathname.endsWith("/v1/system")) return Promise.resolve(systemResponse());
        if (url.pathname.endsWith("/v1/projects") && request.method === "GET") {
          return Promise.resolve(Response.json({ items: [project, otherProject] }));
        }
        if (url.pathname.endsWith(`/v1/projects/${project.id}/signing-keys`)) {
          staleRequest = request;
          return new Promise<Response>((resolve) => {
            resolveStale = resolve;
          });
        }
        if (url.pathname.endsWith(`/v1/projects/${otherProject.id}/signing-keys`)) {
          return Promise.resolve(
            Response.json({
              items: [
                {
                  id: "second-signing-key",
                  project_id: otherProject.id,
                  kid: "kid_second_project",
                  algorithm: "EdDSA",
                  state: "active",
                  ring_revision: 2,
                  signing_epoch: 1,
                  sign_not_before: null,
                  verify_not_after: null,
                  public_jwk: { kid: "kid_second_project" },
                },
              ],
            }),
          );
        }
        return Promise.resolve(Response.json({ items: [] }));
      }),
    );

    renderConsole(`/projects/${project.id}/security/signing-keys`);
    await unlock("owl_ctrl_v1_test", "Signing keys");
    await waitFor(() => {
      expect(staleRequest).toBeDefined();
    });
    fireEvent.change(screen.getByLabelText("Project context"), {
      target: { value: otherProject.id },
    });
    fireEvent.click(
      within(screen.getByRole("navigation", { name: "Resources" })).getByRole("link", {
        name: "Signing keys",
      }),
    );
    expect(await screen.findByText("kid_second_project")).toBeVisible();
    expect(staleRequest?.signal.aborted).toBe(true);

    await act(async () => {
      resolveStale?.(
        Response.json({
          items: [
            {
              id: "stale-signing-key",
              project_id: project.id,
              kid: "kid_stale_project",
              algorithm: "EdDSA",
              state: "active",
              ring_revision: 2,
              signing_epoch: 1,
              sign_not_before: null,
              verify_not_after: null,
              public_jwk: { kid: "kid_stale_project" },
            },
          ],
        }),
      );
      await Promise.resolve();
    });
    expect(screen.queryByText("kid_stale_project")).not.toBeInTheDocument();
    expect(screen.getByText("kid_second_project")).toBeVisible();
  });

  it("does not let a completed mutation refresh or message a different Project", async () => {
    const otherProject = {
      ...project,
      id: "project-2",
      public_id: "project_public_2",
      display_name: "Second Project",
    };
    let firstProjectReads = 0;
    let resolveRotation: ((response: Response) => void) | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const request = input as Request;
        const url = new URL(request.url);
        if (url.pathname.endsWith("/v1/system")) return Promise.resolve(systemResponse());
        if (url.pathname.endsWith("/v1/projects") && request.method === "GET") {
          return Promise.resolve(Response.json({ items: [project, otherProject] }));
        }
        if (
          url.pathname.endsWith(`/v1/projects/${project.id}/signing-keys/rotate`) &&
          request.method === "POST"
        ) {
          return new Promise<Response>((resolve) => {
            resolveRotation = resolve;
          });
        }
        if (
          url.pathname.endsWith(`/v1/projects/${project.id}/signing-keys`) &&
          request.method === "GET"
        ) {
          firstProjectReads += 1;
          return Promise.resolve(
            Response.json({
              items: [
                {
                  id: "first-signing-key",
                  project_id: project.id,
                  kid: "kid_first_project",
                  algorithm: "EdDSA",
                  state: "active",
                  ring_revision: 2,
                  signing_epoch: 1,
                  sign_not_before: null,
                  verify_not_after: null,
                  public_jwk: { kid: "kid_first_project" },
                },
              ],
            }),
          );
        }
        if (url.pathname.endsWith(`/v1/projects/${otherProject.id}/signing-keys`)) {
          return Promise.resolve(
            Response.json({
              items: [
                {
                  id: "second-signing-key",
                  project_id: otherProject.id,
                  kid: "kid_second_project",
                  algorithm: "EdDSA",
                  state: "active",
                  ring_revision: 2,
                  signing_epoch: 1,
                  sign_not_before: null,
                  verify_not_after: null,
                  public_jwk: { kid: "kid_second_project" },
                },
              ],
            }),
          );
        }
        return Promise.resolve(Response.json({ items: [] }));
      }),
    );

    renderConsole(`/projects/${project.id}/security/signing-keys`);
    await unlock("owl_ctrl_v1_test", "Signing keys");
    expect(await screen.findByText("kid_first_project")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Rotate signing key" }));
    await waitFor(() => {
      expect(resolveRotation).toBeDefined();
    });

    fireEvent.change(screen.getByLabelText("Project context"), {
      target: { value: otherProject.id },
    });
    fireEvent.click(
      within(screen.getByRole("navigation", { name: "Resources" })).getByRole("link", {
        name: "Signing keys",
      }),
    );
    expect(await screen.findByText("kid_second_project")).toBeVisible();
    expect(screen.queryByText("kid_first_project")).not.toBeInTheDocument();

    await act(async () => {
      resolveRotation?.(
        Response.json({
          id: "pending-first-rotation",
          project_id: project.id,
          kid: "kid_pending_first_rotation",
          algorithm: "EdDSA",
          state: "provisioning",
          ring_revision: 2,
          signing_epoch: 1,
          sign_not_before: null,
          verify_not_after: null,
          public_jwk: null,
        }),
      );
      await Promise.resolve();
    });
    expect(firstProjectReads).toBe(1);
    expect(screen.queryByText(/Signing key rotation accepted/u)).not.toBeInTheDocument();
    expect(screen.queryByText("kid_first_project")).not.toBeInTheDocument();
    expect(screen.getByText("kid_second_project")).toBeVisible();
  });

  it("requires reviewed Custom OIDC preflight and discards its write-only secret", async () => {
    const submittedBodies: unknown[] = [];
    const policyUpdates: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input) => {
        const request = input as Request;
        const url = new URL(request.url);
        if (url.pathname.endsWith("/v1/system")) return systemResponse();
        if (url.pathname.endsWith("/v1/projects") && request.method === "GET") {
          return Response.json({ items: [project] });
        }
        if (url.pathname.endsWith(`/v1/projects/${project.id}/applications`)) {
          return Response.json({ items: [application] });
        }
        if (url.pathname.endsWith(`/v1/projects/${project.id}/providers/oidc/preflight`)) {
          return Response.json({
            admitted_endpoint_origins: ["https://issuer.example"],
            authorization_code_supported: true,
            canonical_issuer: "https://issuer.example/",
            exact_scopes: ["openid", "profile", "email"],
            managed_profile_supported: true,
            pkce_s256_supported: true,
            policy_mode: "allow_all",
            policy_revision: 1,
            rs256_id_tokens_supported: true,
          });
        }
        if (url.pathname.endsWith(`/v1/projects/${project.id}/provider-egress-policy`)) {
          if (request.method === "PUT") {
            const body = (await request.clone().json()) as unknown;
            policyUpdates.push(body);
            return Response.json({
              project_id: project.id,
              mode: "exact_origins",
              exact_origins: ["https://issuer.example"],
              revision: 2,
            });
          }
          return Response.json({
            project_id: project.id,
            mode: "allow_all",
            exact_origins: [],
            revision: 1,
          });
        }
        if (url.pathname.endsWith(`/v1/projects/${project.id}/providers`)) {
          if (request.method === "POST") {
            submittedBodies.push((await request.clone().json()) as unknown);
            return Response.json({
              id: "provider-1",
              project_id: project.id,
              provider_key: "custom-provider",
              display_name: "Custom provider",
              kind: "oidc",
              issuer: "https://issuer.example/",
              client_id: "client-id",
              callback_url: "https://control.example/callback",
              status: "active",
              revision: 1,
              assigned_application_ids: [],
              login_supported: true,
              identity_proof_supported: true,
              managed_profile: {
                supported: true,
                enabled: false,
                exact_scopes: [],
                profile_schema: "oidc.v1",
                read_retry_safe: true,
                renewal_idempotent_replay: true,
                supports_revocation: true,
              },
            });
          }
          return Response.json({ items: [] });
        }
        throw new Error(`Unexpected request: ${request.method} ${url.pathname}`);
      }),
    );
    renderConsole(`/projects/${project.id}/authentication/providers`);
    await unlock("owl_ctrl_v1_test", "Authentication providers");

    fireEvent.click(await screen.findByRole("button", { name: "Add provider" }));
    const chooser = screen.getByRole("dialog", { name: "Choose a provider" });
    fireEvent.click(within(chooser).getByRole("button", { name: /Custom OIDC/u }));
    let dialog = screen.getByRole("dialog", { name: "Add Custom OIDC" });
    const addProvider = within(dialog).getByRole("button", { name: "Add provider" });
    expect(addProvider).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Canonical HTTPS issuer"), {
      target: { value: "https://issuer.example" },
    });
    const secretInput = within(dialog).getByLabelText("Client secret");
    fireEvent.change(secretInput, { target: { value: "discard-before-preflight" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Run preflight" }));
    expect(secretInput).toHaveValue("");
    await within(dialog).findByRole("heading", { name: "Preflight result" });
    expect(within(dialog).getByText("Safe discovered origins are allowed")).toBeVisible();
    expect(within(dialog).getByText("https://issuer.example")).toBeVisible();
    fireEvent.change(secretInput, { target: { value: "discard-before-policy-change" } });

    fireEvent.click(
      within(dialog).getByRole("button", { name: "Adopt reviewed origins as exact policy" }),
    );
    await waitFor(() => {
      expect(policyUpdates).toEqual([
        { mode: "exact_origins", exact_origins: ["https://issuer.example"], expected_revision: 1 },
      ]);
    });
    expect(within(dialog).queryByRole("heading", { name: "Preflight result" })).toBeNull();
    expect(secretInput).toHaveValue("");
    expect(addProvider).toBeDisabled();

    fireEvent.click(within(dialog).getByRole("button", { name: "Run preflight" }));
    await within(dialog).findByRole("heading", { name: "Preflight result" });
    dialog = screen.getByRole("dialog", { name: "Add Custom OIDC" });
    fireEvent.change(within(dialog).getByLabelText("Provider key"), {
      target: { value: "custom-provider" },
    });
    fireEvent.change(within(dialog).getByLabelText("Display name"), {
      target: { value: "Custom provider" },
    });
    fireEvent.change(within(dialog).getByLabelText("Client ID"), {
      target: { value: "client-id" },
    });
    fireEvent.change(within(dialog).getByLabelText("Client secret"), {
      target: { value: "write-only-secret" },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Add provider" }));

    await waitFor(() => {
      expect(submittedBodies).toEqual([
        expect.objectContaining({
          kind: "oidc",
          issuer: "https://issuer.example/",
          client_secret: "write-only-secret",
        }),
      ]);
    });
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Add Custom OIDC" })).toBeNull();
    });
    expect(document.body.textContent).not.toContain("write-only-secret");
  });

  it("keeps a failed Project policy distinct from loading and offers a safe retry", async () => {
    let policyReads = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const request = input as Request;
        const url = new URL(request.url);
        if (url.pathname.endsWith("/v1/system")) return Promise.resolve(systemResponse());
        if (url.pathname.endsWith("/v1/projects") && request.method === "GET") {
          return Promise.resolve(Response.json({ items: [project] }));
        }
        if (url.pathname.endsWith(`/v1/projects/${project.id}/policy`)) {
          policyReads += 1;
          return Promise.resolve(
            policyReads === 1
              ? Response.json(
                  { code: "service_unavailable", detail: "temporary policy failure" },
                  { status: 503 },
                )
              : Response.json({
                  project_id: project.id,
                  access_token_lifetime_seconds: 900,
                  browser_session_reuse: false,
                  claims_revision: 2,
                  session_revision: 3,
                }),
          );
        }
        throw new Error(`Unexpected request: ${request.method} ${url.pathname}`);
      }),
    );

    renderConsole(`/projects/${project.id}/settings`);
    await unlock("owl_ctrl_v1_test", "Project settings");
    expect(await screen.findByRole("button", { name: "Retry Project policy" })).toBeVisible();
    expect(screen.queryByText("Loading Project policy")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Retry Project policy" }));
    expect(await screen.findByText("15 minutes")).toBeVisible();
    expect(policyReads).toBe(2);
  });

  it("routes client keys through one-time reveal, explicit disposal, and revisioned revoke", async () => {
    const oneTimeCredential = `owl_client_v1.${"A".repeat(22)}.${"B".repeat(43)}`;
    const firstKey: ProjectClientKey = {
      id: "client-key-1",
      project_id: project.id,
      public_key_id: "AAAAAAAAAAAAAAAAAAAAAA",
      display_prefix: "owl_client_v1.AAAAAA",
      label: "production backend",
      status: "active",
      revision: 3,
      digest_key_version: 1,
      created_at: "2026-08-05T12:00:00Z",
      credential_acknowledged_at: "2026-08-05T12:01:00Z",
      last_used_at: null,
      revoked_at: null,
    };
    let createdKey: ProjectClientKey = {
      ...firstKey,
      id: "client-key-2",
      public_key_id: "BBBBBBBBBBBBBBBBBBBBBB",
      display_prefix: "owl_client_v1.BBBBBB",
      label: "replacement backend",
      revision: 1,
      credential_acknowledged_at: null,
    };
    let inventory: ProjectClientKey[] = [firstKey];
    const mutationBodies: unknown[] = [];
    const createIdempotencyKeys: string[] = [];
    let createRequests = 0;
    let acknowledgementRequests = 0;
    const acknowledgementIdempotencyKeys: string[] = [];
    const clipboardWrite = vi.fn(() => Promise.resolve());
    const navigatorWithClipboard = Object.create(navigator) as Navigator;
    Object.defineProperty(navigatorWithClipboard, "clipboard", {
      configurable: true,
      value: { writeText: clipboardWrite },
    });
    vi.stubGlobal("navigator", navigatorWithClipboard);
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input) => {
        const request = input as Request;
        const url = new URL(request.url);
        if (url.pathname.endsWith("/v1/system")) return systemResponse();
        if (url.pathname.endsWith("/v1/projects") && request.method === "GET") {
          return Response.json({ items: [project] });
        }
        if (url.pathname.endsWith(`/v1/projects/${project.id}/client-keys`)) {
          if (request.method === "POST") {
            mutationBodies.push(await request.clone().json());
            createIdempotencyKeys.push(request.headers.get("idempotency-key") ?? "");
            createRequests += 1;
            if (createRequests === 1) {
              return Response.json(
                { code: "request_timeout", detail: "The request outcome is not yet known." },
                { status: 408 },
              );
            }
            inventory = [firstKey, createdKey];
            return Response.json(
              { key: createdKey, credential: oneTimeCredential },
              { status: 201 },
            );
          }
          return Response.json({
            items: inventory,
            next_cursor: null,
            active_unacknowledged_key:
              inventory.find(
                (key) => key.status === "active" && key.credential_acknowledged_at == null,
              ) ?? null,
          });
        }
        if (
          url.pathname.endsWith(
            `/v1/projects/${project.id}/client-keys/${createdKey.id}/acknowledge`,
          )
        ) {
          mutationBodies.push(await request.clone().json());
          acknowledgementIdempotencyKeys.push(request.headers.get("idempotency-key") ?? "");
          acknowledgementRequests += 1;
          if (acknowledgementRequests === 1) {
            return Response.json(
              { code: "service_unavailable", detail: "acknowledgement temporarily unavailable" },
              { status: 503 },
            );
          }
          createdKey = {
            ...createdKey,
            revision: 2,
            credential_acknowledged_at: "2026-08-05T12:02:00Z",
          };
          inventory = [firstKey, createdKey];
          return Response.json(createdKey);
        }
        if (url.pathname.endsWith(`/v1/projects/${project.id}/client-keys/${firstKey.id}/revoke`)) {
          mutationBodies.push(await request.clone().json());
          inventory = [{ ...firstKey, status: "revoked", revision: 4 }, createdKey];
          return Response.json(inventory[0]);
        }
        throw new Error(`Unexpected request: ${request.method} ${url.pathname}`);
      }),
    );

    renderConsole(`/projects/${project.id}/security/client-keys`);
    await unlock("owl_ctrl_v1_test", "Client API keys");
    expect(screen.getByRole("link", { name: "Client API keys" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(await screen.findByText("production backend")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Create client key" }));
    const createDialog = screen.getByRole("dialog", { name: "Create client key" });
    fireEvent.change(within(createDialog).getByLabelText("Key label"), {
      target: { value: "replacement backend" },
    });
    fireEvent.click(within(createDialog).getByRole("button", { name: "Create client key" }));

    const reveal = await screen.findByRole("dialog", { name: "Store this client key now" });
    expect(within(reveal).getByText(oneTimeCredential)).toBeVisible();
    expect(createIdempotencyKeys).toHaveLength(2);
    expect(createIdempotencyKeys[0]).not.toBe("");
    expect(createIdempotencyKeys[1]).toBe(createIdempotencyKeys[0]);
    expect(within(reveal).queryByRole("button", { name: "Close dialog" })).toBeNull();
    const acknowledge = within(reveal).getByRole("button", { name: "I saved this key" });
    expect(acknowledge).toBeDisabled();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.getByRole("dialog", { name: "Store this client key now" })).toBeVisible();
    fireEvent.click(within(reveal).getByRole("button", { name: "Copy credential" }));
    await waitFor(() => {
      expect(clipboardWrite).toHaveBeenCalledWith(oneTimeCredential);
    });
    fireEvent.click(
      within(reveal).getByLabelText(
        "I stored this credential in the customer backend's secret manager.",
      ),
    );
    fireEvent.click(acknowledge);
    expect(await within(reveal).findByText(/temporarily unavailable/u)).toBeVisible();
    expect(within(reveal).getByText(oneTimeCredential)).toBeVisible();
    fireEvent.click(acknowledge);
    await waitFor(() => {
      expect(screen.queryByText(oneTimeCredential)).toBeNull();
    });
    expect(acknowledgementIdempotencyKeys).toHaveLength(2);
    expect(acknowledgementIdempotencyKeys[0]).not.toBe("");
    expect(acknowledgementIdempotencyKeys[1]).toBe(acknowledgementIdempotencyKeys[0]);
    expect(mutationBodies).toContainEqual({ confirm_stored: true, expected_revision: 1 });

    const revoke = screen.getAllByRole("button", { name: "Revoke" })[0];
    if (revoke === undefined) throw new Error("Revoke action is missing");
    fireEvent.click(revoke);
    const confirmation = await screen.findByRole("dialog", { name: "Revoke client key" });
    expect(confirmation).toHaveTextContent("production backend");
    fireEvent.click(within(confirmation).getByRole("button", { name: "Revoke client key" }));
    await waitFor(() => {
      expect(mutationBodies).toContainEqual({ confirm: true, expected_revision: 3 });
    });
    expect(document.body.textContent).not.toContain(oneTimeCredential);
  });

  it.each(["unauthorized", "acknowledged", "revoked"] as const)(
    "clears a revealed credential when acknowledgement resolves as %s",
    async (resolution) => {
      const oneTimeCredential = `owl_client_v1.${"D".repeat(22)}.${"E".repeat(43)}`;
      let issued = false;
      let exactReads = 0;
      let serverKey: ProjectClientKey = {
        id: "client-key-concurrent",
        project_id: project.id,
        public_key_id: "DDDDDDDDDDDDDDDDDDDDDD",
        display_prefix: "owl_client_v1.DDDDDD",
        label: "concurrent backend",
        status: "active",
        revision: 1,
        digest_key_version: 1,
        created_at: "2026-08-05T12:00:00Z",
        credential_acknowledged_at: null,
        last_used_at: null,
        revoked_at: null,
      };
      vi.stubGlobal(
        "fetch",
        vi.fn<typeof fetch>(async (input) => {
          await Promise.resolve();
          const request = input as Request;
          const url = new URL(request.url);
          if (url.pathname.endsWith("/v1/system")) return systemResponse();
          if (url.pathname.endsWith("/v1/projects") && request.method === "GET") {
            return Response.json({ items: [project] });
          }
          if (url.pathname.endsWith(`/v1/projects/${project.id}/client-keys`)) {
            if (request.method === "POST") {
              issued = true;
              return Response.json(
                { key: serverKey, credential: oneTimeCredential },
                { status: 201 },
              );
            }
            return Response.json({
              items: issued ? [serverKey] : [],
              next_cursor: null,
              active_unacknowledged_key:
                issued &&
                serverKey.status === "active" &&
                serverKey.credential_acknowledged_at == null
                  ? serverKey
                  : null,
            });
          }
          if (
            url.pathname.endsWith(
              `/v1/projects/${project.id}/client-keys/${serverKey.id}/acknowledge`,
            )
          ) {
            if (resolution === "unauthorized") {
              return Response.json(
                { code: "unauthorized", detail: "operator key expired" },
                { status: 401 },
              );
            }
            serverKey =
              resolution === "acknowledged"
                ? {
                    ...serverKey,
                    revision: 2,
                    credential_acknowledged_at: "2026-08-05T12:01:00Z",
                  }
                : {
                    ...serverKey,
                    status: "revoked",
                    revision: 2,
                    revoked_at: "2026-08-05T12:01:00Z",
                  };
            return Response.json(
              { code: "revision_conflict", detail: "another operator changed this key" },
              { status: 409 },
            );
          }
          if (
            url.pathname.endsWith(`/v1/projects/${project.id}/client-keys/${serverKey.id}`) &&
            request.method === "GET"
          ) {
            exactReads += 1;
            return Response.json(serverKey);
          }
          throw new Error(`Unexpected request: ${request.method} ${url.pathname}`);
        }),
      );

      renderConsole(`/projects/${project.id}/security/client-keys`);
      await unlock("owl_ctrl_v1_test", "Client API keys");
      await waitFor(() => {
        expect(
          screen
            .getAllByRole("button", { name: "Create client key" })
            .every((button) => !button.hasAttribute("disabled")),
        ).toBe(true);
      });
      const createButtons = screen.getAllByRole("button", { name: "Create client key" });
      const openCreate = createButtons[0];
      if (openCreate === undefined) throw new Error("Create client-key action is missing");
      fireEvent.click(openCreate);
      const createDialog = screen.getByRole("dialog", { name: "Create client key" });
      fireEvent.change(within(createDialog).getByLabelText("Key label"), {
        target: { value: "concurrent backend" },
      });
      fireEvent.click(within(createDialog).getByRole("button", { name: "Create client key" }));
      const reveal = await screen.findByRole("dialog", { name: "Store this client key now" });
      expect(within(reveal).getByText(oneTimeCredential)).toBeVisible();
      fireEvent.click(
        within(reveal).getByLabelText(
          "I stored this credential in the customer backend's secret manager.",
        ),
      );
      fireEvent.click(within(reveal).getByRole("button", { name: "I saved this key" }));

      await waitFor(() => {
        expect(screen.queryByText(oneTimeCredential)).toBeNull();
      });
      if (resolution === "unauthorized") {
        expect(screen.getByRole("heading", { name: "Connect to this deployment" })).toBeVisible();
        expect(screen.queryByRole("heading", { name: "Client API keys" })).toBeNull();
        expect(exactReads).toBe(0);
      } else if (resolution === "acknowledged") {
        expect(screen.getByText(/storage was acknowledged/u)).toBeVisible();
        expect(exactReads).toBe(1);
      } else {
        expect(screen.getByText(/revoked by another operator/u)).toBeVisible();
        expect(exactReads).toBe(1);
      }
    },
  );

  it("blocks replacement after unresolved client-key creation until the implicated key is revoked", async () => {
    const existingKey: ProjectClientKey = {
      id: "client-key-existing",
      project_id: project.id,
      public_key_id: "AAAAAAAAAAAAAAAAAAAAAA",
      display_prefix: "owl_client_v1.AAAAAA",
      label: "existing backend",
      status: "active",
      revision: 1,
      digest_key_version: 1,
      created_at: "2026-08-05T12:00:00Z",
      credential_acknowledged_at: "2026-08-05T12:01:00Z",
      last_used_at: null,
      revoked_at: null,
    };
    const implicatedKey: ProjectClientKey = {
      ...existingKey,
      id: "client-key-implicated",
      public_key_id: "CCCCCCCCCCCCCCCCCCCCCC",
      display_prefix: "owl_client_v1.CCCCCC",
      label: "uncertain backend",
      credential_acknowledged_at: null,
    };
    let inventory: ProjectClientKey[] = [existingKey];
    let inventoryReads = 0;
    let createRequests = 0;
    let reconciliationPagination = false;
    let failNextPostRevokeInventory = false;
    let paginatedReconciliationReads = 0;
    const idempotencyKeys: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input) => {
        await Promise.resolve();
        const request = input as Request;
        const url = new URL(request.url);
        if (url.pathname.endsWith("/v1/system")) return systemResponse();
        if (url.pathname.endsWith("/v1/projects") && request.method === "GET") {
          return Response.json({ items: [project] });
        }
        if (url.pathname.endsWith(`/v1/projects/${project.id}/client-keys`)) {
          if (request.method === "GET") {
            inventoryReads += 1;
            if (inventoryReads === 2 || failNextPostRevokeInventory) {
              failNextPostRevokeInventory = false;
              return Response.json(
                { code: "service_unavailable", detail: "inventory temporarily unavailable" },
                { status: 503 },
              );
            }
            if (reconciliationPagination) {
              paginatedReconciliationReads += 1;
              if (url.searchParams.get("cursor") === null) {
                return Response.json({
                  items: [existingKey],
                  next_cursor: "implicated-page",
                  active_unacknowledged_key:
                    inventory.find(
                      (key) => key.status === "active" && key.credential_acknowledged_at == null,
                    ) ?? null,
                });
              }
              reconciliationPagination = false;
              return Response.json({
                items: [implicatedKey],
                next_cursor: null,
                active_unacknowledged_key:
                  inventory.find(
                    (key) => key.status === "active" && key.credential_acknowledged_at == null,
                  ) ?? null,
              });
            }
            return Response.json({
              items: inventory,
              next_cursor: null,
              active_unacknowledged_key:
                inventory.find(
                  (key) => key.status === "active" && key.credential_acknowledged_at == null,
                ) ?? null,
            });
          }
          createRequests += 1;
          idempotencyKeys.push(request.headers.get("idempotency-key") ?? "");
          if (createRequests === 1) {
            return Response.json(
              { code: "request_timeout", detail: "The create outcome is not known." },
              { status: 408 },
            );
          }
          inventory = [implicatedKey, existingKey];
          reconciliationPagination = true;
          return Response.json(
            {
              code: "secret_unavailable",
              detail:
                "This idempotent create completed, but its one-time credential cannot be shown again.",
            },
            { status: 409 },
          );
        }
        if (
          url.pathname.endsWith(`/v1/projects/${project.id}/client-keys/${implicatedKey.id}/revoke`)
        ) {
          inventory = [{ ...implicatedKey, status: "revoked", revision: 2 }, existingKey];
          failNextPostRevokeInventory = true;
          return Response.json(inventory[0]);
        }
        throw new Error(`Unexpected request: ${request.method} ${url.pathname}`);
      }),
    );

    renderConsole(`/projects/${project.id}/security/client-keys`);
    await unlock("owl_ctrl_v1_test", "Client API keys");
    expect(await screen.findByText("existing backend")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Create client key" }));
    const createDialog = screen.getByRole("dialog", { name: "Create client key" });
    fireEvent.change(within(createDialog).getByLabelText("Key label"), {
      target: { value: "uncertain backend" },
    });
    fireEvent.click(within(createDialog).getByRole("button", { name: "Create client key" }));

    expect(
      await screen.findByText(/Replacement creation is blocked for the unresolved/u),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Create client key" })).toBeDisabled();
    expect(screen.getByText(/authoritative delivery gate could not be refreshed/u)).toBeVisible();
    expect(document.body.textContent).not.toContain("The safe inventory was refreshed");
    expect(idempotencyKeys).toHaveLength(2);
    expect(idempotencyKeys[0]).not.toBe("");
    expect(idempotencyKeys[1]).toBe(idempotencyKeys[0]);

    fireEvent.click(screen.getByRole("button", { name: "Reconcile delivery gate" }));
    await screen.findByText("Unresolved create — credential was never revealed; revoke this key");
    const sameMountImplicatedRow = screen
      .getAllByText("uncertain backend")
      .map((node) => node.closest("tr"))
      .find((row): row is HTMLTableRowElement => row !== null);
    if (sameMountImplicatedRow === undefined)
      throw new Error("Implicated client-key row is missing");
    expect(
      within(sameMountImplicatedRow).queryByRole("button", {
        name: "Confirm stored credential",
      }),
    ).toBeNull();
    expect(
      within(sameMountImplicatedRow).getByRole("button", { name: "Revoke implicated key" }),
    ).toBeVisible();

    reconciliationPagination = true;
    paginatedReconciliationReads = 0;
    fireEvent.click(screen.getByRole("button", { name: "Lock console" }));
    await unlock("owl_ctrl_v1_test", "Projects");
    fireEvent.click(screen.getByRole("link", { name: "Provider Project" }));
    fireEvent.click(await screen.findByRole("link", { name: "Client API keys" }));
    expect(await screen.findByRole("heading", { name: "Client API keys" })).toBeVisible();
    expect(await screen.findByText("existing backend")).toBeVisible();

    // The local uncertain-create marker is intentionally gone after remount. One bounded server
    // response reconstructs the durable unacknowledged gate even though the implicated key is not
    // in the historical page, and no replacement mutation is sent.
    fireEvent.click(screen.getByRole("button", { name: "Create client key" }));
    expect(await screen.findByText("Storage unconfirmed — creation blocked")).toBeVisible();
    expect(paginatedReconciliationReads).toBe(1);
    expect(screen.getByRole("button", { name: "Create client key" })).toBeDisabled();
    expect(createRequests).toBe(2);
    const implicatedRow = screen.getByText("uncertain backend").closest("tr");
    if (implicatedRow === null) throw new Error("Implicated client-key row is missing");
    fireEvent.click(within(implicatedRow).getByRole("button", { name: "Revoke" }));
    const confirmation = await screen.findByRole("dialog", { name: "Revoke client key" });
    fireEvent.click(within(confirmation).getByRole("button", { name: "Revoke client key" }));
    await waitFor(() => {
      expect(screen.queryByText(/Replacement creation is blocked for the unresolved/u)).toBeNull();
    });
    expect(screen.getByRole("button", { name: "Create client key" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Retry inventory" }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Create client key" })).toBeEnabled();
    });
  });

  it("uses the qualified Application read and keeps load failures distinct from not found", async () => {
    const detailPaths: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const request = input as Request;
        const url = new URL(request.url);
        if (url.pathname.endsWith("/v1/system")) return Promise.resolve(systemResponse());
        if (url.pathname.endsWith("/v1/projects") && request.method === "GET") {
          return Promise.resolve(Response.json({ items: [project] }));
        }
        if (
          url.pathname.endsWith(`/v1/projects/${project.id}/applications/${application.id}`) &&
          request.method === "GET"
        ) {
          detailPaths.push(url.pathname);
          return Promise.resolve(
            Response.json(
              { code: "service_unavailable", detail: "temporary Application failure" },
              { status: 503 },
            ),
          );
        }
        throw new Error(`Unexpected request: ${request.method} ${url.pathname}`);
      }),
    );

    renderConsole(`/projects/${project.id}/applications/${application.id}`);
    await unlock("owl_ctrl_v1_test", "Application");
    expect(await screen.findByRole("heading", { name: "Application unavailable" })).toBeVisible();
    expect(screen.getByText(/No missing-resource conclusion was made\./u)).toBeVisible();
    expect(screen.queryByText("Application not found")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Retry Application" }));
    await waitFor(() => {
      expect(detailPaths).toHaveLength(2);
    });
    expect(
      detailPaths.every(
        (path) => path === `/admin/v1/projects/${project.id}/applications/${application.id}`,
      ),
    ).toBe(true);
  });

  it("renders the routed Project-first workspace and focused create dialog", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) =>
        Promise.resolve(
          requestUrl(input).endsWith("/v1/system")
            ? systemResponse()
            : Response.json({ items: [] }),
        ),
      ),
    );
    renderConsole();
    await unlock();

    expect(screen.getByRole("navigation", { name: "Resources" })).toBeVisible();
    expect(screen.getByText("No Projects yet")).toBeVisible();
    expect(screen.queryByLabelText("Display name")).not.toBeInTheDocument();

    const [createProject] = screen.getAllByRole("button", { name: "Create Project" });
    if (createProject === undefined) throw new Error("Create Project action is missing");
    fireEvent.click(createProject);
    expect(screen.getByRole("dialog", { name: "Create Project" })).toBeVisible();
    expect(screen.getByLabelText("Display name")).toHaveFocus();
    fireEvent.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(screen.queryByRole("dialog", { name: "Create Project" })).not.toBeInTheDocument();
  });
});
