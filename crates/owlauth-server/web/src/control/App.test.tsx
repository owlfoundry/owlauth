import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";

import { ControlApp } from "./App";

const policy = {
  project_id: "11111111-1111-4111-8111-111111111111",
  access_token_lifetime_seconds: 900,
  browser_session_reuse: false,
  claims_revision: 1,
  session_revision: 1,
};

const projectionPolicy = {
  project_id: "11111111-1111-4111-8111-111111111111",
  application_id: null,
  verified_email_enabled: false,
  revision: 1,
  expansion_operation_id: null,
};

const project = {
  id: "11111111-1111-4111-8111-111111111111",
  public_id: "prj_public123",
  display_name: "Production",
  belongs_to: null,
  status: "active",
  metadata_revision: 1,
  security_revision: 1,
};

function requestUrl(input: RequestInfo | URL): string {
  return input instanceof Request ? input.url : String(input);
}

function renderConsole() {
  return render(
    <MemoryRouter>
      <ControlApp />
    </MemoryRouter>,
  );
}

describe("Control shell", () => {
  beforeEach(() => {
    document.head.innerHTML = '<meta name="owlauth-control-base" content="/admin/">';
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("verifies, clears, and disposes a page-memory operator key", async () => {
    const fetchImplementation = vi.fn<typeof fetch>((input) => {
      const url = requestUrl(input);
      if (url.endsWith("/v1/system")) {
        return Promise.resolve(
          Response.json({
            product: "owlauth-server",
            provisioning: true,
            login_readiness: true,
            federated_project_auth: false,
          }),
        );
      }
      return Promise.resolve(Response.json({ items: [] }));
    });
    vi.stubGlobal("fetch", fetchImplementation);
    const { unmount } = renderConsole();

    const input = screen.getByLabelText("Operator API key");
    fireEvent.change(input, { target: { value: "owl_ctrl_v1_test" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));

    expect(await screen.findByText("No Projects yet.")).toBeVisible();
    expect((input as HTMLInputElement).value).toBe("");
    expect(document.body.textContent).not.toContain("owl_ctrl_v1_test");
    expect(fetchImplementation).toHaveBeenCalledTimes(2);

    fireEvent.click(screen.getByRole("button", { name: "Lock console" }));
    expect(screen.getByRole("button", { name: "Unlock console" })).toBeVisible();
    unmount();
  });

  it("disposes the active client and aborts work when the operator locks", async () => {
    let projectsRequest: Request | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const request = input as Request;
        if (request.url.endsWith("/v1/system")) {
          return Promise.resolve(
            Response.json({
              product: "owlauth-server",
              provisioning: true,
              login_readiness: true,
              federated_project_auth: false,
            }),
          );
        }
        projectsRequest = request;
        return new Promise<Response>((_resolve, reject) => {
          request.signal.addEventListener(
            "abort",
            () => {
              reject(new Error("Control client was disposed"));
            },
            { once: true },
          );
        });
      }),
    );
    renderConsole();
    fireEvent.change(screen.getByLabelText("Operator API key"), { target: { value: "temporary" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));

    await waitFor(() => {
      expect(projectsRequest).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "Lock console" }));
    expect(projectsRequest?.signal.aborted).toBe(true);
    expect(screen.getByRole("button", { name: "Unlock console" })).toBeVisible();
  });

  it("aborts an unlock that completes after unmount", async () => {
    let resolveRequest: ((response: Response) => void) | undefined;
    let observedRequest: Request | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        observedRequest = input as Request;
        return new Promise<Response>((resolve) => {
          resolveRequest = resolve;
        });
      }),
    );
    const { unmount } = renderConsole();
    fireEvent.change(screen.getByLabelText("Operator API key"), { target: { value: "temporary" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));
    await waitFor(() => {
      expect(observedRequest).toBeDefined();
    });
    unmount();
    expect(observedRequest?.signal.aborted).toBe(true);
    resolveRequest?.(
      Response.json({
        product: "owlauth-server",
        provisioning: true,
        login_readiness: true,
        federated_project_auth: false,
      }),
    );
  });

  it("renders provisioning controls and clears a submitted provider secret", async () => {
    let providerBody: unknown;
    const fetchImplementation = vi.fn<typeof fetch>(async (input) => {
      const request = input as Request;
      const url = request.url;
      if (url.endsWith("/v1/system")) {
        return Response.json({
          product: "owlauth-server",
          provisioning: true,
          login_readiness: true,
          federated_project_auth: false,
        });
      }
      if (url.endsWith("/v1/projects") && request.method === "GET") {
        return Response.json({ items: [project] });
      }
      if (url.endsWith("/projection-policy"))
        return Promise.resolve(Response.json(projectionPolicy));
      if (url.includes("/applications")) return Response.json({ items: [] });
      if (url.includes("/signing-keys")) return Response.json({ items: [] });
      if (url.endsWith("/policy") && request.method === "GET") {
        return Response.json(policy);
      }
      if (url.endsWith("/providers") && request.method === "GET") {
        return Response.json({ items: [] });
      }
      if (url.endsWith("/providers") && request.method === "POST") {
        providerBody = await request.json();
        return Response.json({
          id: "22222222-2222-4222-8222-222222222222",
          project_id: project.id,
          provider_key: "workforce",
          kind: "oidc",
          display_name: "Workforce",
          issuer: "https://accounts.example/",
          client_id: "client",
          callback_url: "https://identity.example/callback",
          status: "active",
          revision: 2,
          assigned_application_ids: [],
          managed_profile: {
            supported: true,
            enabled: true,
            exact_scopes: ["openid", "profile", "offline_access"],
            profile_schema: "oidc_userinfo_v1",
            read_retry_safe: true,
            renewal_idempotent_replay: false,
            supports_revocation: true,
          },
        });
      }
      return new Response(null, { status: 404 });
    });
    vi.stubGlobal("fetch", fetchImplementation);
    renderConsole();
    fireEvent.change(screen.getByLabelText("Operator API key"), { target: { value: "operator" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));

    expect(await screen.findByRole("heading", { name: "Identity providers" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Provision signing key" })).toBeVisible();
    fireEvent.change(screen.getByLabelText("Provider key"), { target: { value: "workforce" } });
    fireEvent.change(screen.getByLabelText("Display name", { selector: "#provider-name" }), {
      target: { value: "Workforce" },
    });
    fireEvent.change(screen.getByLabelText("Canonical HTTPS issuer"), {
      target: { value: "https://accounts.example/" },
    });
    fireEvent.change(screen.getByLabelText("Client ID"), { target: { value: "client" } });
    const secret = screen.getByLabelText("Client secret (write-only)");
    fireEvent.change(secret, { target: { value: "never-render-me" } });
    fireEvent.click(screen.getByRole("button", { name: "Configure provider" }));

    await waitFor(() => {
      expect(providerBody).toBeDefined();
    });
    expect((secret as HTMLInputElement).value).toBe("");
    expect(document.body.textContent).not.toContain("never-render-me");
    expect(providerBody).toMatchObject({ kind: "oidc", client_secret: "never-render-me" });
  });

  it("resumes durable key and provider operations after page state is lost", async () => {
    const signingKey = {
      id: "33333333-3333-4333-8333-333333333333",
      project_id: project.id,
      kid: "kid_recovery",
      algorithm: "EdDSA",
      state: "provisioning",
      ring_revision: 1,
      signing_epoch: 1,
      sign_not_before: null,
      verify_not_after: null,
      public_jwk: null,
    };
    const provider = {
      id: "22222222-2222-4222-8222-222222222222",
      project_id: project.id,
      provider_key: "workforce",
      kind: "oidc",
      display_name: "Workforce",
      issuer: "https://accounts.example/",
      client_id: "client",
      callback_url: "https://identity.example/callback",
      status: "provisioning",
      revision: 1,
      assigned_application_ids: [],
      managed_profile: {
        supported: true,
        enabled: true,
        exact_scopes: ["openid", "profile", "offline_access"],
        profile_schema: "oidc_userinfo_v1",
        read_retry_safe: true,
        renewal_idempotent_replay: false,
        supports_revocation: true,
      },
    };
    let keyReconcileBody: unknown;
    let providerReconcileBody: unknown;
    const fetchImplementation = vi.fn<typeof fetch>(async (input) => {
      const request = input as Request;
      const url = request.url;
      if (url.endsWith("/v1/system")) {
        return Response.json({
          product: "owlauth-server",
          provisioning: true,
          login_readiness: true,
          federated_project_auth: false,
        });
      }
      if (url.endsWith("/v1/projects") && request.method === "GET") {
        return Response.json({ items: [project] });
      }
      if (url.endsWith("/projection-policy"))
        return Promise.resolve(Response.json(projectionPolicy));
      if (url.includes("/applications")) return Response.json({ items: [] });
      if (url.endsWith("/signing-keys") && request.method === "GET") {
        return Response.json({ items: [signingKey] });
      }
      if (url.endsWith(`/signing-keys/${signingKey.id}/reconcile`)) {
        keyReconcileBody = await request.json();
        return Response.json({ ...signingKey, state: "published" });
      }
      if (url.endsWith("/policy") && request.method === "GET") return Response.json(policy);
      if (url.endsWith("/providers") && request.method === "GET") {
        return Response.json({ items: [provider] });
      }
      if (url.endsWith(`/providers/${provider.id}/reconcile`)) {
        providerReconcileBody = await request.json();
        return Response.json({ ...provider, status: "active", revision: 2 });
      }
      return new Response(null, { status: 404 });
    });
    vi.stubGlobal("fetch", fetchImplementation);
    renderConsole();
    fireEvent.change(screen.getByLabelText("Operator API key"), { target: { value: "operator" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));

    const initialResumeButtons = await screen.findAllByRole("button", {
      name: "Resume provisioning",
    });
    const keyResumeButton = initialResumeButtons.at(0);
    if (!keyResumeButton) throw new Error("missing signing-key resume action");
    fireEvent.click(keyResumeButton);
    await waitFor(() => {
      expect(keyReconcileBody).toEqual({ expected_project_revision: 1 });
    });

    const secret = screen.getByLabelText("Re-enter client secret to resume");
    fireEvent.change(secret, { target: { value: "reentered-secret" } });
    const resumeButtons = screen.getAllByRole("button", { name: "Resume provisioning" });
    const providerResumeButton = resumeButtons.at(-1);
    if (!providerResumeButton) throw new Error("missing provider resume action");
    fireEvent.click(providerResumeButton);
    await waitFor(() => {
      expect(providerReconcileBody).toEqual({
        client_secret: "reentered-secret",
        expected_project_revision: 1,
      });
    });
    expect((secret as HTMLInputElement).value).toBe("");
    expect(document.body.textContent).not.toContain("reentered-secret");
    expect(screen.getByRole("button", { name: "Abandon incomplete key" })).toBeVisible();
  });

  it("clears provider secrets across network and 503 retries while retaining one attempt key", async () => {
    const attemptKeys: string[] = [];
    const attemptSecrets: string[] = [];
    let providerPosts = 0;
    const fetchImplementation = vi.fn<typeof fetch>(async (input) => {
      const request = input as Request;
      const url = request.url;
      if (url.endsWith("/v1/system")) {
        return Response.json({
          product: "owlauth-server",
          provisioning: true,
          login_readiness: true,
          federated_project_auth: false,
        });
      }
      if (url.endsWith("/v1/projects") && request.method === "GET") {
        return Response.json({ items: [project] });
      }
      if (url.endsWith("/projection-policy"))
        return Promise.resolve(Response.json(projectionPolicy));
      if (url.includes("/applications")) return Response.json({ items: [] });
      if (url.includes("/signing-keys")) return Response.json({ items: [] });
      if (url.endsWith("/policy") && request.method === "GET") return Response.json(policy);
      if (url.endsWith("/providers") && request.method === "GET") {
        return Response.json({ items: [] });
      }
      if (url.endsWith("/providers") && request.method === "POST") {
        providerPosts += 1;
        attemptKeys.push(request.headers.get("idempotency-key") ?? "");
        const body = (await request.clone().json()) as { client_secret?: string };
        attemptSecrets.push(body.client_secret ?? "");
        if (providerPosts === 1) throw new TypeError("network unavailable");
        if (providerPosts === 2) {
          return Response.json(
            { code: "temporarily_unavailable", detail: "Try again later." },
            { status: 503 },
          );
        }
        return Response.json({
          id: "22222222-2222-4222-8222-222222222222",
          project_id: project.id,
          provider_key: "workforce",
          kind: "oidc",
          display_name: "Workforce",
          issuer: "https://accounts.example/",
          client_id: "client",
          callback_url: "https://identity.example/callback",
          status: "active",
          revision: 2,
          assigned_application_ids: [],
          managed_profile: {
            supported: true,
            enabled: true,
            exact_scopes: ["openid", "profile", "offline_access"],
            profile_schema: "oidc_userinfo_v1",
            read_retry_safe: true,
            renewal_idempotent_replay: false,
            supports_revocation: true,
          },
        });
      }
      return new Response(null, { status: 404 });
    });
    vi.stubGlobal("fetch", fetchImplementation);
    renderConsole();
    fireEvent.change(screen.getByLabelText("Operator API key"), { target: { value: "operator" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));

    expect(await screen.findByRole("heading", { name: "Identity providers" })).toBeVisible();
    fireEvent.change(screen.getByLabelText("Provider key"), { target: { value: "workforce" } });
    fireEvent.change(screen.getByLabelText("Display name", { selector: "#provider-name" }), {
      target: { value: "Workforce" },
    });
    fireEvent.change(screen.getByLabelText("Canonical HTTPS issuer"), {
      target: { value: "https://accounts.example/" },
    });
    fireEvent.change(screen.getByLabelText("Client ID"), { target: { value: "client" } });
    const secret = screen.getByLabelText("Client secret (write-only)");

    fireEvent.change(secret, { target: { value: "retry-secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Configure provider" }));
    expect(secret).toHaveValue("");
    expect(document.body.textContent).not.toContain("retry-secret");
    expect(await screen.findByRole("status")).toHaveTextContent("The request failed.");

    fireEvent.change(secret, { target: { value: "retry-secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Configure provider" }));
    expect(secret).toHaveValue("");
    expect(document.body.textContent).not.toContain("retry-secret");
    expect(await screen.findByRole("status")).toHaveTextContent("Try again later.");

    fireEvent.change(secret, { target: { value: "retry-secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Configure provider" }));
    expect(secret).toHaveValue("");
    expect(await screen.findByText(/write-only/u)).toBeVisible();
    expect(attemptKeys).toHaveLength(3);
    expect(new Set(attemptKeys).size).toBe(1);
    expect(attemptKeys[0]).not.toBe("");
    expect(attemptSecrets).toEqual(["retry-secret", "retry-secret", "retry-secret"]);
  });

  it("refreshes current revisions after a mutation conflict", async () => {
    let projectReads = 0;
    const fetchImplementation = vi.fn<typeof fetch>((input) => {
      const request = input as Request;
      const url = request.url;
      if (url.endsWith("/v1/system")) {
        return Promise.resolve(
          Response.json({
            product: "owlauth-server",
            provisioning: true,
            login_readiness: true,
            federated_project_auth: false,
          }),
        );
      }
      if (url.endsWith("/v1/projects") && request.method === "GET") {
        projectReads += 1;
        return Promise.resolve(
          Response.json({
            items: [{ ...project, metadata_revision: projectReads === 1 ? 1 : 2 }],
          }),
        );
      }
      if (url.endsWith(`/v1/projects/${project.id}`) && request.method === "PATCH") {
        return Promise.resolve(
          Response.json(
            { code: "revision_conflict", detail: "The expected revision is stale." },
            { status: 409 },
          ),
        );
      }
      if (url.endsWith("/projection-policy"))
        return Promise.resolve(Response.json(projectionPolicy));
      if (url.includes("/applications")) {
        return Promise.resolve(Response.json({ items: [] }));
      }
      if (url.includes("/signing-keys")) {
        return Promise.resolve(Response.json({ items: [] }));
      }
      if (url.endsWith("/policy")) {
        return Promise.resolve(Response.json(policy));
      }
      if (url.endsWith("/providers")) {
        return Promise.resolve(Response.json({ items: [] }));
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchImplementation);
    renderConsole();
    fireEvent.change(screen.getByLabelText("Operator API key"), { target: { value: "operator" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));

    expect(await screen.findByText(/metadata revision 1/)).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Update Project" }));

    expect(
      await screen.findByText(
        "The resource changed. Current revisions were refreshed; review and retry.",
      ),
    ).toBeVisible();
    expect(await screen.findByText(/metadata revision 2/)).toBeVisible();
    expect(projectReads).toBeGreaterThanOrEqual(2);
  });

  it("renders only a bounded authentication failure and disposes the denied client", async () => {
    let deniedRequest: Request | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        deniedRequest = input as Request;
        return Promise.resolve(new Response(null, { status: 401 }));
      }),
    );
    renderConsole();
    const input = screen.getByLabelText("Operator API key");
    fireEvent.change(input, { target: { value: "wrong" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Authentication failed.");
    expect(input).toHaveValue("");
    expect(deniedRequest?.signal.aborted).toBe(true);
    expect(document.body.textContent).not.toContain("wrong");
  });
});
