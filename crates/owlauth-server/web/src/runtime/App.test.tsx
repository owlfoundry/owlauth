import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import { RuntimeApp, hostedNavigation, safeNavigationUrl } from "./App";

const future = "2099-01-01T00:00:00Z";

function installFlow(
  flow: "interaction" | "managed_reauthorization" | "browser-logout",
  bootstrap: unknown,
) {
  const flowMeta = document.createElement("meta");
  flowMeta.name = "owlauth-runtime-flow";
  flowMeta.content = flow;
  const bootstrapMeta = document.createElement("meta");
  bootstrapMeta.name = "owlauth-runtime-bootstrap";
  bootstrapMeta.content = JSON.stringify(bootstrap);
  document.head.append(flowMeta, bootstrapMeta);
}

function interactionBootstrap(overrides: Record<string, unknown> = {}) {
  return {
    project_id: "prj_public",
    project_display_name: "Production",
    application_id: "app_public",
    application_display_name: "Customer portal",
    application_type: "web",
    status: "awaiting_method_selection",
    revision: 4,
    session_reuse_available: true,
    email_available: false,
    email_proof_modes: [],
    presentation_hint: "Use your company account",
    providers: [
      { key: "workforce", display_name: "Workforce SSO", kind: "oidc" },
      { key: "partners", display_name: "Partner login", kind: "google" },
    ],
    csrf: "csrf-sensitive-value",
    expires_at: future,
    ...overrides,
  };
}

function logoutBootstrap(overrides: Record<string, unknown> = {}) {
  return {
    project_id: "prj_public",
    revision: 2,
    csrf: "logout-csrf-sensitive-value",
    expires_at: future,
    ...overrides,
  };
}

describe("Runtime Hosted Authentication", () => {
  beforeEach(() => {
    document.head.innerHTML = '<meta name="owlauth-runtime-base" content="/runtime/">';
    window.history.replaceState({}, "", "/runtime/auth/");
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders a neutral entry page without accepting query parameters as authority", () => {
    window.history.replaceState(
      {},
      "",
      "/runtime/auth/?project_id=attacker&application_id=attacker&csrf=attacker",
    );
    render(<RuntimeApp />);
    expect(screen.getByRole("heading", { name: "Hosted authentication" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "No sign-in is active" })).toBeVisible();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("consumes bootstrap metadata once and renders only admitted interaction choices", () => {
    window.history.replaceState({}, "", "/runtime/auth/interactions/interaction_1");
    installFlow("interaction", interactionBootstrap());

    render(<RuntimeApp />);

    expect(screen.getByRole("heading", { name: "Customer portal" })).toBeVisible();
    expect(screen.getByText("Production")).toBeVisible();
    expect(screen.getByRole("group", { name: "Sign-in methods" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Continue with Workforce SSO" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Continue with Partner login" })).toBeVisible();
    expect(screen.getByText("Use your company account")).toBeVisible();
    expect(screen.getByRole("button", { name: "Continue with current session" })).toBeVisible();
    expect(document.head.querySelector('meta[name="owlauth-runtime-flow"]')).toBeNull();
    expect(document.head.querySelector('meta[name="owlauth-runtime-bootstrap"]')).toBeNull();
    expect(document.body.textContent).not.toContain("csrf-sensitive-value");
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });

  it("uses the canonical email-first order and preserves the server provider order", () => {
    window.history.replaceState({}, "", "/runtime/auth/interactions/ordered_interaction");
    installFlow(
      "interaction",
      interactionBootstrap({
        email_available: true,
        email_proof_modes: ["otp"],
        providers: [
          { key: "partners", display_name: "Partner login", kind: "google" },
          { key: "workforce", display_name: "Workforce SSO", kind: "oidc" },
        ],
      }),
    );

    render(<RuntimeApp />);

    const methodNames = within(screen.getByRole("group", { name: "Sign-in methods" }))
      .getAllByRole("button")
      .map((button) => button.textContent);
    expect(methodNames).toEqual([
      "Continue with email",
      "Continue with Partner login",
      "Continue with Workforce SSO",
    ]);
  });

  it("does not offer session reuse when the authoritative presentation says it is unavailable", () => {
    window.history.replaceState({}, "", "/runtime/auth/interactions/interaction_2");
    installFlow(
      "interaction",
      interactionBootstrap({ session_reuse_available: false, presentation_hint: null }),
    );
    render(<RuntimeApp />);
    expect(screen.queryByRole("button", { name: /current session/u })).not.toBeInTheDocument();
    expect(screen.queryByText("Use your company account")).not.toBeInTheDocument();
  });

  it("runs the accessible email entry and generic check-mail state without retaining the address", async () => {
    window.history.replaceState({}, "", "/runtime/auth/interactions/email_interaction");
    installFlow(
      "interaction",
      interactionBootstrap({
        email_available: true,
        email_proof_modes: ["otp"],
        providers: [],
      }),
    );
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const request = input as Request;
      if (request.url.endsWith("/email/select")) {
        return Response.json({ completed: true });
      }
      expect(request.url).toContain("/email/challenges");
      expect(await request.clone().json()).toEqual({
        csrf: "csrf-sensitive-value",
        expected_revision: 5,
        email: "person@example.test",
      });
      return Response.json(
        {
          accepted: true,
          revision: 6,
          challenge_id: "01912345-6789-7abc-8def-0123456789ab",
          generation: 1,
          proof_modes: ["otp"],
          expires_at: future,
        },
        { status: 202 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<RuntimeApp />);
    fireEvent.click(screen.getByRole("button", { name: "Continue with email" }));
    expect(await screen.findByRole("heading", { name: "Enter your email address" })).toBeVisible();
    fireEvent.change(screen.getByLabelText("Email address"), {
      target: { value: "person@example.test" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send sign-in email" }));
    expect(await screen.findByRole("heading", { name: "Check your email" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Verify code" })).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent("Use the newest code");
    expect(screen.getByRole("status")).not.toHaveTextContent("sign-in link");
    expect(document.body.textContent).not.toContain("person@example.test");
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });

  it("renders only magic-link instructions for a magic-only email policy", async () => {
    window.history.replaceState({}, "", "/runtime/auth/interactions/magic_only");
    installFlow(
      "interaction",
      interactionBootstrap({
        email_available: true,
        email_proof_modes: ["magic_link"],
        providers: [],
      }),
    );
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input) => {
        await Promise.resolve();
        const request = input as Request;
        if (request.url.endsWith("/email/select")) return Response.json({ completed: true });
        return Response.json(
          {
            accepted: true,
            revision: 6,
            challenge_id: "01912345-6789-7abc-8def-0123456789ab",
            generation: 1,
            proof_modes: ["magic_link"],
            expires_at: future,
          },
          { status: 202 },
        );
      }),
    );
    render(<RuntimeApp />);
    fireEvent.click(screen.getByRole("button", { name: "Continue with email" }));
    fireEvent.change(await screen.findByLabelText("Email address"), {
      target: { value: "person@example.test" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send sign-in email" }));
    expect(await screen.findByRole("heading", { name: "Check your email" })).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent("Open the newest sign-in link");
    expect(screen.queryByLabelText("One-time code")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Verify code" })).not.toBeInTheDocument();
  });

  it("scrubs a fragment-only magic proof before rendering explicit confirmation", () => {
    window.history.replaceState(
      {},
      "",
      "/runtime/auth/email/confirm/01912345-6789-7abc-8def-0123456789ab#proof=abcdefghijklmnopqrstuv&project=prj_public&transaction=01912345-6789-7abc-8def-0123456789ab&generation=1&revision=3",
    );
    const flowMeta = document.createElement("meta");
    flowMeta.name = "owlauth-runtime-flow";
    flowMeta.content = "email-magic";
    const csrfMeta = document.createElement("meta");
    csrfMeta.name = "owlauth-magic-csrf";
    csrfMeta.content = "transfer_csrf_value";
    document.head.append(flowMeta, csrfMeta);
    render(<RuntimeApp />);
    expect(window.location.hash).toBe("");
    expect(screen.getByRole("heading", { name: "Continue email sign-in" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Continue sign-in" })).toBeVisible();
    expect(document.body.textContent).not.toContain("abcdefghijklmnopqrstuv");
    expect(document.head.querySelector('meta[name="owlauth-magic-csrf"]')).toBeNull();
  });

  it("uses the trusted native type from a real magic response for custom-scheme navigation", async () => {
    window.history.replaceState(
      {},
      "",
      "/runtime/auth/email/confirm/01912345-6789-7abc-8def-0123456789ab#proof=abcdefghijklmnopqrstuv&project=prj_public&transaction=01912345-6789-7abc-8def-0123456789ab&generation=1&revision=3",
    );
    const flowMeta = document.createElement("meta");
    flowMeta.name = "owlauth-runtime-flow";
    flowMeta.content = "email-magic";
    const csrfMeta = document.createElement("meta");
    csrfMeta.name = "owlauth-magic-csrf";
    csrfMeta.content = "transfer_csrf_value";
    document.head.append(flowMeta, csrfMeta);
    const target = "com.example.app:/callback?handoff=one-use";
    const fetchMock = vi.fn<typeof fetch>((input) => {
      const request = input as Request;
      expect(request.method).toBe("POST");
      expect(request.url).toContain("/auth/email/magic/confirm");
      return Promise.resolve(
        Response.json({
          completed: true,
          redirect_url: target,
          application_type: "native",
        }),
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const replace = vi.spyOn(hostedNavigation, "replace").mockImplementation(() => undefined);

    render(<RuntimeApp />);
    fireEvent.click(screen.getByRole("button", { name: "Continue sign-in" }));

    await waitFor(() => {
      expect(replace).toHaveBeenCalledWith(target);
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("submits provider selection with the bound revision and disposes the CSRF value", async () => {
    window.history.replaceState({}, "", "/runtime/auth/interactions/interaction_3");
    installFlow("interaction", interactionBootstrap());
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const request = input as Request;
      expect(request.method).toBe("POST");
      expect(request.url).toContain(
        "/runtime/v1/projects/prj_public/auth/interactions/interaction_3/method",
      );
      expect(await request.clone().json()).toEqual({
        csrf: "csrf-sensitive-value",
        expected_revision: 4,
        provider_key: "workforce",
      });
      return Response.json({ url: "javascript:alert(1)" });
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<RuntimeApp />);

    fireEvent.click(screen.getByRole("button", { name: "Continue with Workforce SSO" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Continuing with Workforce SSO");
    expect(document.body.textContent).not.toContain("csrf-sensitive-value");
    expect(await screen.findByRole("alert")).toHaveTextContent(/start sign-in again/u);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("submits explicit session reuse and rejects unsafe returned navigation", async () => {
    window.history.replaceState({}, "", "/runtime/auth/interactions/interaction_4");
    installFlow("interaction", interactionBootstrap());
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input) => {
        const request = input as Request;
        expect(request.url).toContain(
          "/runtime/v1/projects/prj_public/auth/interactions/interaction_4/session/reuse",
        );
        expect(await request.clone().json()).toEqual({
          csrf: "csrf-sensitive-value",
          expected_revision: 4,
        });
        return Response.json({ url: "https://user:secret@app.example/callback" });
      }),
    );
    render(<RuntimeApp />);
    fireEvent.click(screen.getByRole("button", { name: "Continue with current session" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/start sign-in again/u);
  });

  it("starts only the fixed managed reauthorization provider with bound CSRF and revision", async () => {
    window.history.replaceState(
      {},
      "",
      "/runtime/auth/managed-reauthorizations/managed_interaction_1",
    );
    installFlow("managed_reauthorization", {
      project_public_id: "prj_public",
      provider_key: "workforce-main",
      provider_display_name: "Workforce SSO <img>",
      provider_kind: "oidc",
      status: "awaiting_provider_start",
      revision: 2,
      csrf: "managed-csrf-sensitive-value",
      expires_at: future,
    });
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const request = input as Request;
      expect(request.url).toContain(
        "/runtime/v1/projects/prj_public/auth/managed-reauthorizations/managed_interaction_1/start",
      );
      expect(await request.clone().json()).toEqual({
        csrf: "managed-csrf-sensitive-value",
        expected_revision: 2,
      });
      return Response.json({ url: "javascript:alert(1)" });
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<RuntimeApp />);

    expect(screen.getByText(/Continue only with Workforce SSO <img>/u)).toBeVisible();
    expect(screen.getByText(/does not sign you in/u)).toBeVisible();
    expect(screen.queryByText(/workforce-main/u)).not.toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Continue with Workforce SSO <img>" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/new managed reauthorization/u);
    expect(document.body.textContent).not.toContain("managed-csrf-sensitive-value");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("renders a completed managed callback only on its matching provider route", () => {
    window.history.replaceState(
      {},
      "",
      "/runtime/projects/prj_public/auth/callback/workforce-main?code=bounded&state=bounded",
    );
    installFlow("managed_reauthorization", {
      project_public_id: "prj_public",
      provider_key: "workforce-main",
      provider_display_name: "Workforce SSO",
      provider_kind: "oidc",
      status: "completed",
      revision: 3,
      expires_at: future,
    });

    render(<RuntimeApp />);

    expect(screen.getByRole("heading", { name: "Connection reauthorized" })).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent(
      "You can close this page and return to the Console.",
    );
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it.each([
    [
      "a different provider",
      "/runtime/projects/prj_public/auth/callback/other-provider?code=bounded&state=bounded",
      "completed",
    ],
    [
      "a different Project",
      "/runtime/projects/prj_other/auth/callback/workforce-main?code=bounded&state=bounded",
      "completed",
    ],
    [
      "a non-terminal status",
      "/runtime/projects/prj_public/auth/callback/workforce-main?code=bounded&state=bounded",
      "provider_exchange_in_progress",
    ],
  ])("rejects a managed callback with %s", (_case, path, status) => {
    window.history.replaceState({}, "", path);
    installFlow("managed_reauthorization", {
      project_public_id: "prj_public",
      provider_key: "workforce-main",
      provider_display_name: "Workforce SSO",
      provider_kind: "oidc",
      status,
      revision: 3,
      expires_at: future,
    });

    render(<RuntimeApp />);

    expect(screen.getByRole("heading", { name: "No sign-in is active" })).toBeVisible();
    expect(screen.queryByRole("heading", { name: "Connection reauthorized" })).toBeNull();
  });

  it("directs a just-expired managed reauthorization back to the management flow", () => {
    window.history.replaceState(
      {},
      "",
      "/runtime/auth/managed-reauthorizations/managed_interaction_expired",
    );
    installFlow("managed_reauthorization", {
      project_public_id: "prj_public",
      provider_key: "workforce-main",
      provider_display_name: "Workforce SSO",
      provider_kind: "oidc",
      status: "awaiting_provider_start",
      revision: 2,
      csrf: "expired-managed-csrf",
      expires_at: new Date(Date.now() - 1).toISOString(),
    });

    render(<RuntimeApp />);

    expect(screen.getByRole("heading", { name: "Reauthorization expired" })).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Return to the management flow and create a new reauthorization.",
    );
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("expired-managed-csrf");
  });

  it("renders progress and terminal interaction states without mutation controls", () => {
    window.history.replaceState({}, "", "/runtime/auth/interactions/interaction_5");
    installFlow("interaction", interactionBootstrap({ status: "provider_exchange_in_progress" }));
    render(<RuntimeApp />);
    expect(screen.getByRole("heading", { name: "Completing sign-in" })).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent(/in progress/u);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("csrf-sensitive-value");
  });

  it("renders a safe local error and removes malformed bootstrap metadata", () => {
    window.history.replaceState({}, "", "/runtime/auth/interactions/copied_interaction");
    installFlow("interaction", interactionBootstrap({ providers: [], csrf: "leak-me" }));
    render(<RuntimeApp />);
    expect(screen.getByRole("alert")).toHaveTextContent(/start again/u);
    expect(document.body.textContent).not.toContain("leak-me");
    expect(document.head.querySelector('meta[name="owlauth-runtime-bootstrap"]')).toBeNull();
  });

  it("requires an explicit browser logout confirmation and supports cancellation", () => {
    window.history.replaceState({}, "", "/runtime/auth/browser-logout/logout_1");
    installFlow("browser-logout", logoutBootstrap());
    render(<RuntimeApp />);
    expect(screen.getByRole("heading", { name: "Sign out" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "Sign out of this Project?" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Confirm sign out" })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("heading", { name: "Sign-out cancelled" })).toBeVisible();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("logout-csrf-sensitive-value");
  });

  it("confirms browser logout through the same-origin generated client", async () => {
    window.history.replaceState({}, "", "/runtime/auth/browser-logout/logout_2");
    installFlow("browser-logout", logoutBootstrap());
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const request = input as Request;
      expect(request.url).toContain(
        "/runtime/v1/projects/prj_public/auth/browser-logout/logout_2/confirm",
      );
      expect(await request.clone().json()).toEqual({
        csrf: "logout-csrf-sensitive-value",
        expected_revision: 2,
      });
      return Response.json({ completed: true });
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<RuntimeApp />);
    fireEvent.click(screen.getByRole("button", { name: "Confirm sign out" }));
    expect(await screen.findByRole("heading", { name: "Signed out" })).toBeVisible();
    expect(screen.getByText(/browser session has ended/u)).toBeVisible();
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("aborts an in-flight mutation when the page unmounts", async () => {
    window.history.replaceState({}, "", "/runtime/auth/interactions/interaction_6");
    installFlow("interaction", interactionBootstrap());
    let observedSignal: AbortSignal | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        observedSignal = (input as Request).signal;
        return new Promise<Response>(() => undefined);
      }),
    );
    const view = render(<RuntimeApp />);
    fireEvent.click(screen.getByRole("button", { name: "Continue with Partner login" }));
    await waitFor(() => {
      expect(observedSignal).toBeDefined();
    });
    view.unmount();
    expect(observedSignal?.aborted).toBe(true);
  });
});

describe("Runtime navigation validation", () => {
  it("accepts only bounded credential-free fragment-free navigation classes", () => {
    expect(safeNavigationUrl("https://idp.example/authorize?request=1", true)).toBe(
      "https://idp.example/authorize?request=1",
    );
    expect(safeNavigationUrl("http://localhost:9000/authorize", true)).toBe(
      "http://localhost:9000/authorize",
    );
    expect(safeNavigationUrl("http://localhost:9000/callback", false)).toBe(
      "http://localhost:9000/callback",
    );
    expect(safeNavigationUrl("http://application.test/callback", false)).toBeNull();
    expect(safeNavigationUrl("com.example.app:/callback?handoff=one", false, "native")).toBe(
      "com.example.app:/callback?handoff=one",
    );
    expect(safeNavigationUrl("com.example.app:/callback", false, "web")).toBeNull();
    expect(safeNavigationUrl("javascript:alert(1)", false, "native")).toBeNull();
    expect(safeNavigationUrl("data:text/html,unsafe", false, "native")).toBeNull();
    expect(safeNavigationUrl("http://idp.example/authorize", true)).toBeNull();
    expect(safeNavigationUrl("javascript:alert(1)", true)).toBeNull();
    expect(safeNavigationUrl("https://user:secret@example.test/", false)).toBeNull();
    expect(safeNavigationUrl("https://example.test/#handoff", false)).toBeNull();
    expect(safeNavigationUrl(`https://example.test/${"a".repeat(4096)}`, false)).toBeNull();
  });
});
