import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { RuntimeApp } from "../App";
import {
  identityMutationNavigation,
  validateIdentityMutationBootstrap,
} from "./IdentityMutationFlow";

const future = "2099-01-01T00:00:00Z";
const intent = "mutation_handle_1";
const providerSlot = "11111111-1111-4111-8111-111111111111";
const emailSlot = "22222222-2222-4222-8222-222222222222";
const challenge = "33333333-3333-4333-8333-333333333333";

function slot(overrides: Record<string, unknown> = {}) {
  return {
    id: emailSlot,
    role: "identity_owner",
    identity_kind: "email",
    method_kind: "email",
    state: "unselected",
    next_action: "select_method",
    proved: false,
    ...overrides,
  };
}

function bootstrap(overrides: Record<string, unknown> = {}) {
  return {
    project_public_id: "prj_public",
    operation_kind: "unlink",
    status: "pending_proof",
    revision: 1,
    csrf: "identity_csrf_value",
    expires_at: future,
    slots: [slot()],
    ...overrides,
  };
}

function installMutation(value: unknown) {
  window.history.replaceState({}, "", `/runtime/auth/identity-mutations/${intent}`);
  const flow = document.createElement("meta");
  flow.name = "owlauth-runtime-flow";
  flow.content = "identity_mutation";
  const data = document.createElement("meta");
  data.name = "owlauth-runtime-bootstrap";
  data.content = JSON.stringify(value);
  document.head.append(flow, data);
}

function installMagic() {
  window.history.replaceState(
    {},
    "",
    `/runtime/auth/identity-mutations/email/confirm/${challenge}#proof=abcdefghijklmnopqrstuv&project=prj_public&interaction=${intent}&slot=${emailSlot}&generation=2&revision=7`,
  );
  const values: Record<string, string> = {
    "owlauth-runtime-flow": "identity_mutation_magic",
    "owlauth-identity-magic-csrf": "magic_csrf_value",
    "owlauth-identity-magic-project": "prj_public",
    "owlauth-identity-magic-slot": emailSlot,
    "owlauth-identity-magic-generation": "2",
    "owlauth-identity-magic-revision": "7",
  };
  for (const [name, content] of Object.entries(values)) {
    const meta = document.createElement("meta");
    meta.name = name;
    meta.content = content;
    document.head.append(meta);
  }
}

describe("Hosted identity mutation", () => {
  beforeEach(() => {
    document.head.innerHTML = '<meta name="owlauth-runtime-base" content="/runtime/">';
    window.history.replaceState({}, "", "/runtime/auth/");
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("strictly rejects unknown or unsafe bootstrap fields", () => {
    expect(validateIdentityMutationBootstrap(bootstrap())).toBe(true);
    expect(
      validateIdentityMutationBootstrap({ ...bootstrap(), raw_email: "secret@example.test" }),
    ).toBe(false);
    expect(
      validateIdentityMutationBootstrap(
        bootstrap({ slots: [slot({ next_action: "await_provider" })] }),
      ),
    ).toBe(false);
    expect(
      validateIdentityMutationBootstrap(
        bootstrap({
          operation_kind: "link",
          slots: [slot({ role: "candidate_identity" })],
        }),
      ),
    ).toBe(false);
  });

  it("renders both immutable link proof slots and their server-owned state", () => {
    installMutation(
      bootstrap({
        operation_kind: "link",
        revision: 8,
        slots: [
          slot({
            id: providerSlot,
            role: "destination_owner",
            identity_kind: "provider",
            method_kind: "provider",
            state: "proved",
            next_action: null,
            proved: true,
          }),
          slot({
            role: "candidate_identity",
            state: "email_address_entry",
            next_action: "enter_email",
          }),
        ],
      }),
    );
    render(<RuntimeApp />);

    const destination = screen.getByRole("heading", { name: "Destination owner proof" });
    const candidate = screen.getByRole("heading", { name: "New identity proof" });
    expect(destination).toBeVisible();
    expect(candidate).toBeVisible();
    expect(destination.parentElement).toHaveTextContent("Status: Proof complete");
    expect(candidate.parentElement).toHaveTextContent("Status: Waiting for an email address");
    expect(document.body.textContent).not.toContain("next action");
    expect(document.body.textContent).not.toContain("identity_csrf_value");
  });

  it("starts only the fixed provider method and validates navigation", async () => {
    installMutation(
      bootstrap({
        slots: [
          slot({
            id: providerSlot,
            identity_kind: "provider",
            method_kind: "provider",
          }),
        ],
      }),
    );
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const request = input as Request;
      expect(request.url).toContain(`/identity-mutations/${intent}/proofs/${providerSlot}/method`);
      expect(await request.clone().json()).toEqual({
        expected_revision: 1,
        csrf: "identity_csrf_value",
        method_kind: "provider",
      });
      return Response.json({
        method_kind: "provider",
        result: { url: "https://provider.example/authorize?state=opaque" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const replace = vi
      .spyOn(identityMutationNavigation, "replace")
      .mockImplementation(() => undefined);
    render(<RuntimeApp />);

    fireEvent.click(screen.getByRole("button", { name: "Start provider proof" }));
    await waitFor(() => {
      expect(replace).toHaveBeenCalledWith("https://provider.example/authorize?state=opaque");
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("offers an authoritative refresh while an external email proof is pending", () => {
    installMutation(
      bootstrap({
        revision: 4,
        slots: [
          slot({
            state: "email_challenge_pending",
            next_action: "verify_email",
          }),
        ],
      }),
    );
    const reload = vi
      .spyOn(identityMutationNavigation, "reload")
      .mockImplementation(() => undefined);
    render(<RuntimeApp />);

    fireEvent.click(screen.getByRole("button", { name: "Refresh proof status" }));
    expect(reload).toHaveBeenCalledOnce();
  });

  it("refreshes a pending external proof when an initially hidden tab becomes visible", () => {
    installMutation(
      bootstrap({
        revision: 4,
        slots: [
          slot({
            state: "email_challenge_pending",
            next_action: "verify_email",
          }),
        ],
      }),
    );
    const visibility = vi.spyOn(document, "visibilityState", "get").mockReturnValue("hidden");
    const reload = vi
      .spyOn(identityMutationNavigation, "reload")
      .mockImplementation(() => undefined);
    render(<RuntimeApp />);

    visibility.mockReturnValue("visible");
    document.dispatchEvent(new Event("visibilitychange"));
    expect(reload).toHaveBeenCalledOnce();
  });

  it("supports email entry, bounded resend, OTP, and explicit ready confirmation", async () => {
    installMutation(bootstrap());
    let challengeGeneration = 0;
    const bodies: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input) => {
        const request = input as Request;
        bodies.push(await request.clone().json());
        if (request.url.endsWith("/method")) {
          return Response.json({
            method_kind: "email",
            result: { revision: 2, state: "email_address_entry" },
          });
        }
        if (request.url.endsWith("/email/challenges")) {
          challengeGeneration += 1;
          return Response.json(
            {
              accepted: true,
              revision: challengeGeneration + 2,
              challenge_id: challenge,
              generation: challengeGeneration,
              proof_modes: ["otp", "magic_link"],
              expires_at: future,
            },
            { status: 202 },
          );
        }
        if (request.url.endsWith("/email/otp/verify")) {
          return Response.json({ revision: 5, state: "proved" });
        }
        return Response.json({ revision: 6, status: "ready" });
      }),
    );
    render(<RuntimeApp />);

    fireEvent.click(screen.getByRole("button", { name: "Start email proof" }));
    const email = await screen.findByLabelText("Email address for this proof");
    fireEvent.change(email, { target: { value: "person@example.test" } });
    fireEvent.click(screen.getByRole("button", { name: "Send verification email" }));
    expect(await screen.findByLabelText("One-time code")).toBeVisible();
    expect(document.body.textContent).not.toContain("person@example.test");

    fireEvent.change(screen.getByLabelText("Email address for this proof"), {
      target: { value: "person@example.test" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send a newer email" }));
    await waitFor(() => {
      expect(challengeGeneration).toBe(2);
    });
    fireEvent.change(screen.getByLabelText("One-time code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify newest code" }));
    expect(
      await screen.findByRole("button", { name: "Mark proofs ready for operator review" }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Mark proofs ready for operator review" }));
    expect(
      await screen.findByRole("heading", { name: "Proofs ready for operator review" }),
    ).toBeVisible();

    expect(bodies).toEqual([
      { expected_revision: 1, csrf: "identity_csrf_value", method_kind: "email" },
      { expected_revision: 2, csrf: "identity_csrf_value", email: "person@example.test" },
      { expected_revision: 3, csrf: "identity_csrf_value", email: "person@example.test" },
      {
        expected_revision: 4,
        csrf: "identity_csrf_value",
        challenge_id: challenge,
        generation: 2,
        otp: "123456",
      },
      { expected_revision: 5, csrf: "identity_csrf_value" },
    ]);
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });

  it.each([
    ["cancelled", "Identity verification cancelled"],
    ["completed", "Identity change completed"],
    ["expired", "Identity verification expired"],
  ] as const)("renders the %s terminal state without mutation controls", (status, heading) => {
    installMutation(
      bootstrap({
        status,
        slots:
          status === "completed"
            ? [slot({ state: "proved", next_action: null, proved: true })]
            : [slot()],
      }),
    );
    render(<RuntimeApp />);

    expect(screen.getByRole("heading", { name: heading })).toBeVisible();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("identity_csrf_value");
  });

  it("aborts an in-flight magic transfer when the view unmounts", async () => {
    installMagic();
    let signal: AbortSignal | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        signal = (input as Request).signal;
        return new Promise<Response>(() => undefined);
      }),
    );
    const view = render(<RuntimeApp />);
    fireEvent.click(screen.getByRole("button", { name: "Transfer proof to the identity request" }));
    await waitFor(() => {
      expect(signal).toBeDefined();
    });
    view.unmount();
    expect(signal?.aborted).toBe(true);
  });

  it("scrubs magic authority before render and transfers it only by explicit POST", async () => {
    installMagic();
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const request = input as Request;
      expect(await request.clone().json()).toEqual({
        expected_revision: 7,
        csrf: "magic_csrf_value",
        challenge_id: challenge,
        generation: 2,
        token: "abcdefghijklmnopqrstuv",
      });
      return Response.json({ revision: 8, state: "proved" });
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<RuntimeApp />);

    expect(window.location.hash).toBe("");
    expect(document.body.textContent).not.toContain("abcdefghijklmnopqrstuv");
    expect(
      screen.getByRole("button", { name: "Transfer proof to the identity request" }),
    ).toBeVisible();
    expect(fetchMock).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Transfer proof to the identity request" }));
    expect(await screen.findByRole("heading", { name: "Identity proof received" })).toBeVisible();
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });
});
