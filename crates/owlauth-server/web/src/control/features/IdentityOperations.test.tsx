import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import {
  type Application,
  ControlRequestError,
  type DisposableControlClient,
  type Project,
  type ProjectUser,
  type ProjectUserIdentity,
  type Provider,
} from "../client";
import { ControlConfirmationProvider } from "../app/Confirmation";
import { IdentityOperations, validateSafeIdentityInventory } from "./IdentityOperations";

const project: Project = {
  id: "11111111-1111-4111-8111-111111111111",
  public_id: "prj_public",
  display_name: "Production",
  belongs_to: null,
  status: "active",
  metadata_revision: 1,
  security_revision: 1,
};
const winner: ProjectUser = {
  id: "22222222-2222-4222-8222-222222222222",
  project_id: project.id,
  public_id: "usr_winner",
  display_name: "Winner",
  picture_url: null,
  status: "active",
  user_revision: 7,
  security_revision: 8,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};
const loser: ProjectUser = {
  ...winner,
  id: "33333333-3333-4333-8333-333333333333",
  public_id: "usr_loser",
  display_name: "Loser",
  user_revision: 9,
  security_revision: 10,
};
const providerIdentity: ProjectUserIdentity = {
  id: "44444444-4444-4444-8444-444444444444",
  project_id: project.id,
  user_id: winner.id,
  identity_kind: "provider",
  provider_key: "historical-provider",
  status: "active",
  identity_revision: 11,
  is_primary_source: true,
  verified_or_observed_at: "2026-01-01T00:00:00Z",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};
const emailIdentity: ProjectUserIdentity = {
  id: "55555555-5555-4555-8555-555555555555",
  project_id: project.id,
  user_id: winner.id,
  identity_kind: "email",
  address: "redacted",
  status: "active",
  identity_revision: 12,
  is_primary_source: false,
  verified_or_observed_at: "2026-01-01T00:00:00Z",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};
const loserEmail: ProjectUserIdentity = {
  ...emailIdentity,
  id: "66666666-6666-4666-8666-666666666666",
  user_id: loser.id,
  identity_revision: 13,
};
const application: Application = {
  id: "77777777-7777-4777-8777-777777777777",
  project_id: project.id,
  public_id: "app_public",
  display_name: "Proof application",
  application_type: "web",
  status: "active",
  metadata_revision: 3,
  security_revision: 4,
  configuration: { redirect_uris: [], allowed_origins: [], publishable_keys: [] },
};
const provider: Provider = {
  id: "88888888-8888-4888-8888-888888888888",
  project_id: project.id,
  provider_key: "current-authority",
  display_name: "Current authority",
  kind: "oidc",
  issuer: "https://issuer.example",
  client_id: "public-client-label",
  callback_url: "https://runtime.example/callback",
  status: "active",
  revision: 5,
  secret_replacement_pending: false,
  login_supported: true,
  identity_proof_supported: true,
  assigned_application_ids: [application.id],
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
const githubProvider: Provider = {
  ...provider,
  id: "89898989-8989-4989-8989-898989898989",
  provider_key: "github",
  display_name: "GitHub login only",
  kind: "github",
  issuer: "https://github.com",
  identity_proof_supported: false,
};

function successful<T>(data: T) {
  return { data, error: undefined, response: Response.json(data) };
}

function intent(operation: "link" | "unlink" | "merge", status = "pending_proof") {
  return {
    id: "99999999-9999-4999-8999-999999999999",
    project_id: project.id,
    operation_kind: operation,
    status,
    revision: status === "ready" ? 4 : 1,
    effective_expires_at: "2099-01-01T00:00:00Z",
    slots: [
      {
        id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        role:
          operation === "unlink"
            ? "identity_owner"
            : operation === "merge"
              ? "winner_owner"
              : "destination_owner",
        identity_kind: "provider",
        method_kind: "provider",
        proved: status === "ready",
      },
    ],
    hosted_target: "https://runtime.example/auth/identity-mutations/opaque",
  };
}

function renderPanel(options?: {
  post?: (path: string, options: unknown) => Promise<unknown>;
  get?: (path: string, options: unknown) => Promise<unknown>;
  identities?: ProjectUserIdentity[];
  providers?: Provider[];
  onError?: (error: unknown) => Promise<void>;
  reload?: () => Promise<void>;
}) {
  const post = vi.fn(
    options?.post ??
      ((...args: [string, unknown]) => {
        void args;
        return Promise.resolve(successful(intent("link")));
      }),
  );
  const get = vi.fn(
    options?.get ??
      ((path: string) =>
        path.endsWith("/identities")
          ? Promise.resolve(successful({ items: [loserEmail] }))
          : Promise.resolve(successful(intent("link", "ready")))),
  );
  const onError = vi.fn(options?.onError ?? (() => Promise.resolve()));
  const reload = vi.fn(options?.reload ?? (() => Promise.resolve()));
  const setMessage = vi.fn();
  const session = {
    client: { POST: post, GET: get },
    dispose: vi.fn(),
  } as unknown as DisposableControlClient;
  render(
    <ControlConfirmationProvider>
      <IdentityOperations
        session={session}
        project={project}
        selectedUser={winner}
        users={[winner, loser]}
        identities={options?.identities ?? [providerIdentity, emailIdentity]}
        applications={[application]}
        providers={options?.providers ?? [provider]}
        hasMoreUsers={false}
        loadingMoreUsers={false}
        loadMoreUsers={() => Promise.resolve()}
        reloadSelectedUser={reload}
        onError={onError}
        setMessage={setMessage}
      />
    </ControlConfirmationProvider>,
  );
  return { post, get, onError, reload, setMessage };
}

function selectElement(selector: string): HTMLSelectElement {
  const element = document.querySelector(selector);
  if (!(element instanceof HTMLSelectElement)) throw new Error(`Missing select ${selector}`);
  return element;
}

function chooseOperation(operation: "link" | "unlink" | "merge") {
  fireEvent.change(screen.getByLabelText("Operation"), { target: { value: operation } });
}

function chooseProviderAuthority(prefix: string) {
  fireEvent.change(selectElement(`#${prefix}-application`), {
    target: { value: application.id },
  });
  fireEvent.change(selectElement(`#${prefix}-provider`), {
    target: { value: provider.id },
  });
}

function popup() {
  const replace = vi.fn();
  const close = vi.fn();
  const value = { opener: window, location: { replace }, close } as unknown as Window;
  return { value, replace, close };
}

describe("Control identity mutation orchestration", () => {
  afterEach(() => vi.restoreAllMocks());

  it("omits login-only providers from identity-proof authority choices", () => {
    renderPanel({ providers: [provider, githubProvider] });
    chooseOperation("link");
    fireEvent.change(screen.getByLabelText("Exact existing identity"), {
      target: { value: providerIdentity.id },
    });
    fireEvent.change(selectElement("#destination-application"), {
      target: { value: application.id },
    });
    const options = Array.from(selectElement("#destination-provider").options).map(
      (option) => option.textContent,
    );
    expect(options).toContain("Current authority (current-authority)");
    expect(options).not.toContain("GitHub login only (github)");
  });

  it("accepts only bounded redacted inventory", () => {
    expect(validateSafeIdentityInventory([providerIdentity, emailIdentity])).toBe(true);
    expect(
      validateSafeIdentityInventory([{ ...emailIdentity, address: "person@example.test" }]),
    ).toBe(false);
    expect(
      validateSafeIdentityInventory([{ ...providerIdentity, provider_key: "x".repeat(65) }]),
    ).toBe(false);
    expect(validateSafeIdentityInventory(Array.from({ length: 101 }, () => providerIdentity))).toBe(
      false,
    );
  });

  it("requires explicit operation and candidate choices and clears reinterpretable authorities", () => {
    renderPanel();
    expect(screen.getByLabelText("Operation")).toHaveValue("");
    expect(screen.queryByLabelText("Exact existing identity")).not.toBeInTheDocument();

    chooseOperation("link");
    fireEvent.change(screen.getByLabelText("Exact existing identity"), {
      target: { value: providerIdentity.id },
    });
    chooseProviderAuthority("destination");
    fireEvent.change(screen.getByLabelText("New candidate identity kind"), {
      target: { value: "provider" },
    });
    chooseProviderAuthority("candidate");

    fireEvent.change(screen.getByLabelText("New candidate identity kind"), {
      target: { value: "email" },
    });
    expect(selectElement("#candidate-application")).toHaveValue("");
    expect(document.querySelector("#candidate-provider")).toBeNull();

    fireEvent.change(screen.getByLabelText("New candidate identity kind"), {
      target: { value: "provider" },
    });
    expect(selectElement("#candidate-application")).toHaveValue("");
    expect(selectElement("#candidate-provider")).toHaveValue("");

    fireEvent.change(screen.getByLabelText("Exact existing identity"), {
      target: { value: emailIdentity.id },
    });
    expect(selectElement("#destination-application")).toHaveValue("");
    expect(document.querySelector("#destination-provider")).toBeNull();
  });

  it("creates an exact Link plan, pre-opens the popup, and confirms the exact ready variant", async () => {
    const created = intent("link", "ready");
    const completed = { ...created, status: "completed", revision: 5 };
    const post = vi.fn((path: string, options: unknown) => {
      void options;
      return Promise.resolve(successful(path.endsWith("/confirm") ? completed : created));
    });
    const reserved = popup();
    const open = vi.spyOn(window, "open").mockReturnValue(reserved.value);
    renderPanel({ post });

    chooseOperation("link");
    fireEvent.change(screen.getByLabelText("Exact existing identity"), {
      target: { value: providerIdentity.id },
    });
    chooseProviderAuthority("destination");
    fireEvent.change(screen.getByLabelText("New candidate identity kind"), {
      target: { value: "email" },
    });
    fireEvent.change(selectElement("#candidate-application"), {
      target: { value: application.id },
    });
    fireEvent.click(screen.getByRole("button", { name: /Create proof intent/u }));

    expect(open).toHaveBeenCalledWith("about:blank", "_blank");
    await waitFor(() => {
      expect(reserved.replace).toHaveBeenCalledWith(created.hosted_target);
    });
    const createOptions = post.mock.calls[0]?.[1] as {
      params: { header: Record<string, string> };
      body: unknown;
    };
    expect(createOptions.params.header["Idempotency-Key"]).toMatch(/^console_/u);
    expect(createOptions.body).toEqual({
      operation_kind: "link",
      destination: {
        user_id: winner.id,
        expected_user_revision: 7,
        expected_user_security_revision: 8,
      },
      destination_identity: {
        identity_kind: "provider",
        identity_id: providerIdentity.id,
        expected_identity_revision: 11,
      },
      candidate_identity_kind: "email",
      destination_proof_authority: {
        method_kind: "provider",
        application_id: application.id,
        provider_id: provider.id,
      },
      candidate_proof_authority: { method_kind: "email", application_id: application.id },
    });
    expect(document.body.textContent).not.toContain("issuer.example");
    const exactReview = (
      await screen.findByRole("heading", {
        name: "Exact immutable create-time plan",
      })
    ).parentElement;
    expect(exactReview).toHaveTextContent(winner.id);
    expect(exactReview).toHaveTextContent("Expected user revision: 7");
    expect(exactReview).toHaveTextContent("Expected user security revision: 8");
    expect(exactReview).toHaveTextContent(providerIdentity.id);
    expect(exactReview).toHaveTextContent("Expected identity revision: 11");
    expect(exactReview).toHaveTextContent(application.id);
    expect(exactReview).toHaveTextContent(provider.id);
    expect(exactReview).toHaveTextContent("Candidate identity kind: email");
    expect(exactReview?.querySelector("input, select, button")).toBeNull();

    fireEvent.change(screen.getByLabelText("Exact existing identity"), {
      target: { value: emailIdentity.id },
    });
    expect(exactReview).toHaveTextContent(providerIdentity.id);

    fireEvent.change(screen.getByLabelText("Typed confirmation phrase"), {
      target: { value: "LINK IDENTITY" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Confirm exact link at revision 4/u }));
    await waitFor(() => {
      expect(post).toHaveBeenLastCalledWith(
        "/v1/projects/{project_id}/identity-mutation-intents/{intent_id}/confirm",
        expect.objectContaining({
          body: { operation_kind: "link", expected_revision: 4, confirmation: "link_identity" },
        }),
      );
    });
  });

  it("builds the exact Unlink variant with a typed replacement primary source", async () => {
    const post = vi.fn((...args: [string, unknown]) => {
      void args;
      return Promise.resolve(successful(intent("unlink")));
    });
    vi.spyOn(window, "open").mockReturnValue(popup().value);
    renderPanel({ post });
    chooseOperation("unlink");
    fireEvent.change(screen.getByLabelText("Exact existing identity"), {
      target: { value: emailIdentity.id },
    });
    fireEvent.change(selectElement("#owner-application"), {
      target: { value: application.id },
    });
    fireEvent.change(screen.getByLabelText("Primary-source disposition"), {
      target: { value: "provider" },
    });
    fireEvent.change(screen.getByLabelText("Exact replacement primary identity"), {
      target: { value: providerIdentity.id },
    });
    fireEvent.click(screen.getByRole("button", { name: /Create proof intent/u }));
    await waitFor(() => {
      expect(post).toHaveBeenCalledOnce();
    });
    expect((post.mock.calls[0]?.[1] as { body: unknown }).body).toEqual({
      operation_kind: "unlink",
      owner: {
        user_id: winner.id,
        expected_user_revision: 7,
        expected_user_security_revision: 8,
      },
      identity: {
        identity_kind: "email",
        identity_id: emailIdentity.id,
        expected_identity_revision: 12,
      },
      proof_authority: { method_kind: "email", application_id: application.id },
      primary_source_disposition: {
        disposition: "provider",
        identity_id: providerIdentity.id,
        expected_identity_revision: 11,
      },
    });
    const unlinkReview = (
      await screen.findByRole("heading", {
        name: "Exact immutable create-time plan",
      })
    ).parentElement;
    expect(unlinkReview).toHaveTextContent("Primary-source disposition: provider");
    expect(unlinkReview).toHaveTextContent(providerIdentity.id);
    expect(unlinkReview).toHaveTextContent("Expected identity revision: 11");
  });

  it("builds an exact Merge with explicit users, authorities, and fixed dispositions", async () => {
    const post = vi.fn((...args: [string, unknown]) => {
      void args;
      return Promise.resolve(successful(intent("merge")));
    });
    vi.spyOn(window, "open").mockReturnValue(popup().value);
    renderPanel({ post });
    chooseOperation("merge");
    fireEvent.change(screen.getByLabelText("Exact winning-user proof identity"), {
      target: { value: providerIdentity.id },
    });
    chooseProviderAuthority("winner");
    fireEvent.change(screen.getByLabelText("Exact losing user"), { target: { value: loser.id } });
    fireEvent.click(screen.getByRole("button", { name: /Load losing user/u }));
    expect(await screen.findByRole("status")).toHaveTextContent(/bounded, redacted/u);
    fireEvent.change(screen.getByLabelText("Exact losing-user proof identity"), {
      target: { value: loserEmail.id },
    });
    fireEvent.change(selectElement("#loser-application"), {
      target: { value: application.id },
    });
    fireEvent.change(screen.getByLabelText("Exact primary source after merge"), {
      target: { value: providerIdentity.id },
    });
    fireEvent.click(screen.getByRole("button", { name: /Create proof intent/u }));
    await waitFor(() => {
      expect(post).toHaveBeenCalledOnce();
    });
    expect((post.mock.calls[0]?.[1] as { body: unknown }).body).toEqual({
      operation_kind: "merge",
      winner: {
        user_id: winner.id,
        expected_user_revision: 7,
        expected_user_security_revision: 8,
      },
      winner_identity: {
        identity_kind: "provider",
        identity_id: providerIdentity.id,
        expected_identity_revision: 11,
      },
      winner_proof_authority: {
        method_kind: "provider",
        application_id: application.id,
        provider_id: provider.id,
      },
      loser: {
        user_id: loser.id,
        expected_user_revision: 9,
        expected_user_security_revision: 10,
      },
      loser_identity: {
        identity_kind: "email",
        identity_id: loserEmail.id,
        expected_identity_revision: 13,
      },
      loser_proof_authority: { method_kind: "email", application_id: application.id },
      primary_source: {
        identity_kind: "provider",
        identity_id: providerIdentity.id,
        expected_identity_revision: 11,
      },
      sessions_disposition: "loser_revoked",
      bindings_disposition: "winner_preferred",
    });
    const mergeReview = (
      await screen.findByRole("heading", {
        name: "Exact immutable create-time plan",
      })
    ).parentElement;
    expect(mergeReview).toHaveTextContent(winner.id);
    expect(mergeReview).toHaveTextContent("Expected user revision: 7");
    expect(mergeReview).toHaveTextContent(loser.id);
    expect(mergeReview).toHaveTextContent("Expected user security revision: 10");
    expect(mergeReview).toHaveTextContent(loserEmail.id);
    expect(mergeReview).toHaveTextContent("Expected identity revision: 13");
    expect(mergeReview).toHaveTextContent("Losing sessions disposition: loser_revoked");
    expect(mergeReview).toHaveTextContent("Application bindings disposition: winner_preferred");
  });

  it("keeps an orphan read/cancel-only and never reconstructs final confirmation", async () => {
    const ready = intent("merge", "ready");
    const get = vi.fn(() => Promise.resolve(successful(ready)));
    const post = vi.fn(() =>
      Promise.resolve(successful({ ...ready, status: "cancelled", revision: 5 })),
    );
    renderPanel({ get, post });
    fireEvent.change(screen.getByLabelText("Read an existing intent by ID"), {
      target: { value: ready.id },
    });
    fireEvent.click(screen.getByRole("button", { name: "Read intent" }));
    expect(await screen.findByText(/Original immutable plan unavailable/u)).toBeVisible();
    expect(screen.queryByLabelText("Typed confirmation phrase")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel intent" }));
    fireEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel intent" }),
    );
    await waitFor(() => {
      expect(post).toHaveBeenCalledWith(
        "/v1/projects/{project_id}/identity-mutation-intents/{intent_id}/cancel",
        expect.objectContaining({ body: { expected_revision: 4 } }),
      );
    });
    expect(
      screen.getByRole("heading", { name: "Identity mutation intent" }).parentElement,
    ).toHaveTextContent("cancelled");
    expect(screen.queryByRole("button", { name: "Cancel intent" })).not.toBeInTheDocument();
  });

  it("refreshes a stale final-confirmation revision without losing the exact plan snapshot", async () => {
    const ready = intent("link", "ready");
    const refreshed = { ...ready, revision: 6 };
    const conflict = new ControlRequestError(undefined, 409);
    const post = vi.fn((path: string, options: unknown) => {
      void options;
      return path.endsWith("/confirm")
        ? Promise.reject(conflict)
        : Promise.resolve(successful(ready));
    });
    const get = vi.fn(() => Promise.resolve(successful(refreshed)));
    const onError = vi.fn(() => Promise.resolve());
    vi.spyOn(window, "open").mockReturnValue(popup().value);
    renderPanel({ post, get, onError });

    chooseOperation("link");
    fireEvent.change(screen.getByLabelText("Exact existing identity"), {
      target: { value: providerIdentity.id },
    });
    chooseProviderAuthority("destination");
    fireEvent.change(screen.getByLabelText("New candidate identity kind"), {
      target: { value: "email" },
    });
    fireEvent.change(selectElement("#candidate-application"), {
      target: { value: application.id },
    });
    fireEvent.click(screen.getByRole("button", { name: /Create proof intent/u }));
    fireEvent.change(await screen.findByLabelText("Typed confirmation phrase"), {
      target: { value: "LINK IDENTITY" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Confirm exact link at revision 4/u }));

    await waitFor(() => {
      expect(get).toHaveBeenCalledWith(
        "/v1/projects/{project_id}/identity-mutation-intents/{intent_id}",
        expect.objectContaining({
          params: { path: { project_id: project.id, intent_id: ready.id } },
        }),
      );
    });
    expect(onError).toHaveBeenCalledWith(conflict);
    expect(
      screen.getByRole("heading", { name: "Identity mutation intent" }).parentElement,
    ).toHaveTextContent("revision 6");
    expect(screen.getByRole("heading", { name: "Exact immutable create-time plan" })).toBeVisible();
    expect(screen.getByLabelText("Typed confirmation phrase")).toHaveValue("");
  });

  it("reuses one idempotency key after a network ambiguity and exposes a blocked-popup target", async () => {
    const keys: string[] = [];
    const post = vi.fn((_path: string, options: unknown) => {
      const request = options as { params: { header: Record<string, string> } };
      keys.push(request.params.header["Idempotency-Key"] ?? "");
      return keys.length === 1
        ? Promise.reject(new ControlRequestError(undefined, 503))
        : Promise.resolve(successful(intent("link")));
    });
    vi.spyOn(window, "open").mockReturnValue(null);
    renderPanel({ post });
    chooseOperation("link");
    fireEvent.change(screen.getByLabelText("Exact existing identity"), {
      target: { value: providerIdentity.id },
    });
    chooseProviderAuthority("destination");
    fireEvent.change(screen.getByLabelText("New candidate identity kind"), {
      target: { value: "email" },
    });
    fireEvent.change(selectElement("#candidate-application"), {
      target: { value: application.id },
    });
    fireEvent.click(screen.getByRole("button", { name: /Create proof intent/u }));
    await waitFor(() => {
      expect(post).toHaveBeenCalledTimes(1);
    });
    fireEvent.click(screen.getByRole("button", { name: /Create proof intent/u }));
    expect(
      await screen.findByRole("link", { name: /Continue Hosted identity verification/u }),
    ).toBeVisible();
    expect(keys[1]).toBe(keys[0]);
  });

  it("handles a create 409 honestly and refreshes selected-user authority", async () => {
    const conflict = new ControlRequestError(undefined, 409);
    const reload = vi.fn(() => Promise.resolve());
    const onError = vi.fn(() => Promise.resolve());
    vi.spyOn(window, "open").mockReturnValue(popup().value);
    renderPanel({ post: () => Promise.reject(conflict), reload, onError });
    chooseOperation("link");
    fireEvent.change(screen.getByLabelText("Exact existing identity"), {
      target: { value: providerIdentity.id },
    });
    chooseProviderAuthority("destination");
    fireEvent.change(screen.getByLabelText("New candidate identity kind"), {
      target: { value: "email" },
    });
    fireEvent.change(selectElement("#candidate-application"), {
      target: { value: application.id },
    });
    fireEvent.click(screen.getByRole("button", { name: /Create proof intent/u }));
    expect(await screen.findByRole("status")).toHaveTextContent(
      /conflicted with current authority/u,
    );
    expect(reload).toHaveBeenCalledOnce();
    expect(onError).toHaveBeenCalledWith(conflict);
  });
});
