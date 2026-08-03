import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import {
  type Application,
  type DisposableControlClient,
  type ProjectionPolicy,
  type WebhookDelivery,
  type WebhookEndpoint,
} from "./client";
import { ApplicationSyncPanel } from "./ApplicationSyncPanel";

const application: Application = {
  id: "22222222-2222-4222-8222-222222222222",
  project_id: "11111111-1111-4111-8111-111111111111",
  public_id: "app_public123",
  display_name: "Customer portal",
  application_type: "web",
  configuration: {
    allowed_origins: ["https://app.example"],
    publishable_keys: ["pk_test"],
    redirect_uris: ["https://app.example/callback"],
  },
  status: "active",
  metadata_revision: 1,
  security_revision: 1,
};

const policy: ProjectionPolicy = {
  project_id: application.project_id,
  application_id: application.id,
  verified_email_enabled: false,
  revision: 1,
  expansion_operation_id: null,
};

const baseEndpoint: WebhookEndpoint = {
  id: "33333333-3333-4333-8333-333333333333",
  public_id: "whk_public123",
  project_id: application.project_id,
  application_id: application.id,
  url: "https://hooks.example/events",
  subscribed_event_types: ["user.projection.created", "user.projection.updated"],
  status: "pending",
  revision: 1,
  current_secret_generation: 1,
  overlap_secret_generation: null,
  overlap_expires_at: null,
  consecutive_failure_count: 0,
  last_delivery_at: null,
  last_success_at: null,
  last_failure_class: null,
  last_tested_at: null,
  last_test_succeeded_at: null,
  created_at: "2026-08-03T00:00:00Z",
  updated_at: "2026-08-03T00:00:00Z",
};

function successful<T>(data: T) {
  return { data, error: undefined, response: Response.json(data) };
}

function renderPanel(options?: { endpoint?: WebhookEndpoint; delivery?: WebhookDelivery }) {
  let endpoint = options?.endpoint;
  let currentPolicy = policy;
  const get = vi.fn((path: string) => {
    if (path.endsWith("/projection-policy")) return Promise.resolve(successful(currentPolicy));
    if (path.endsWith("/webhook-endpoints")) {
      return Promise.resolve(successful({ items: endpoint === undefined ? [] : [endpoint] }));
    }
    if (path.endsWith("/user-events")) return Promise.resolve(successful({ items: [] }));
    if (path.endsWith("/webhook-deliveries")) {
      return Promise.resolve(successful({ items: options?.delivery ? [options.delivery] : [] }));
    }
    throw new Error(`unexpected GET ${path}`);
  });
  const put = vi.fn((path: string, request: { body: { verified_email_enabled?: boolean } }) => {
    if (path.endsWith("/projection-policy")) {
      currentPolicy = {
        ...currentPolicy,
        verified_email_enabled: request.body.verified_email_enabled ?? false,
        revision: currentPolicy.revision + 1,
        expansion_operation_id: "44444444-4444-4444-8444-444444444444",
      };
      return Promise.resolve(successful(currentPolicy));
    }
    throw new Error(`unexpected PUT ${path}`);
  });
  const post = vi.fn(
    (
      path: string,
      _request: {
        body: Record<string, unknown>;
        params?: { header?: { "Idempotency-Key"?: string } };
      },
    ) => {
      void _request;
      if (path.endsWith("/webhook-endpoints")) {
        endpoint = baseEndpoint;
        return Promise.resolve(successful(endpoint));
      }
      if (path.endsWith("/test") && endpoint !== undefined) {
        endpoint = {
          ...endpoint,
          revision: endpoint.revision + 1,
          last_tested_at: "2026-08-03T00:01:00Z",
          last_test_succeeded_at: "2026-08-03T00:01:00Z",
        };
        return Promise.resolve(successful(endpoint));
      }
      if (path.endsWith("/activate") && path.includes("/secret-rotations/")) {
        if (endpoint === undefined) throw new Error("missing endpoint");
        endpoint = {
          ...endpoint,
          revision: endpoint.revision + 1,
          current_secret_generation: 2,
          overlap_secret_generation: 1,
        };
        return Promise.resolve(successful(endpoint));
      }
      if (path.endsWith("/activate") && endpoint !== undefined) {
        endpoint = { ...endpoint, status: "active", revision: endpoint.revision + 1 };
        return Promise.resolve(successful(endpoint));
      }
      if (path.endsWith("/secret-rotations") && endpoint !== undefined) {
        endpoint = { ...endpoint, revision: endpoint.revision + 1 };
        return Promise.resolve(successful({ endpoint, generation: 2, already_active: false }));
      }
      if (path.endsWith("/replay") && options?.delivery !== undefined) {
        return Promise.resolve(
          successful({
            ...options.delivery,
            id: "55555555-5555-4555-8555-555555555555",
            state: "pending",
            replay_of_delivery_id: options.delivery.id,
            replay_sequence: 1,
          }),
        );
      }
      throw new Error(`unexpected POST ${path}`);
    },
  );
  const onError = vi.fn(() => Promise.resolve());
  const setMessage = vi.fn();
  const session = {
    client: { GET: get, PUT: put, POST: post },
    dispose: vi.fn(),
  } as unknown as DisposableControlClient;
  render(
    <ApplicationSyncPanel
      session={session}
      application={application}
      onError={onError}
      setMessage={setMessage}
    />,
  );
  return { get, onError, post, put, setMessage };
}

describe("Application sync Console", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("clears a write-only secret and enforces pending test then activation", async () => {
    const { post, setMessage } = renderPanel();
    expect(await screen.findByText("No webhook endpoints.")).toBeVisible();

    fireEvent.change(screen.getByLabelText("HTTPS URL"), {
      target: { value: "https://hooks.example/events" },
    });
    const secret = screen.getByLabelText("Signing secret");
    fireEvent.change(secret, { target: { value: "a".repeat(32) } });
    fireEvent.click(screen.getByRole("button", { name: "Create pending endpoint" }));

    await waitFor(() => {
      expect(screen.getByText(/Status pending/u)).toBeVisible();
    });
    expect(secret).toHaveValue("");
    expect(document.body.textContent).not.toContain("a".repeat(32));
    expect(post.mock.calls[0]?.[1]).toMatchObject({
      body: { secret: "a".repeat(32), url: "https://hooks.example/events" },
    });
    expect(post.mock.calls[0]?.[1].params?.header?.["Idempotency-Key"]).not.toBe("");

    const activate = screen.getByRole("button", { name: "Activate endpoint" });
    expect(activate).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Test destination policy" }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Activate endpoint" })).toBeEnabled();
    });
    fireEvent.click(screen.getByRole("button", { name: "Activate endpoint" }));
    await waitFor(() => {
      expect(screen.getByText(/Status active/u)).toBeVisible();
    });
    expect(setMessage).toHaveBeenCalledWith("Webhook endpoint activated.");
  });

  it("prepares and activates a bounded secret overlap and confirms replay", async () => {
    const delivery: WebhookDelivery = {
      id: "66666666-6666-4666-8666-666666666666",
      endpoint_id: baseEndpoint.id,
      event_id: "77777777-7777-4777-8777-777777777777",
      state: "terminal",
      attempt_count: 3,
      next_attempt_at: "2026-08-03T00:00:00Z",
      last_http_status: 410,
      last_outcome_class: "permanent",
      delivered_at: null,
      terminal_at: "2026-08-03T00:10:00Z",
      replay_of_delivery_id: null,
      replay_sequence: 0,
      created_at: "2026-08-03T00:00:00Z",
    };
    const active = {
      ...baseEndpoint,
      status: "active" as const,
      last_tested_at: "2026-08-03T00:01:00Z",
      last_test_succeeded_at: "2026-08-03T00:01:00Z",
    };
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const { post } = renderPanel({ endpoint: active, delivery });
    expect(await screen.findByLabelText("Next signing secret")).toBeVisible();

    const secret = screen.getByLabelText("Next signing secret");
    fireEvent.change(secret, { target: { value: "b".repeat(32) } });
    fireEvent.click(screen.getByRole("button", { name: "Prepare secret rotation" }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Activate generation 2" })).toBeVisible();
    });
    expect(secret).toHaveValue("");
    expect(document.body.textContent).not.toContain("b".repeat(32));

    fireEvent.change(screen.getByLabelText("Overlap seconds"), { target: { value: "600" } });
    fireEvent.click(screen.getByRole("button", { name: "Activate generation 2" }));
    await waitFor(() => {
      expect(
        post.mock.calls.some(
          ([path, request]) =>
            path.includes("/secret-rotations/") &&
            path.endsWith("/activate") &&
            request.body["overlap_seconds"] === 600,
        ),
      ).toBe(true);
    });

    fireEvent.click(screen.getByRole("button", { name: "Replay immutable event" }));
    await waitFor(() => {
      expect(
        post.mock.calls.some(
          ([path, request]) => path.endsWith("/replay") && request.body["confirm"] === true,
        ),
      ).toBe(true);
    });
  });
});
