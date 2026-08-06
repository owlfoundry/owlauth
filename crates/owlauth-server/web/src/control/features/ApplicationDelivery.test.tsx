import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";

import {
  type Application,
  ControlRequestError,
  type DisposableControlClient,
  type WebhookDelivery,
  type WebhookEndpoint,
} from "../client";
import { ControlConfirmationProvider } from "../app/Confirmation";
import { ApplicationDelivery } from "./ApplicationDelivery";

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

function failed() {
  const problem = { code: "service_unavailable", detail: "temporary delivery failure" };
  return {
    data: undefined,
    error: problem,
    response: Response.json(problem, { status: 503 }),
  };
}

function renderPanel(options?: {
  endpoint?: WebhookEndpoint;
  delivery?: WebhookDelivery;
  conflictEndpoint?: boolean;
  failInitialEndpointRead?: boolean;
}) {
  let endpoint = options?.endpoint;
  let endpointReads = 0;
  const get = vi.fn((path: string) => {
    if (path.endsWith("/webhook-endpoints")) {
      endpointReads += 1;
      if (options?.failInitialEndpointRead === true && endpointReads === 1) {
        return Promise.resolve(failed());
      }
      return Promise.resolve(successful({ items: endpoint === undefined ? [] : [endpoint] }));
    }
    if (path.endsWith("/user-events")) return Promise.resolve(successful({ items: [] }));
    if (path.endsWith("/webhook-deliveries")) {
      return Promise.resolve(successful({ items: options?.delivery ? [options.delivery] : [] }));
    }
    throw new Error(`unexpected GET ${path}`);
  });
  const put = vi.fn((path: string, _request: { body: Record<string, unknown> }) => {
    void _request;
    if (path.includes("/webhook-endpoints/") && options?.conflictEndpoint === true) {
      if (endpoint === undefined) throw new Error("missing endpoint");
      endpoint = {
        ...endpoint,
        subscribed_event_types: ["user.projection.disabled"],
        revision: endpoint.revision + 1,
      };
      return Promise.reject(new ControlRequestError(undefined, 409));
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
  const onError = vi.fn(async (error: unknown, refreshConflict?: () => Promise<void>) => {
    if (error instanceof ControlRequestError && error.status === 409) {
      await refreshConflict?.();
    }
  });
  const setMessage = vi.fn();
  const session = {
    client: { GET: get, PUT: put, POST: post },
    dispose: vi.fn(),
  } as unknown as DisposableControlClient;
  const router = createMemoryRouter([
    {
      path: "*",
      element: (
        <ControlConfirmationProvider>
          <ApplicationDelivery
            session={session}
            application={application}
            onError={onError}
            setMessage={setMessage}
          />
        </ControlConfirmationProvider>
      ),
    },
  ]);
  render(<RouterProvider router={router} />);
  return { get, onError, post, put, setMessage };
}

describe("Application sync Console", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("keeps failed initial reads distinct from empty state and retries the coherent snapshot", async () => {
    const { onError } = renderPanel({ failInitialEndpointRead: true });

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Application delivery state could not be loaded",
    );
    expect(screen.queryByRole("heading", { name: "No webhook endpoints" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "No Application user events" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "No webhook deliveries" })).toBeNull();
    expect(screen.getByText("Webhook endpoints are unavailable.")).toBeVisible();
    expect(onError).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: "Retry Application delivery state" }));
    expect(await screen.findByRole("heading", { name: "No webhook endpoints" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "No Application user events" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "No webhook deliveries" })).toBeVisible();
    expect(screen.queryByText("Application delivery state could not be loaded")).toBeNull();
  });

  it("clears a write-only secret and enforces pending test then activation", async () => {
    const { post, setMessage } = renderPanel();
    expect(await screen.findByRole("heading", { name: "No webhook endpoints" })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Create webhook endpoint" }));

    fireEvent.change(screen.getByLabelText("HTTPS URL"), {
      target: { value: "https://hooks.example/events" },
    });
    const secret = screen.getByLabelText("Signing secret");
    fireEvent.change(secret, { target: { value: "a".repeat(32) } });
    fireEvent.click(screen.getByRole("button", { name: "Create pending endpoint" }));

    await waitFor(() => {
      expect(screen.getByText("pending")).toBeVisible();
    });
    expect(secret).not.toBeInTheDocument();
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
      expect(screen.getByText("active")).toBeVisible();
    });
    expect(setMessage).toHaveBeenCalledWith("Webhook endpoint activated.");
  });

  it("closes a stale subscription draft and remounts committed state after a conflict", async () => {
    const { put } = renderPanel({ endpoint: baseEndpoint, conflictEndpoint: true });
    fireEvent.click(await screen.findByRole("button", { name: "Edit subscriptions" }));
    const created = screen.getByLabelText("user.projection.created");
    expect(created).toBeChecked();
    fireEvent.click(created);
    fireEvent.click(screen.getByRole("button", { name: "Save subscriptions" }));

    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Edit webhook subscriptions" })).toBeNull();
    });
    fireEvent.click(screen.getByRole("button", { name: "Edit subscriptions" }));
    expect(screen.getByLabelText("user.projection.created")).not.toBeChecked();
    expect(screen.getByLabelText("user.projection.disabled")).toBeChecked();
    expect(put).toHaveBeenCalledTimes(1);
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
    const { post } = renderPanel({ endpoint: active, delivery });
    fireEvent.click(await screen.findByRole("button", { name: "Rotate secret" }));
    expect(await screen.findByLabelText("Next signing secret")).toBeVisible();

    const secret = screen.getByLabelText("Next signing secret");
    fireEvent.change(secret, { target: { value: "too-short" } });
    fireEvent.click(screen.getByRole("button", { name: "Prepare secret rotation" }));
    expect(post).not.toHaveBeenCalled();
    fireEvent.change(secret, { target: { value: "b".repeat(32) } });
    fireEvent.click(screen.getByRole("button", { name: "Prepare secret rotation" }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Activate generation 2" })).toBeVisible();
    });
    expect(secret).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("b".repeat(32));

    const overlap = screen.getByLabelText("Overlap window in seconds");
    fireEvent.change(overlap, { target: { value: "10" } });
    fireEvent.click(screen.getByRole("button", { name: "Activate generation 2" }));
    expect(post).toHaveBeenCalledTimes(1);
    fireEvent.change(overlap, { target: { value: "600" } });
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
    fireEvent.click(screen.getByRole("button", { name: "Replay delivery" }));
    await waitFor(() => {
      expect(
        post.mock.calls.some(
          ([path, request]) => path.endsWith("/replay") && request.body["confirm"] === true,
        ),
      ).toBe(true);
    });
  });
});
