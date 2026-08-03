import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { SyntheticEvent } from "react";

import styles from "./app.module.css";
import {
  type Application,
  type ApplicationUserEvent,
  type ApplicationUserEventType,
  type DisposableControlClient,
  IdempotencyAttempt,
  type ProjectionPolicy,
  type WebhookDelivery,
  type WebhookEndpoint,
  requireData,
} from "./client";

const EVENT_TYPES: readonly ApplicationUserEventType[] = [
  "user.projection.created",
  "user.projection.updated",
  "user.projection.disabled",
];

interface ProjectProjectionPanelProps {
  readonly session: DisposableControlClient;
  readonly projectId: string;
  readonly disabled: boolean;
  readonly onError: (error: unknown) => Promise<void>;
  readonly setMessage: (message: string | null) => void;
}

export function ProjectProjectionPanel({
  session,
  projectId,
  disabled,
  onError,
  setMessage,
}: ProjectProjectionPanelProps) {
  const [policy, setPolicy] = useState<ProjectionPolicy | null>(null);

  const refresh = useCallback(async () => {
    const result = await session.client.GET("/v1/projects/{project_id}/projection-policy", {
      params: { path: { project_id: projectId } },
    });
    setPolicy(requireData(result.data, result.error, result.response));
  }, [projectId, session]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void refresh().catch(onError);
    }, 0);
    return () => {
      window.clearTimeout(timer);
    };
  }, [onError, refresh]);

  async function update(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (policy === null) return;
    const fields = new FormData(event.currentTarget);
    try {
      const result = await session.client.PUT("/v1/projects/{project_id}/projection-policy", {
        params: { path: { project_id: projectId } },
        body: {
          verified_email_enabled: fields.get("verified_email_enabled") === "on",
          expected_revision: policy.revision,
        },
      });
      const updated = requireData(result.data, result.error, result.response);
      setPolicy(updated);
      setMessage(
        updated.expansion_operation_id === null
          ? "Project projection policy is already converged."
          : "Project projection expansion was scheduled.",
      );
    } catch (error) {
      await onError(error);
      await refresh().catch(onError);
    }
  }

  if (policy === null) return null;
  return (
    <form className={styles["form"]} onSubmit={(event) => void update(event)}>
      <h3>Project user projection</h3>
      <p>Revision {String(policy.revision)}. Expansion is asynchronous and monotonic.</p>
      <label>
        <input
          name="verified_email_enabled"
          type="checkbox"
          defaultChecked={policy.verified_email_enabled}
          disabled={disabled}
        />
        Allow verified email in Application projections
      </label>
      <button type="submit" disabled={disabled}>
        Update Project projection
      </button>
    </form>
  );
}

interface ApplicationSyncPanelProps {
  readonly session: DisposableControlClient;
  readonly application: Application;
  readonly onError: (error: unknown) => Promise<void>;
  readonly setMessage: (message: string | null) => void;
}

interface PreparedRotation {
  readonly generation: number;
  readonly endpointRevision: number;
}

export function ApplicationSyncPanel({
  session,
  application,
  onError,
  setMessage,
}: ApplicationSyncPanelProps) {
  const [policy, setPolicy] = useState<ProjectionPolicy | null>(null);
  const [endpoints, setEndpoints] = useState<WebhookEndpoint[]>([]);
  const [events, setEvents] = useState<ApplicationUserEvent[]>([]);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [preparedRotations, setPreparedRotations] = useState<Record<string, PreparedRotation>>({});
  const createAttempt = useRef(new IdempotencyAttempt());

  const path = useMemo(
    () => ({
      project_id: application.project_id,
      application_id: application.id,
    }),
    [application.id, application.project_id],
  );

  const refresh = useCallback(async () => {
    const [policyResult, endpointResult, eventResult, deliveryResult] = await Promise.all([
      session.client.GET(
        "/v1/projects/{project_id}/applications/{application_id}/projection-policy",
        { params: { path } },
      ),
      session.client.GET(
        "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints",
        { params: { path } },
      ),
      session.client.GET("/v1/projects/{project_id}/applications/{application_id}/user-events", {
        params: { path },
      }),
      session.client.GET(
        "/v1/projects/{project_id}/applications/{application_id}/webhook-deliveries",
        { params: { path, query: {} } },
      ),
    ]);
    setPolicy(requireData(policyResult.data, policyResult.error, policyResult.response));
    setEndpoints(
      requireData(endpointResult.data, endpointResult.error, endpointResult.response).items,
    );
    setEvents(requireData(eventResult.data, eventResult.error, eventResult.response).items);
    setDeliveries(
      requireData(deliveryResult.data, deliveryResult.error, deliveryResult.response).items,
    );
  }, [path, session]);

  useEffect(() => {
    createAttempt.current.abandon();
    const timer = window.setTimeout(() => {
      void refresh().catch(onError);
    }, 0);
    return () => {
      window.clearTimeout(timer);
    };
  }, [onError, refresh]);

  async function updateProjection(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (policy === null) return;
    const fields = new FormData(event.currentTarget);
    try {
      const result = await session.client.PUT(
        "/v1/projects/{project_id}/applications/{application_id}/projection-policy",
        {
          params: { path },
          body: {
            verified_email_enabled: fields.get("verified_email_enabled") === "on",
            expected_revision: policy.revision,
          },
        },
      );
      setPolicy(requireData(result.data, result.error, result.response));
      setMessage("Application projection expansion was scheduled.");
    } catch (error) {
      await onError(error);
      await refresh().catch(onError);
    }
  }

  async function createEndpoint(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    const idempotencyKey = createAttempt.current.begin();
    if (idempotencyKey === null) return;
    const secretInput = form.elements.namedItem("secret");
    const secret = fieldText(fields, "secret");
    if (secretInput instanceof HTMLInputElement) secretInput.value = "";
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints",
        {
          params: { path, header: { "Idempotency-Key": idempotencyKey } },
          body: {
            url: fieldText(fields, "url"),
            subscribed_event_types: selectedEventTypes(fields),
            secret,
          },
        },
      );
      requireData(result.data, result.error, result.response);
      createAttempt.current.settle();
      form.reset();
      await refresh();
      setMessage("Pending webhook endpoint created. Test it before activation.");
    } catch (error) {
      createAttempt.current.settle(error);
      await onError(error);
    }
  }

  async function updateEndpoint(
    endpoint: WebhookEndpoint,
    event: SyntheticEvent<HTMLFormElement, SubmitEvent>,
  ) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    try {
      const result = await session.client.PUT(
        "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}",
        {
          params: { path: { ...path, endpoint_id: endpoint.id } },
          body: {
            subscribed_event_types: selectedEventTypes(fields),
            expected_revision: endpoint.revision,
          },
        },
      );
      requireData(result.data, result.error, result.response);
      await refresh();
      setMessage("Webhook subscriptions updated.");
    } catch (error) {
      await onError(error);
      await refresh().catch(onError);
    }
  }

  async function endpointTransition(
    endpoint: WebhookEndpoint,
    action: "test" | "activate" | "disable",
  ) {
    try {
      const params = { path: { ...path, endpoint_id: endpoint.id } };
      const body = { expected_revision: endpoint.revision };
      const result =
        action === "test"
          ? await session.client.POST(
              "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/test",
              { params, body },
            )
          : action === "activate"
            ? await session.client.POST(
                "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/activate",
                { params, body },
              )
            : await session.client.POST(
                "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/disable",
                { params, body },
              );
      requireData(result.data, result.error, result.response);
      await refresh();
      setMessage(
        action === "test"
          ? "Webhook DNS and destination policy test passed."
          : action === "activate"
            ? "Webhook endpoint activated."
            : "Webhook endpoint disabled.",
      );
    } catch (error) {
      await onError(error);
      await refresh().catch(onError);
    }
  }

  async function prepareRotation(
    endpoint: WebhookEndpoint,
    idempotencyKey: string,
    secret: string,
  ) {
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/secret-rotations",
        {
          params: {
            path: { ...path, endpoint_id: endpoint.id },
            header: { "Idempotency-Key": idempotencyKey },
          },
          body: { secret, expected_revision: endpoint.revision },
        },
      );
      const prepared = requireData(result.data, result.error, result.response);
      setPreparedRotations((current) => ({
        ...current,
        [endpoint.id]: {
          generation: prepared.generation,
          endpointRevision: prepared.endpoint.revision,
        },
      }));
      await refresh();
      setMessage("Webhook secret generation prepared; activate it after consumer rollout.");
    } catch (error) {
      await onError(error);
      await refresh().catch(onError);
      throw error;
    }
  }

  async function activateRotation(
    endpoint: WebhookEndpoint,
    prepared: PreparedRotation,
    overlapSeconds: number,
  ) {
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/secret-rotations/{generation}/activate",
        {
          params: {
            path: {
              ...path,
              endpoint_id: endpoint.id,
              generation: prepared.generation,
            },
          },
          body: {
            expected_revision: prepared.endpointRevision,
            overlap_seconds: overlapSeconds,
          },
        },
      );
      requireData(result.data, result.error, result.response);
      setPreparedRotations((current) =>
        Object.fromEntries(Object.entries(current).filter(([id]) => id !== endpoint.id)),
      );
      await refresh();
      setMessage("Webhook secret generation activated with bounded overlap.");
    } catch (error) {
      await onError(error);
      await refresh().catch(onError);
    }
  }

  async function replay(delivery: WebhookDelivery) {
    if (!window.confirm(`Replay delivery ${delivery.id} for the same immutable event?`)) return;
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/applications/{application_id}/webhook-deliveries/{delivery_id}/replay",
        {
          params: { path: { ...path, delivery_id: delivery.id } },
          body: { confirm: true },
        },
      );
      requireData(result.data, result.error, result.response);
      await refresh();
      setMessage("A new webhook delivery lineage was created for the immutable event.");
    } catch (error) {
      await onError(error);
    }
  }

  const disabled = application.status !== "active";
  return (
    <section aria-labelledby={`application-sync-${application.id}`}>
      <h5 id={`application-sync-${application.id}`}>Application user sync</h5>
      {policy === null ? null : (
        <form className={styles["form"]} onSubmit={(event) => void updateProjection(event)}>
          <p>Projection policy revision {String(policy.revision)}.</p>
          <label>
            <input
              name="verified_email_enabled"
              type="checkbox"
              defaultChecked={policy.verified_email_enabled}
              disabled={disabled}
            />
            Allow verified email for this Application
          </label>
          <button type="submit" disabled={disabled}>
            Update Application projection
          </button>
        </form>
      )}

      <form className={styles["form"]} onSubmit={(event) => void createEndpoint(event)}>
        <h6>Create webhook endpoint</h6>
        <label htmlFor={`webhook-url-${application.id}`}>HTTPS URL</label>
        <input
          id={`webhook-url-${application.id}`}
          name="url"
          type="url"
          required
          disabled={disabled}
        />
        <EventTypeFields prefix={`new-${application.id}`} />
        <label htmlFor={`webhook-secret-${application.id}`}>Signing secret</label>
        <input
          id={`webhook-secret-${application.id}`}
          name="secret"
          type="password"
          minLength={32}
          maxLength={128}
          autoComplete="new-password"
          required
          disabled={disabled}
        />
        <button type="submit" disabled={disabled}>
          Create pending endpoint
        </button>
      </form>

      {endpoints.length === 0 ? <p>No webhook endpoints.</p> : null}
      {endpoints.map((endpoint) => (
        <article className={styles["panel"]} key={`${endpoint.id}:${String(endpoint.revision)}`}>
          <h6>{endpoint.url}</h6>
          <p>
            Status {endpoint.status}; revision {String(endpoint.revision)}; current secret
            generation {endpoint.current_secret_generation ?? "none"}.
          </p>
          <p>
            Last tested {endpoint.last_tested_at ?? "never"}; last success{" "}
            {endpoint.last_success_at ?? "never"}; consecutive failures{" "}
            {String(endpoint.consecutive_failure_count)}.
          </p>
          <form
            className={styles["form"]}
            onSubmit={(event) => void updateEndpoint(endpoint, event)}
          >
            <EventTypeFields
              prefix={`endpoint-${endpoint.id}`}
              selected={endpoint.subscribed_event_types}
            />
            <button type="submit" disabled={endpoint.status === "disabled" || disabled}>
              Update subscriptions
            </button>
          </form>
          {endpoint.status === "pending" ? (
            <>
              <button type="button" onClick={() => void endpointTransition(endpoint, "test")}>
                Test destination policy
              </button>{" "}
              <button
                type="button"
                disabled={endpoint.last_test_succeeded_at === null}
                onClick={() => void endpointTransition(endpoint, "activate")}
              >
                Activate endpoint
              </button>
            </>
          ) : null}
          {endpoint.status !== "disabled" ? (
            <>
              {" "}
              <button type="button" onClick={() => void endpointTransition(endpoint, "disable")}>
                Disable endpoint
              </button>
              <WebhookRotationForm
                endpoint={endpoint}
                prepared={preparedRotations[endpoint.id]}
                onPrepare={prepareRotation}
                onActivate={activateRotation}
              />
            </>
          ) : null}
        </article>
      ))}

      <h6>Immutable user events</h6>
      {events.length === 0 ? (
        <p>No Application user events.</p>
      ) : (
        <ul className={styles["list"]}>
          {events.map((item) => (
            <li key={item.event_id}>
              <code>{item.event_type}</code> user <code>{item.user_id}</code>, user revision{" "}
              {String(item.user_revision)}, projection revision {String(item.projection_revision)}
              <details>
                <summary>Safe event body</summary>
                <pre>{JSON.stringify(item.safe_body, null, 2)}</pre>
              </details>
            </li>
          ))}
        </ul>
      )}

      <h6>Webhook deliveries</h6>
      {deliveries.length === 0 ? (
        <p>No webhook deliveries.</p>
      ) : (
        <ul className={styles["list"]}>
          {deliveries.map((delivery) => (
            <li key={delivery.id}>
              Event <code>{delivery.event_id}</code>; state {delivery.state}; attempts{" "}
              {String(delivery.attempt_count)}; outcome {delivery.last_outcome_class ?? "none"}
              {delivery.state === "terminal" ? (
                <button type="button" onClick={() => void replay(delivery)}>
                  Replay immutable event
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      <button type="button" onClick={() => void refresh().catch(onError)}>
        Refresh sync state
      </button>
    </section>
  );
}

interface WebhookRotationFormProps {
  readonly endpoint: WebhookEndpoint;
  readonly prepared: PreparedRotation | undefined;
  readonly onPrepare: (
    endpoint: WebhookEndpoint,
    idempotencyKey: string,
    secret: string,
  ) => Promise<void>;
  readonly onActivate: (
    endpoint: WebhookEndpoint,
    prepared: PreparedRotation,
    overlapSeconds: number,
  ) => Promise<void>;
}

function WebhookRotationForm({
  endpoint,
  prepared,
  onPrepare,
  onActivate,
}: WebhookRotationFormProps) {
  const attempt = useRef(new IdempotencyAttempt());
  const overlapInput = useRef<HTMLInputElement | null>(null);

  async function submit(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    const idempotencyKey = attempt.current.begin();
    if (idempotencyKey === null) return;
    const secret = fieldText(fields, "rotation_secret");
    const input = form.elements.namedItem("rotation_secret");
    if (input instanceof HTMLInputElement) input.value = "";
    try {
      await onPrepare(endpoint, idempotencyKey, secret);
      attempt.current.settle();
    } catch (error) {
      attempt.current.settle(error);
    }
  }

  return (
    <form className={styles["form"]} onSubmit={(event) => void submit(event)}>
      <label htmlFor={`rotation-secret-${endpoint.id}`}>Next signing secret</label>
      <input
        id={`rotation-secret-${endpoint.id}`}
        name="rotation_secret"
        type="password"
        minLength={32}
        maxLength={128}
        autoComplete="new-password"
        required
      />
      <button type="submit">Prepare secret rotation</button>
      {prepared === undefined ? null : (
        <>
          <label htmlFor={`rotation-overlap-${endpoint.id}`}>Overlap seconds</label>
          <input
            ref={overlapInput}
            id={`rotation-overlap-${endpoint.id}`}
            type="number"
            min={300}
            max={86400}
            defaultValue={3600}
          />
          <button
            type="button"
            onClick={() =>
              void onActivate(endpoint, prepared, Number(overlapInput.current?.value ?? 3600))
            }
          >
            Activate generation {String(prepared.generation)}
          </button>
        </>
      )}
    </form>
  );
}

interface EventTypeFieldsProps {
  readonly prefix: string;
  readonly selected?: readonly ApplicationUserEventType[];
}

function EventTypeFields({ prefix, selected = EVENT_TYPES }: EventTypeFieldsProps) {
  return (
    <fieldset>
      <legend>Subscribed event types</legend>
      {EVENT_TYPES.map((eventType) => (
        <label key={eventType} htmlFor={`${prefix}-${eventType}`}>
          <input
            id={`${prefix}-${eventType}`}
            name="subscribed_event_types"
            type="checkbox"
            value={eventType}
            defaultChecked={selected.includes(eventType)}
          />
          {eventType}
        </label>
      ))}
    </fieldset>
  );
}

function fieldText(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}

function selectedEventTypes(fields: FormData): ApplicationUserEventType[] {
  const selected = fields
    .getAll("subscribed_event_types")
    .filter((value): value is string => typeof value === "string")
    .filter((value): value is ApplicationUserEventType =>
      EVENT_TYPES.includes(value as ApplicationUserEventType),
    );
  return selected;
}
