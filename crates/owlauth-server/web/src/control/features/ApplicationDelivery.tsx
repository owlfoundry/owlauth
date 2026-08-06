import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { SyntheticEvent } from "react";

import { DataTable, DescriptionList, EmptyState, Section } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Checkbox, Field, Input } from "../../shared/primitives/Field";
import { Dialog } from "../../shared/primitives/Overlay";
import { useControlConfirmation } from "../app/Confirmation";
import {
  type Application,
  type ApplicationUserEvent,
  type ApplicationUserEventType,
  ControlRequestError,
  type DisposableControlClient,
  IdempotencyAttempt,
  type WebhookDelivery,
  type WebhookEndpoint,
  requireData,
} from "../client";
import styles from "./features.module.css";

const EVENT_TYPES: readonly ApplicationUserEventType[] = [
  "user.projection.created",
  "user.projection.updated",
  "user.projection.disabled",
];

type ErrorHandler = (error: unknown, refreshConflict?: () => Promise<void>) => Promise<void>;
type LoadState = "loading" | "ready" | "failed";

export interface ApplicationDeliveryDraft {
  readonly submitting: boolean;
  readonly discard: () => void;
}

interface ApplicationDeliveryProps {
  readonly session: DisposableControlClient;
  readonly application: Application;
  readonly onError: ErrorHandler;
  readonly setMessage: (message: string | null) => void;
  readonly onDraftChange?: (draft: ApplicationDeliveryDraft | null) => void;
}

interface PreparedRotation {
  readonly generation: number;
  readonly endpointRevision: number;
}

export function ApplicationDelivery({
  session,
  application,
  onError,
  setMessage,
  onDraftChange,
}: ApplicationDeliveryProps) {
  const confirm = useControlConfirmation();
  const [endpoints, setEndpoints] = useState<WebhookEndpoint[]>([]);
  const [events, setEvents] = useState<ApplicationUserEvent[]>([]);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [hasLoaded, setHasLoaded] = useState(false);
  const [preparedRotations, setPreparedRotations] = useState<Record<string, PreparedRotation>>({});
  const [creatingEndpoint, setCreatingEndpoint] = useState(false);
  const [editingEndpointId, setEditingEndpointId] = useState<string | null>(null);
  const [rotatingEndpointId, setRotatingEndpointId] = useState<string | null>(null);
  const [overlayError, setOverlayError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const createAttempt = useRef(new IdempotencyAttempt());
  const rotationAttempt = useRef(new IdempotencyAttempt());
  const discardDraft = useCallback(() => {
    createAttempt.current.abandon();
    rotationAttempt.current.abandon();
    setCreatingEndpoint(false);
    setEditingEndpointId(null);
    setRotatingEndpointId(null);
    setOverlayError(null);
  }, []);
  const draftDirty = creatingEndpoint || editingEndpointId !== null || rotatingEndpointId !== null;

  useEffect(() => {
    if (onDraftChange === undefined) return;
    onDraftChange(draftDirty ? { submitting, discard: discardDraft } : null);
    return () => {
      onDraftChange(null);
    };
  }, [discardDraft, draftDirty, onDraftChange, submitting]);

  const path = useMemo(
    () => ({ project_id: application.project_id, application_id: application.id }),
    [application.id, application.project_id],
  );

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      setLoadState("loading");
      try {
        const [endpointResult, eventResult, deliveryResult] = await Promise.all([
          session.client.GET(
            "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints",
            { params: { path }, signal: signal ?? null },
          ),
          session.client.GET(
            "/v1/projects/{project_id}/applications/{application_id}/user-events",
            {
              params: { path },
              signal: signal ?? null,
            },
          ),
          session.client.GET(
            "/v1/projects/{project_id}/applications/{application_id}/webhook-deliveries",
            { params: { path, query: {} }, signal: signal ?? null },
          ),
        ]);
        const nextEndpoints = requireData(
          endpointResult.data,
          endpointResult.error,
          endpointResult.response,
        ).items;
        const nextEvents = requireData(
          eventResult.data,
          eventResult.error,
          eventResult.response,
        ).items;
        const nextDeliveries = requireData(
          deliveryResult.data,
          deliveryResult.error,
          deliveryResult.response,
        ).items;

        if (signal?.aborted !== true) {
          setEndpoints(nextEndpoints);
          setEvents(nextEvents);
          setDeliveries(nextDeliveries);
          setHasLoaded(true);
          setLoadState("ready");
        }
      } catch (error) {
        if (signal?.aborted !== true) setLoadState("failed");
        throw error;
      }
    },
    [path, session],
  );

  useEffect(() => {
    const endpointAttempt = createAttempt.current;
    const secretRotationAttempt = rotationAttempt.current;
    endpointAttempt.abandon();
    secretRotationAttempt.abandon();
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      setEndpoints([]);
      setEvents([]);
      setDeliveries([]);
      setHasLoaded(false);
      void refresh(controller.signal).catch((error: unknown) => {
        if (!controller.signal.aborted) void onError(error);
      });
    }, 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
      endpointAttempt.abandon();
      secretRotationAttempt.abandon();
    };
  }, [onError, refresh]);

  async function createEndpoint(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    const idempotencyKey = createAttempt.current.begin();
    if (idempotencyKey === null) return;
    const secretInput = form.elements.namedItem("secret");
    const secret = fieldText(fields, "secret");
    if (secretInput instanceof HTMLInputElement) secretInput.value = "";
    setOverlayError(null);
    setSubmitting(true);
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
      setCreatingEndpoint(false);
      setMessage("Pending webhook endpoint created. Test it before activation.");
    } catch (error) {
      createAttempt.current.settle(error);
      setOverlayError(deliveryError(error, "Webhook endpoint could not be created."));
      await onError(error, async () => {
        createAttempt.current.abandon();
        await refresh();
        setCreatingEndpoint(false);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function updateEndpoint(
    endpoint: WebhookEndpoint,
    event: SyntheticEvent<HTMLFormElement, SubmitEvent>,
  ) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    setOverlayError(null);
    setSubmitting(true);
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
      setEditingEndpointId(null);
      setMessage("Webhook subscriptions updated.");
    } catch (error) {
      setOverlayError(deliveryError(error, "Webhook subscriptions could not be updated."));
      await onError(error, async () => {
        await refresh();
        setEditingEndpointId(null);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function endpointTransition(
    endpoint: WebhookEndpoint,
    action: "test" | "activate" | "disable",
  ) {
    setSubmitting(true);
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
      await onError(error, refresh);
    } finally {
      setSubmitting(false);
    }
  }

  async function prepareRotation(endpoint: WebhookEndpoint, secret: string) {
    const idempotencyKey = rotationAttempt.current.begin();
    if (idempotencyKey === null) return;
    setOverlayError(null);
    setSubmitting(true);
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
      rotationAttempt.current.settle();
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
      rotationAttempt.current.settle(error);
      setOverlayError(deliveryError(error, "Webhook secret rotation could not be prepared."));
      await onError(error, async () => {
        rotationAttempt.current.abandon();
        await refresh();
        setRotatingEndpointId(null);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function activateRotation(
    endpoint: WebhookEndpoint,
    prepared: PreparedRotation,
    overlapSeconds: number,
  ) {
    setOverlayError(null);
    setSubmitting(true);
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/secret-rotations/{generation}/activate",
        {
          params: {
            path: { ...path, endpoint_id: endpoint.id, generation: prepared.generation },
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
      rotationAttempt.current.abandon();
      await refresh();
      setRotatingEndpointId(null);
      setMessage("Webhook secret generation activated with bounded overlap.");
    } catch (error) {
      setOverlayError(deliveryError(error, "Webhook secret rotation could not be activated."));
      await onError(error, async () => {
        rotationAttempt.current.abandon();
        await refresh();
        setRotatingEndpointId(null);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function replay(delivery: WebhookDelivery) {
    if (
      !(await confirm({
        title: "Replay webhook delivery",
        message: `Replay delivery ${delivery.id} for the same immutable event?`,
        actionLabel: "Replay delivery",
      }))
    )
      return;
    setSubmitting(true);
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
    } finally {
      setSubmitting(false);
    }
  }

  const disabled = application.status !== "active";
  const editingEndpoint = endpoints.find((endpoint) => endpoint.id === editingEndpointId) ?? null;
  const rotatingEndpoint = endpoints.find((endpoint) => endpoint.id === rotatingEndpointId) ?? null;

  return (
    <>
      {loadState === "failed" ? (
        <InlineAlert tone="danger">
          Application delivery state could not be loaded. Previously loaded values, if shown, were
          preserved and may be stale.{" "}
          <Button type="button" variant="quiet" onClick={() => void refresh().catch(onError)}>
            Retry Application delivery state
          </Button>
        </InlineAlert>
      ) : null}
      <Section
        title="Webhook endpoints"
        description="Endpoint signing secrets are write-only and independently rotated."
        action={
          !disabled && hasLoaded && loadState === "ready" ? (
            <Button
              type="button"
              variant="primary"
              onClick={() => {
                setOverlayError(null);
                setCreatingEndpoint(true);
              }}
            >
              Create webhook endpoint
            </Button>
          ) : undefined
        }
      >
        {!hasLoaded ? (
          loadState === "loading" ? (
            <p role="status">Loading webhook endpoints</p>
          ) : (
            <p>Webhook endpoints are unavailable.</p>
          )
        ) : endpoints.length === 0 ? (
          <EmptyState
            level={3}
            title="No webhook endpoints"
            description="Create a pending endpoint, test its exact destination, then activate it."
          />
        ) : (
          <div className={styles["cards"]}>
            {endpoints.map((endpoint) => (
              <article
                className={styles["panel"]}
                key={`${endpoint.id}:${String(endpoint.revision)}`}
              >
                <div className={styles["sectionHeader"]}>
                  <div>
                    <h3>{endpoint.url}</h3>
                    <StatusBadge status={endpoint.status} />
                  </div>
                  <div className={styles["actions"]}>
                    <Button
                      type="button"
                      variant="quiet"
                      disabled={submitting || endpoint.status === "disabled" || disabled}
                      onClick={() => {
                        setOverlayError(null);
                        setEditingEndpointId(endpoint.id);
                      }}
                    >
                      Edit subscriptions
                    </Button>
                    {endpoint.status === "pending" ? (
                      <>
                        <Button
                          type="button"
                          variant="quiet"
                          disabled={submitting}
                          onClick={() => void endpointTransition(endpoint, "test")}
                        >
                          Test destination policy
                        </Button>
                        <Button
                          type="button"
                          disabled={submitting || endpoint.last_test_succeeded_at === null}
                          onClick={() => void endpointTransition(endpoint, "activate")}
                        >
                          Activate endpoint
                        </Button>
                      </>
                    ) : null}
                    {endpoint.status !== "disabled" ? (
                      <>
                        <Button
                          type="button"
                          variant="quiet"
                          disabled={submitting}
                          onClick={() => {
                            rotationAttempt.current.abandon();
                            setOverlayError(null);
                            setRotatingEndpointId(endpoint.id);
                          }}
                        >
                          Rotate secret
                        </Button>
                        <Button
                          type="button"
                          variant="danger"
                          disabled={submitting}
                          onClick={() => void endpointTransition(endpoint, "disable")}
                        >
                          Disable endpoint
                        </Button>
                      </>
                    ) : null}
                  </div>
                </div>
                <DescriptionList
                  items={[
                    { term: "Subscriptions", detail: endpoint.subscribed_event_types.join(", ") },
                    {
                      term: "Current secret",
                      detail:
                        endpoint.current_secret_generation === null
                          ? "None"
                          : `Generation ${String(endpoint.current_secret_generation)}`,
                    },
                    {
                      term: "Overlap secret",
                      detail:
                        endpoint.overlap_secret_generation === null
                          ? "None"
                          : `Generation ${String(endpoint.overlap_secret_generation)} until ${endpoint.overlap_expires_at ?? "unknown"}`,
                    },
                    { term: "Last destination test", detail: endpoint.last_tested_at ?? "Never" },
                    { term: "Last delivery success", detail: endpoint.last_success_at ?? "Never" },
                    {
                      term: "Consecutive failures",
                      detail: String(endpoint.consecutive_failure_count),
                    },
                  ]}
                />
              </article>
            ))}
          </div>
        )}
      </Section>

      <Section
        title="Immutable user events"
        description="Signed durable-outbox source events and their safe bodies."
      >
        {!hasLoaded ? (
          loadState === "loading" ? (
            <p role="status">Loading Application user events</p>
          ) : (
            <p>Application user events are unavailable.</p>
          )
        ) : events.length === 0 ? (
          <EmptyState
            level={3}
            title="No Application user events"
            description="Events appear after a user projection is created or changed."
          />
        ) : (
          <DataTable
            caption="Immutable Application user events"
            headings={["Event", "User", "Body"]}
          >
            {events.map((item) => (
              <tr key={item.event_id}>
                <td>
                  <code>{item.event_type}</code>
                  <span className={styles["machineValue"]}>{item.event_id}</span>
                </td>
                <td>
                  <code>{item.user_id}</code>
                </td>
                <td>
                  <details>
                    <summary>Review safe body</summary>
                    <pre>{JSON.stringify(item.safe_body, null, 2)}</pre>
                  </details>
                </td>
              </tr>
            ))}
          </DataTable>
        )}
      </Section>

      <Section
        title="Webhook deliveries"
        description="Delivery attempts retain immutable event lineage."
        action={
          <Button
            type="button"
            variant="quiet"
            disabled={submitting}
            onClick={() => void refresh().catch(onError)}
          >
            Refresh delivery state
          </Button>
        }
      >
        {!hasLoaded ? (
          loadState === "loading" ? (
            <p role="status">Loading webhook deliveries</p>
          ) : (
            <p>Webhook deliveries are unavailable.</p>
          )
        ) : deliveries.length === 0 ? (
          <EmptyState
            level={3}
            title="No webhook deliveries"
            description="Deliveries appear after an active endpoint receives a user event."
          />
        ) : (
          <DataTable
            caption="Webhook deliveries"
            headings={["Event", "State", "Attempts", "Outcome", "Action"]}
          >
            {deliveries.map((delivery) => (
              <tr key={delivery.id}>
                <td>
                  <code>{delivery.event_id}</code>
                </td>
                <td>
                  <StatusBadge status={delivery.state} />
                </td>
                <td>{String(delivery.attempt_count)}</td>
                <td>{delivery.last_outcome_class ?? "None"}</td>
                <td>
                  {delivery.state === "terminal" ? (
                    <Button
                      type="button"
                      variant="secondary"
                      disabled={submitting}
                      onClick={() => void replay(delivery)}
                    >
                      Replay immutable event
                    </Button>
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            ))}
          </DataTable>
        )}
      </Section>

      <Dialog
        open={creatingEndpoint}
        title="Create webhook endpoint"
        onClose={() => {
          if (submitting) return;
          createAttempt.current.abandon();
          setOverlayError(null);
          setCreatingEndpoint(false);
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={() => {
                createAttempt.current.abandon();
                setCreatingEndpoint(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" form="webhook-create-form" variant="primary" busy={submitting}>
              Create pending endpoint
            </Button>
          </>
        }
      >
        <form
          id="webhook-create-form"
          className={styles["form"]}
          onSubmit={(event) => void createEndpoint(event)}
        >
          {overlayError === null ? null : (
            <InlineAlert tone="danger" role="alert">
              {overlayError}
            </InlineAlert>
          )}
          <Field label="HTTPS URL" htmlFor={`webhook-url-${application.id}`}>
            <Input
              id={`webhook-url-${application.id}`}
              name="url"
              type="url"
              required
              disabled={disabled}
              data-owl-initial-focus
            />
          </Field>
          <EventTypeFields prefix={`new-${application.id}`} />
          <Field label="Signing secret" htmlFor={`webhook-secret-${application.id}`}>
            <Input
              id={`webhook-secret-${application.id}`}
              name="secret"
              type="password"
              minLength={32}
              maxLength={128}
              autoComplete="new-password"
              required
              disabled={disabled}
            />
          </Field>
        </form>
      </Dialog>

      <Dialog
        open={editingEndpoint !== null}
        title="Edit webhook subscriptions"
        onClose={() => {
          if (!submitting) {
            setOverlayError(null);
            setEditingEndpointId(null);
          }
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={() => {
                setOverlayError(null);
                setEditingEndpointId(null);
              }}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              form="webhook-subscriptions-form"
              variant="primary"
              busy={submitting}
            >
              Save subscriptions
            </Button>
          </>
        }
      >
        {editingEndpoint === null ? null : (
          <form
            id="webhook-subscriptions-form"
            className={styles["form"]}
            onSubmit={(event) => void updateEndpoint(editingEndpoint, event)}
          >
            {overlayError === null ? null : (
              <InlineAlert tone="danger" role="alert">
                {overlayError}
              </InlineAlert>
            )}
            <EventTypeFields
              prefix={`endpoint-${editingEndpoint.id}`}
              selected={editingEndpoint.subscribed_event_types}
            />
          </form>
        )}
      </Dialog>

      <WebhookRotationDialog
        endpoint={rotatingEndpoint}
        prepared={rotatingEndpoint === null ? undefined : preparedRotations[rotatingEndpoint.id]}
        submitting={submitting}
        error={overlayError}
        onClose={() => {
          rotationAttempt.current.abandon();
          setOverlayError(null);
          setRotatingEndpointId(null);
        }}
        onPrepare={prepareRotation}
        onActivate={activateRotation}
      />
    </>
  );
}

function WebhookRotationDialog({
  endpoint,
  prepared,
  submitting,
  error,
  onClose,
  onPrepare,
  onActivate,
}: {
  readonly endpoint: WebhookEndpoint | null;
  readonly prepared: PreparedRotation | undefined;
  readonly submitting: boolean;
  readonly error: string | null;
  readonly onClose: () => void;
  readonly onPrepare: (endpoint: WebhookEndpoint, secret: string) => Promise<void>;
  readonly onActivate: (
    endpoint: WebhookEndpoint,
    prepared: PreparedRotation,
    overlapSeconds: number,
  ) => Promise<void>;
}) {
  const formId = "webhook-rotation-form";
  return (
    <Dialog
      open={endpoint !== null}
      title="Rotate webhook signing secret"
      onClose={() => {
        if (!submitting) onClose();
      }}
      actions={
        endpoint === null ? undefined : (
          <>
            <Button type="button" variant="quiet" disabled={submitting} onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" form={formId} variant="primary" busy={submitting}>
              {prepared === undefined
                ? "Prepare secret rotation"
                : `Activate generation ${String(prepared.generation)}`}
            </Button>
          </>
        )
      }
    >
      <form
        id={formId}
        onSubmit={(event) => {
          event.preventDefault();
          if (endpoint === null) return;
          const form = event.currentTarget;
          if (!form.checkValidity()) return;
          const fields = new FormData(form);
          if (prepared === undefined) {
            const secret = fieldText(fields, "secret");
            if (secret.length < 32 || secret.length > 128) return;
            const secretInput = form.elements.namedItem("secret");
            if (secretInput instanceof HTMLInputElement) secretInput.value = "";
            void onPrepare(endpoint, secret);
          } else {
            const overlapSeconds = Number(fieldText(fields, "overlap_seconds"));
            if (
              !Number.isInteger(overlapSeconds) ||
              overlapSeconds < 300 ||
              overlapSeconds > 86400
            ) {
              return;
            }
            void onActivate(endpoint, prepared, overlapSeconds);
          }
        }}
      >
        {error === null ? null : (
          <InlineAlert tone="danger" role="alert">
            {error}
          </InlineAlert>
        )}
        {prepared === undefined ? (
          <Field label="Next signing secret" htmlFor="rotation-secret">
            <Input
              key="rotation-secret"
              id="rotation-secret"
              name="secret"
              type="password"
              minLength={32}
              maxLength={128}
              autoComplete="new-password"
              required
              data-owl-initial-focus
            />
          </Field>
        ) : (
          <Field
            label="Overlap window in seconds"
            htmlFor="rotation-overlap"
            description="Keep the prior generation valid only while consumers adopt the new secret."
          >
            <Input
              key="rotation-overlap"
              id="rotation-overlap"
              name="overlap_seconds"
              type="number"
              min={300}
              max={86400}
              defaultValue={3600}
              required
              data-owl-initial-focus
            />
          </Field>
        )}
      </form>
    </Dialog>
  );
}

function EventTypeFields({
  prefix,
  selected = EVENT_TYPES,
}: {
  readonly prefix: string;
  readonly selected?: readonly ApplicationUserEventType[];
}) {
  return (
    <fieldset className={styles["fieldset"]}>
      <legend>Subscribed event types</legend>
      {EVENT_TYPES.map((eventType) => (
        <Checkbox
          key={eventType}
          id={`${prefix}-${eventType}`}
          name="subscribed_event_types"
          value={eventType}
          defaultChecked={selected.includes(eventType)}
        >
          {eventType}
        </Checkbox>
      ))}
    </fieldset>
  );
}

function deliveryError(error: unknown, fallback: string): string {
  return error instanceof ControlRequestError ? error.message : fallback;
}

function fieldText(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}

function selectedEventTypes(fields: FormData): ApplicationUserEventType[] {
  return fields
    .getAll("subscribed_event_types")
    .filter((value): value is string => typeof value === "string")
    .filter((value): value is ApplicationUserEventType =>
      EVENT_TYPES.includes(value as ApplicationUserEventType),
    );
}
