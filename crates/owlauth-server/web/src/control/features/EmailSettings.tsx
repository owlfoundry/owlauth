import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import type { SyntheticEvent } from "react";

import { formatDuration } from "../../shared/compositions/CopyValue";
import { ChevronDownIcon } from "../../shared/icons/Icons";
import {
  DataTable,
  DescriptionList,
  EmptyState,
  LoadingState,
  Section,
} from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Checkbox, Field, Input, Select } from "../../shared/primitives/Field";
import { Dialog, SideSheet } from "../../shared/primitives/Overlay";
import { useControlConfirmation } from "../app/Confirmation";
import { UnsavedChangesGuard } from "../app/UnsavedChangesGuard";
import {
  type CreateSmtpConfigurationRequest,
  type DisposableControlClient,
  type EmailMethodPolicy,
  IdempotencyAttempt,
  type Project,
  type SmtpConfiguration,
  type SmtpTestOperation,
  requireData,
} from "../client";
import styles from "./features.module.css";

interface EmailSettingsProps {
  readonly session: DisposableControlClient;
  readonly project: Project;
  readonly onProjectChanged: () => Promise<void>;
  readonly onError: (error: unknown, refreshConflict?: () => Promise<void>) => Promise<void>;
  readonly setMessage: (message: string | null) => void;
}

export function EmailSettings({
  session,
  project,
  onProjectChanged,
  onError,
  setMessage,
}: EmailSettingsProps) {
  const confirm = useControlConfirmation();
  const [policy, setPolicy] = useState<EmailMethodPolicy | null>(null);
  const [smtp, setSmtp] = useState<SmtpConfiguration[]>([]);
  const [expandedSmtpId, setExpandedSmtpId] = useState<string | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "failed">("loading");
  const [editingPolicy, setEditingPolicy] = useState(false);
  const [creatingSmtp, setCreatingSmtp] = useState(false);
  const [testingSmtp, setTestingSmtp] = useState<SmtpConfiguration | null>(null);
  const [smtpTestOperation, setSmtpTestOperation] = useState<SmtpTestOperation | null>(null);
  const [smtpTestRevision, setSmtpTestRevision] = useState<number | null>(null);
  const [deliveredSmtpTests, setDeliveredSmtpTests] = useState<Record<string, number>>({});
  const [smtpTestPolling, setSmtpTestPolling] = useState(false);
  const [editorError, setEditorError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const createAttempt = useRef(new IdempotencyAttempt());
  const smtpTestAttempts = useRef(new Map<string, IdempotencyAttempt>());
  const smtpTestPollAttempts = useRef(0);

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      const [policyResult, smtpResult] = await Promise.all([
        session.client.GET("/v1/projects/{project_id}/email-method", {
          params: { path: { project_id: project.id } },
          signal: signal ?? null,
        }),
        session.client.GET("/v1/projects/{project_id}/smtp-configurations", {
          params: { path: { project_id: project.id } },
          signal: signal ?? null,
        }),
      ]);
      if (signal?.aborted !== true) {
        setPolicy(requireData(policyResult.data, policyResult.error, policyResult.response));
        const configurations = requireData(
          smtpResult.data,
          smtpResult.error,
          smtpResult.response,
        ).items;
        setSmtp(configurations);
        setExpandedSmtpId((current) =>
          current !== null && configurations.some((item) => item.id === current) ? current : null,
        );
      }
    },
    [project.id, session],
  );

  const load = useCallback(
    async (signal?: AbortSignal) => {
      setLoadState("loading");
      try {
        await refresh(signal);
        if (signal?.aborted !== true) setLoadState("ready");
      } catch (error) {
        if (signal?.aborted !== true) setLoadState("failed");
        throw error;
      }
    },
    [refresh],
  );

  useEffect(() => {
    const attempt = createAttempt.current;
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      void load(controller.signal).catch((error: unknown) => {
        if (!controller.signal.aborted) void onError(error);
      });
    }, 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
      attempt.abandon();
    };
  }, [load, onError]);

  useEffect(() => {
    if (smtpTestOperation === null || isTerminalSmtpTest(smtpTestOperation) || !smtpTestPolling) {
      return;
    }
    if (smtpTestPollAttempts.current >= 20) {
      setSmtpTestPolling(false);
      return;
    }
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      smtpTestPollAttempts.current += 1;
      void session.client
        .GET("/v1/projects/{project_id}/smtp-configurations/{smtp_id}/tests/{operation_id}", {
          params: {
            path: {
              project_id: project.id,
              smtp_id: smtpTestOperation.smtp_configuration_id,
              operation_id: smtpTestOperation.id,
            },
          },
          signal: controller.signal,
        })
        .then((result) => {
          if (controller.signal.aborted) return;
          const operation = requireData(result.data, result.error, result.response);
          setSmtpTestOperation(operation);
          if (operation.status === "delivered" && smtpTestRevision !== null) {
            setDeliveredSmtpTests((current) => ({
              ...current,
              [operation.smtp_configuration_id]: smtpTestRevision,
            }));
          }
          if (isTerminalSmtpTest(operation)) setSmtpTestPolling(false);
        })
        .catch((error: unknown) => {
          if (!controller.signal.aborted) {
            setSmtpTestPolling(false);
            void onError(error);
          }
        });
    }, 500);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [onError, project.id, session, smtpTestOperation, smtpTestPolling, smtpTestRevision]);

  async function updatePolicy(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (policy === null) return;
    const fields = new FormData(event.currentTarget);
    setEditorError(null);
    setSubmitting(true);
    try {
      const result = await session.client.PUT("/v1/projects/{project_id}/email-method", {
        params: { path: { project_id: project.id } },
        body: {
          enabled: fields.get("enabled") === "on",
          otp_enabled: fields.get("otp_enabled") === "on",
          magic_link_enabled: fields.get("magic_link_enabled") === "on",
          otp_digits: Number(field(fields, "otp_digits")),
          otp_validity_seconds: Number(field(fields, "otp_validity_seconds")),
          otp_max_attempts: Number(field(fields, "otp_max_attempts")),
          resend_after_seconds: Number(field(fields, "resend_after_seconds")),
          max_generations: Number(field(fields, "max_generations")),
          magic_validity_seconds: Number(field(fields, "magic_validity_seconds")),
          signup_enabled: fields.get("signup_enabled") === "on",
          transferred_magic_link_enabled: fields.get("transferred_magic_link_enabled") === "on",
          allow_deployment_default: fields.get("allow_deployment_default") === "on",
          expected_policy_revision: policy.policy_revision,
          expected_security_revision: policy.security_revision,
        },
      });
      setPolicy(requireData(result.data, result.error, result.response));
      setEditingPolicy(false);
      setMessage("Email method policy updated.");
    } catch (error) {
      setEditorError("Email method policy could not be updated.");
      await onError(error, async () => {
        await refresh();
        setEditingPolicy(false);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function createSmtp(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    const idempotencyKey = createAttempt.current.begin();
    if (idempotencyKey === null) return;
    let username = field(fields, "username");
    let password = field(fields, "password");
    const body: CreateSmtpConfigurationRequest = {
      host: field(fields, "host"),
      port: Number(field(fields, "port")),
      tls_mode:
        field(fields, "tls_mode") === "starttls_required"
          ? ("starttls_required" as const)
          : ("implicit_tls" as const),
      sender_address: field(fields, "sender_address"),
      sender_name: optional(fields, "sender_name"),
      reply_to: optional(fields, "reply_to"),
      credential: JSON.stringify({ username, password }),
      expected_project_security_revision: project.security_revision,
    };
    form.reset();
    fields.set("username", "");
    fields.set("password", "");
    username = "";
    password = "";
    setEditorError(null);
    setSubmitting(true);
    try {
      const result = await session.client.POST("/v1/projects/{project_id}/smtp-configurations", {
        params: {
          path: { project_id: project.id },
          header: { "Idempotency-Key": idempotencyKey },
        },
        body,
      });
      requireData(result.data, result.error, result.response);
      createAttempt.current.settle();
      await Promise.all([onProjectChanged(), refresh()]);
      setCreatingSmtp(false);
      setMessage("Pending SMTP generation reconciled. Test it before activation.");
    } catch (error) {
      createAttempt.current.settle(error);
      setEditorError("SMTP generation could not be created. Re-enter write-only credentials.");
      await onError(error, async () => {
        createAttempt.current.abandon();
        await Promise.all([onProjectChanged(), refresh()]);
        setCreatingSmtp(false);
      });
    } finally {
      username = "";
      password = "";
      body.credential = "";
      setSubmitting(false);
    }
  }

  async function test(configuration: SmtpConfiguration, recipient: string) {
    const intent = `${configuration.id}\u0000${String(configuration.revision)}\u0000${recipient}`;
    let attempt = smtpTestAttempts.current.get(intent);
    if (attempt === undefined) {
      attempt = new IdempotencyAttempt();
      smtpTestAttempts.current.set(intent, attempt);
    }
    const idempotencyKey = attempt.begin();
    if (idempotencyKey === null) return;
    setEditorError(null);
    setSubmitting(true);
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/smtp-configurations/{smtp_id}/test",
        {
          params: {
            path: { project_id: project.id, smtp_id: configuration.id },
            header: { "Idempotency-Key": idempotencyKey },
          },
          body: { recipient, expected_revision: configuration.revision },
        },
      );
      const operation = requireData(result.data, result.error, result.response);
      attempt.settle();
      smtpTestPollAttempts.current = 0;
      setSmtpTestOperation(operation);
      setSmtpTestRevision(configuration.revision);
      if (operation.status === "delivered") {
        setDeliveredSmtpTests((current) => ({
          ...current,
          [configuration.id]: configuration.revision,
        }));
      }
      setSmtpTestPolling(!isTerminalSmtpTest(operation));
      setTestingSmtp(null);
      setMessage("SMTP test accepted. Its delivery result is being checked.");
    } catch (error) {
      attempt.settle(error);
      setEditorError("The SMTP test could not be confirmed. Review the recipient and retry.");
      await onError(error, async () => {
        await refresh();
        setTestingSmtp(null);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function transition(
    configuration: SmtpConfiguration,
    action: "activate" | "disable" | "compromise",
  ) {
    if (
      action !== "activate" &&
      !(await confirm({
        title: action === "disable" ? "Disable SMTP generation" : "Mark SMTP compromised",
        message: (
          <p>
            Generation {String(configuration.generation)} delivers through {configuration.host} as{" "}
            {configuration.sender_address}.{" "}
            {action === "disable"
              ? "Disabling it removes this generation from future delivery eligibility."
              : "Marking it compromised immediately invalidates its delivery eligibility and may invalidate pending email proofs."}
          </p>
        ),
        actionLabel: action === "disable" ? "Disable generation" : "Mark compromised",
        destructive: true,
      }))
    ) {
      return;
    }
    setSubmitting(true);
    try {
      const path =
        action === "activate"
          ? ("/v1/projects/{project_id}/smtp-configurations/{smtp_id}/activate" as const)
          : action === "disable"
            ? ("/v1/projects/{project_id}/smtp-configurations/{smtp_id}/disable" as const)
            : ("/v1/projects/{project_id}/smtp-configurations/{smtp_id}/compromise" as const);
      const result = await session.client.POST(path, {
        params: { path: { project_id: project.id, smtp_id: configuration.id } },
        body: { expected_revision: configuration.revision },
      });
      requireData(result.data, result.error, result.response);
      await refresh();
      setMessage(`SMTP generation ${action} completed.`);
    } catch (error) {
      await onError(error, refresh);
    } finally {
      setSubmitting(false);
    }
  }

  if (loadState === "loading") return <LoadingState>Loading email configuration</LoadingState>;
  if (loadState === "failed" || policy === null) {
    return (
      <InlineAlert tone="danger" role="alert">
        <p>Email policy or SMTP generations could not be loaded.</p>
        <Button type="button" onClick={() => void load().catch(onError)}>
          Retry email configuration
        </Button>
      </InlineAlert>
    );
  }

  const active = project.status === "active";
  return (
    <>
      <UnsavedChangesGuard
        dirty={editingPolicy || creatingSmtp || testingSmtp !== null}
        submitting={submitting}
        onDiscard={() => {
          createAttempt.current.abandon();
          setEditingPolicy(false);
          setCreatingSmtp(false);
          setTestingSmtp(null);
          setSmtpTestOperation(null);
          setSmtpTestRevision(null);
          setSmtpTestPolling(false);
          setEditorError(null);
        }}
      />
      <Section
        title="Passwordless policy"
        description="Committed proof, signup, and delivery-selection policy."
        action={
          active ? (
            <Button
              type="button"
              onClick={() => {
                setEditorError(null);
                setEditingPolicy(true);
              }}
            >
              Edit policy
            </Button>
          ) : undefined
        }
      >
        <DescriptionList
          items={[
            { term: "Project method", detail: policy.enabled ? "Enabled" : "Disabled" },
            ...(policy.enabled
              ? [
                  {
                    term: "Proof modes",
                    detail:
                      [
                        policy.otp_enabled ? "One-time code" : null,
                        policy.magic_link_enabled ? "Magic link" : null,
                      ]
                        .filter(Boolean)
                        .join(", ") || "None enabled",
                  },
                  ...(policy.otp_enabled
                    ? [
                        {
                          term: "One-time code",
                          detail: `${String(policy.otp_digits)} digits, ${formatDuration(policy.otp_validity_seconds)}, ${String(policy.otp_max_attempts)} attempts`,
                        },
                        {
                          term: "Resend and generation limits",
                          detail: `${formatDuration(policy.resend_after_seconds)} between messages; ${String(policy.max_generations)} active generations`,
                        },
                      ]
                    : []),
                  ...(policy.magic_link_enabled
                    ? [
                        {
                          term: "Magic-link lifetime",
                          detail: formatDuration(policy.magic_validity_seconds),
                        },
                      ]
                    : []),
                  {
                    term: "New email users",
                    detail: policy.signup_enabled ? "Allowed" : "Blocked",
                  },
                  {
                    term: "Transferred browser",
                    detail: policy.transferred_magic_link_enabled ? "Allowed" : "Blocked",
                  },
                  {
                    term: "Deployment-default SMTP",
                    detail: policy.allow_deployment_default ? "Allowed" : "Not allowed",
                  },
                ]
              : []),
          ]}
        />
      </Section>

      {smtpTestOperation === null ? null : (
        <SmtpTestStatus
          operation={smtpTestOperation}
          polling={smtpTestPolling}
          onDismiss={() => {
            setSmtpTestPolling(false);
            setSmtpTestOperation(null);
            setSmtpTestRevision(null);
          }}
          onRefresh={() => {
            smtpTestPollAttempts.current = 0;
            setSmtpTestPolling(true);
          }}
        />
      )}

      <Section
        title="SMTP generations"
        description="Credentials are write-only. Create, test, and activate one reviewed generation at a time."
        action={
          active ? (
            <Button
              type="button"
              variant="primary"
              onClick={() => {
                setEditorError(null);
                setCreatingSmtp(true);
              }}
            >
              Create SMTP generation
            </Button>
          ) : undefined
        }
      >
        {smtp.length === 0 ? (
          <EmptyState
            level={3}
            title="No SMTP generations"
            description="Create a pending generation, test its destination, then activate it."
          />
        ) : (
          <DataTable
            caption="Project SMTP generations"
            headings={["Generation", "Delivery", "Status", "Actions", "Details"]}
          >
            {smtp.map((configuration) => (
              <Fragment key={configuration.id}>
                <tr>
                  <td>{String(configuration.generation)}</td>
                  <td>
                    <span className={styles["machineValue"]}>
                      {configuration.host}:{String(configuration.port)}
                    </span>
                    <span>{configuration.sender_address}</span>
                  </td>
                  <td>
                    <StatusBadge status={configuration.status} />
                  </td>
                  <td>
                    <div className={styles["actions"]}>
                      <Button
                        type="button"
                        variant="quiet"
                        disabled={submitting}
                        onClick={() => {
                          setEditorError(null);
                          setTestingSmtp(configuration);
                        }}
                      >
                        Send test
                      </Button>
                      {configuration.status === "pending" ? (
                        <>
                          <Button
                            type="button"
                            disabled={submitting}
                            onClick={() => void transition(configuration, "activate")}
                          >
                            Activate
                          </Button>
                          <span>
                            {deliveredSmtpTests[configuration.id] === configuration.revision
                              ? "Delivered test observed for this revision; the server revalidates it on activation."
                              : "A delivered test for this exact revision is required. The server validates durable evidence, including tests completed in another Console session."}
                          </span>
                        </>
                      ) : null}
                      {!(["disabled", "compromised", "retired"] as string[]).includes(
                        configuration.status,
                      ) ? (
                        <Button
                          type="button"
                          variant="quiet"
                          disabled={submitting}
                          onClick={() => void transition(configuration, "disable")}
                        >
                          Disable
                        </Button>
                      ) : null}
                      {!(["compromised", "retired"] as string[]).includes(configuration.status) ? (
                        <Button
                          type="button"
                          variant="danger"
                          disabled={submitting}
                          onClick={() => void transition(configuration, "compromise")}
                        >
                          Mark compromised
                        </Button>
                      ) : null}
                    </div>
                  </td>
                  <td>
                    <Button
                      type="button"
                      variant="quiet"
                      iconOnly
                      aria-label={`${expandedSmtpId === configuration.id ? "Collapse" : "Expand"} SMTP generation ${String(configuration.generation)} details`}
                      aria-expanded={expandedSmtpId === configuration.id}
                      aria-controls={`smtp-generation-${configuration.id}`}
                      onClick={() => {
                        setExpandedSmtpId((current) =>
                          current === configuration.id ? null : configuration.id,
                        );
                      }}
                    >
                      <ChevronDownIcon
                        className={
                          expandedSmtpId === configuration.id
                            ? styles["disclosureIconExpanded"]
                            : styles["disclosureIcon"]
                        }
                      />
                    </Button>
                  </td>
                </tr>
                {expandedSmtpId === configuration.id ? (
                  <tr id={`smtp-generation-${configuration.id}`}>
                    <td colSpan={5} className={styles["expandedDetailCell"]}>
                      <DescriptionList
                        items={[
                          {
                            term: "Hostname",
                            detail: `${configuration.host}:${String(configuration.port)}`,
                          },
                          {
                            term: "TLS mode",
                            detail:
                              configuration.tls_mode === "implicit_tls"
                                ? "Implicit TLS"
                                : "STARTTLS required",
                          },
                          {
                            term: "Sender",
                            detail:
                              configuration.sender_name === null ||
                              configuration.sender_name === undefined
                                ? configuration.sender_address
                                : `${configuration.sender_name} <${configuration.sender_address}>`,
                          },
                          { term: "Reply-to", detail: configuration.reply_to ?? "Not configured" },
                          {
                            term: "Safe fingerprint",
                            detail: <code>{configuration.safe_fingerprint}</code>,
                          },
                          { term: "Revision", detail: String(configuration.revision) },
                        ]}
                      />
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            ))}
          </DataTable>
        )}
      </Section>

      <SideSheet
        open={editingPolicy}
        side="right"
        closeLabel="Close passwordless policy editor"
        title="Edit passwordless policy"
        onClose={() => {
          if (!submitting) setEditingPolicy(false);
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={() => {
                setEditingPolicy(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" form="email-policy-form" variant="primary" busy={submitting}>
              Save policy
            </Button>
          </>
        }
      >
        <form
          id="email-policy-form"
          className={styles["form"]}
          onSubmit={(event) => void updatePolicy(event)}
        >
          {editorError === null ? null : (
            <InlineAlert tone="danger" role="alert">
              {editorError}
            </InlineAlert>
          )}
          <Checkbox name="enabled" defaultChecked={policy.enabled} data-owl-initial-focus>
            Enable Project email method
          </Checkbox>
          <Checkbox name="otp_enabled" defaultChecked={policy.otp_enabled}>
            One-time codes
          </Checkbox>
          <Checkbox name="magic_link_enabled" defaultChecked={policy.magic_link_enabled}>
            Magic links
          </Checkbox>
          <Field label="OTP digits" htmlFor="otp-digits">
            <Input
              id="otp-digits"
              name="otp_digits"
              type="number"
              min={6}
              max={10}
              defaultValue={policy.otp_digits}
              required
            />
          </Field>
          <Field label="OTP lifetime seconds" htmlFor="otp-validity">
            <Input
              id="otp-validity"
              name="otp_validity_seconds"
              type="number"
              min={30}
              max={600}
              defaultValue={policy.otp_validity_seconds}
              required
            />
          </Field>
          <Field label="OTP attempts" htmlFor="otp-attempts">
            <Input
              id="otp-attempts"
              name="otp_max_attempts"
              type="number"
              min={1}
              max={5}
              defaultValue={policy.otp_max_attempts}
              required
            />
          </Field>
          <Field label="Resend delay seconds" htmlFor="resend-delay">
            <Input
              id="resend-delay"
              name="resend_after_seconds"
              type="number"
              min={30}
              max={600}
              defaultValue={policy.resend_after_seconds}
              required
            />
          </Field>
          <Field label="Maximum generations" htmlFor="max-generations">
            <Input
              id="max-generations"
              name="max_generations"
              type="number"
              min={1}
              max={5}
              defaultValue={policy.max_generations}
              required
            />
          </Field>
          <Field label="Magic-link lifetime seconds" htmlFor="magic-validity">
            <Input
              id="magic-validity"
              name="magic_validity_seconds"
              type="number"
              min={30}
              max={600}
              defaultValue={policy.magic_validity_seconds}
              required
            />
          </Field>
          <Checkbox name="signup_enabled" defaultChecked={policy.signup_enabled}>
            Allow new email users
          </Checkbox>
          <Checkbox
            name="transferred_magic_link_enabled"
            defaultChecked={policy.transferred_magic_link_enabled}
          >
            Allow transferred-browser confirmation
          </Checkbox>
          <Checkbox
            name="allow_deployment_default"
            defaultChecked={policy.allow_deployment_default}
          >
            Allow deployment-default SMTP
          </Checkbox>
        </form>
      </SideSheet>

      <Dialog
        open={creatingSmtp}
        title="Create SMTP generation"
        onClose={() => {
          if (submitting) return;
          createAttempt.current.abandon();
          setCreatingSmtp(false);
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={() => {
                createAttempt.current.abandon();
                setCreatingSmtp(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" form="smtp-create-form" variant="primary" busy={submitting}>
              Create pending generation
            </Button>
          </>
        }
      >
        <form
          id="smtp-create-form"
          className={styles["form"]}
          onSubmit={(event) => void createSmtp(event)}
        >
          {editorError === null ? null : (
            <InlineAlert tone="danger" role="alert">
              {editorError}
            </InlineAlert>
          )}
          <Field label="Hostname" htmlFor="smtp-host">
            <Input id="smtp-host" name="host" required maxLength={253} data-owl-initial-focus />
          </Field>
          <Field label="Port" htmlFor="smtp-port">
            <Input
              id="smtp-port"
              name="port"
              type="number"
              min={1}
              max={65535}
              defaultValue={465}
              required
            />
          </Field>
          <Field label="TLS mode" htmlFor="smtp-tls">
            <Select id="smtp-tls" name="tls_mode" defaultValue="implicit_tls">
              <option value="implicit_tls">Implicit TLS</option>
              <option value="starttls_required">STARTTLS required</option>
            </Select>
          </Field>
          <Field label="Sender address" htmlFor="smtp-sender">
            <Input id="smtp-sender" name="sender_address" type="email" required maxLength={254} />
          </Field>
          <Field label="Sender name" htmlFor="smtp-sender-name" optional>
            <Input id="smtp-sender-name" name="sender_name" maxLength={128} />
          </Field>
          <Field label="Reply-to" htmlFor="smtp-reply" optional>
            <Input id="smtp-reply" name="reply_to" type="email" maxLength={254} />
          </Field>
          <Field label="SMTP username" htmlFor="smtp-username">
            <Input id="smtp-username" name="username" autoComplete="off" required maxLength={256} />
          </Field>
          <Field label="SMTP password" htmlFor="smtp-password">
            <Input
              id="smtp-password"
              name="password"
              type="password"
              autoComplete="new-password"
              required
              maxLength={2048}
            />
          </Field>
        </form>
      </Dialog>

      <SmtpTestDialog
        configuration={testingSmtp}
        submitting={submitting}
        error={editorError}
        onClose={() => {
          setTestingSmtp(null);
        }}
        onTest={test}
      />
    </>
  );
}

function SmtpTestStatus({
  operation,
  polling,
  onDismiss,
  onRefresh,
}: {
  readonly operation: SmtpTestOperation;
  readonly polling: boolean;
  readonly onDismiss: () => void;
  readonly onRefresh: () => void;
}) {
  const terminal = isTerminalSmtpTest(operation);
  const tone =
    operation.status === "delivered"
      ? ("success" as const)
      : operation.status === "failed"
        ? ("danger" as const)
        : operation.status === "ambiguous"
          ? ("warning" as const)
          : ("info" as const);
  return (
    <InlineAlert tone={tone} role={operation.status === "failed" ? "alert" : "status"}>
      <p>
        <strong>SMTP test status: {operation.status}</strong>
      </p>
      <p>
        {operation.status === "delivered"
          ? "The advisory test message was delivered. Activation remains a separate explicit action."
          : operation.status === "failed"
            ? "The advisory test failed. Review the SMTP configuration before retrying."
            : operation.status === "ambiguous"
              ? "Delivery could not be confirmed. Review the SMTP configuration before activation."
              : polling
                ? "The bounded test is still running. OwlAuth is checking its safe status."
                : "The test is still pending. Refresh its exact operation when ready."}
      </p>
      <div className={styles["actions"]}>
        {!terminal && !polling ? (
          <Button type="button" variant="secondary" onClick={onRefresh}>
            Refresh test status
          </Button>
        ) : null}
        <Button type="button" variant="quiet" onClick={onDismiss}>
          Dismiss test status
        </Button>
      </div>
    </InlineAlert>
  );
}

function isTerminalSmtpTest(operation: SmtpTestOperation): boolean {
  return ["delivered", "failed", "ambiguous"].includes(operation.status);
}

function SmtpTestDialog({
  configuration,
  submitting,
  error,
  onClose,
  onTest,
}: {
  readonly configuration: SmtpConfiguration | null;
  readonly submitting: boolean;
  readonly error: string | null;
  readonly onClose: () => void;
  readonly onTest: (configuration: SmtpConfiguration, recipient: string) => Promise<void>;
}) {
  const formId = "smtp-test-form";
  return (
    <Dialog
      open={configuration !== null}
      title="Send SMTP test"
      onClose={() => {
        if (!submitting) onClose();
      }}
      actions={
        <>
          <Button type="button" variant="quiet" disabled={submitting} onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form={formId} variant="primary" busy={submitting}>
            Send test
          </Button>
        </>
      }
    >
      <form
        id={formId}
        onSubmit={(event) => {
          event.preventDefault();
          if (!event.currentTarget.checkValidity()) return;
          const recipient = field(new FormData(event.currentTarget), "recipient");
          if (configuration !== null) void onTest(configuration, recipient);
        }}
      >
        {error === null ? null : (
          <InlineAlert tone="danger" role="alert">
            {error}
          </InlineAlert>
        )}
        <Field label="Test recipient" htmlFor="smtp-test-recipient">
          <Input
            id="smtp-test-recipient"
            name="recipient"
            type="email"
            required
            maxLength={254}
            data-owl-initial-focus
          />
        </Field>
      </form>
    </Dialog>
  );
}

function field(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}

function optional(fields: FormData, name: string): string | null {
  const value = field(fields, name).trim();
  return value === "" ? null : value;
}
