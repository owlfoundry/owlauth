import { useCallback, useRef, useState } from "react";
import type { SyntheticEvent } from "react";

import styles from "./app.module.css";
import {
  type Application,
  type DisposableControlClient,
  type EmailMethodPolicy,
  IdempotencyAttempt,
  type Project,
  type SmtpConfiguration,
  requireData,
} from "./client";

interface EmailPanelProps {
  readonly session: DisposableControlClient;
  readonly project: Project;
  readonly applications: Application[];
  readonly onApplicationsChanged: () => Promise<void>;
  readonly onProjectChanged: () => Promise<void>;
  readonly onError: (error: unknown) => Promise<void>;
  readonly setMessage: (message: string | null) => void;
}

export function EmailPanel({
  session,
  project,
  applications,
  onApplicationsChanged,
  onProjectChanged,
  onError,
  setMessage,
}: EmailPanelProps) {
  const [policy, setPolicy] = useState<EmailMethodPolicy | null>(null);
  const [smtp, setSmtp] = useState<SmtpConfiguration[]>([]);
  const createAttempt = useRef(new IdempotencyAttempt());
  const smtpTestAttempts = useRef(new Map<string, IdempotencyAttempt>());

  const refresh = useCallback(async () => {
    const [policyResult, smtpResult] = await Promise.all([
      session.client.GET("/v1/projects/{project_id}/email-method", {
        params: { path: { project_id: project.id } },
      }),
      session.client.GET("/v1/projects/{project_id}/smtp-configurations", {
        params: { path: { project_id: project.id } },
      }),
    ]);
    setPolicy(requireData(policyResult.data, policyResult.error, policyResult.response));
    setSmtp(requireData(smtpResult.data, smtpResult.error, smtpResult.response).items);
  }, [project.id, session]);

  async function updatePolicy(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (policy === null) return;
    const fields = new FormData(event.currentTarget);
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
      setMessage("Email method policy updated.");
    } catch (error) {
      await onError(error);
    }
  }

  async function assign(application: Application, enabled: boolean) {
    try {
      const result = await session.client.PUT(
        "/v1/projects/{project_id}/applications/{application_id}/email-method",
        {
          params: { path: { project_id: project.id, application_id: application.id } },
          body: {
            enabled,
            expected_application_security_revision: application.security_revision,
          },
        },
      );
      setPolicy(requireData(result.data, result.error, result.response));
      await onApplicationsChanged();
      setMessage(
        `Email method ${enabled ? "assigned to" : "removed from"} ${application.display_name}.`,
      );
    } catch (error) {
      await onError(error);
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
    const body = {
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
      explicitly_allowed_private_ips: [],
      expected_project_security_revision: project.security_revision,
    };
    // Credential controls are uncontrolled. Keep operator input present until dispatch has
    // succeeded; failed requests must not destroy the only copy needed for a safe retry.
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
      form.reset();
      await onProjectChanged();
      await refresh();
      setMessage("Pending SMTP generation reconciled. Test it before activation.");
    } catch (error) {
      createAttempt.current.settle(error);
      await onError(error);
    } finally {
      username = "";
      password = "";
      body.credential = "";
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
      requireData(result.data, result.error, result.response);
      attempt.settle();
      setMessage("Bounded SMTP test accepted.");
    } catch (error) {
      attempt.settle(error);
      await onError(error);
    }
  }

  async function transition(
    configuration: SmtpConfiguration,
    action: "activate" | "disable" | "compromise",
  ) {
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
      await onError(error);
    }
  }

  return (
    <section aria-labelledby="email-method-heading">
      <h3 id="email-method-heading">Passwordless email</h3>
      {policy === null ? (
        <button type="button" onClick={() => void refresh().catch(onError)}>
          Load email settings
        </button>
      ) : (
        <form className={styles["form"]} onSubmit={(event) => void updatePolicy(event)}>
          <p>
            Policy revision {String(policy.policy_revision)}; security revision{" "}
            {String(policy.security_revision)}
          </p>
          <label>
            <input name="enabled" type="checkbox" defaultChecked={policy.enabled} /> Enable Project
            email method
          </label>
          <label>
            <input name="otp_enabled" type="checkbox" defaultChecked={policy.otp_enabled} />{" "}
            One-time codes
          </label>
          <label>
            <input
              name="magic_link_enabled"
              type="checkbox"
              defaultChecked={policy.magic_link_enabled}
            />{" "}
            Magic links
          </label>
          <label>
            OTP digits
            <input
              name="otp_digits"
              type="number"
              min={6}
              max={10}
              defaultValue={policy.otp_digits}
            />
          </label>
          <label>
            OTP lifetime seconds
            <input
              name="otp_validity_seconds"
              type="number"
              min={30}
              max={600}
              defaultValue={policy.otp_validity_seconds}
            />
          </label>
          <label>
            OTP attempts
            <input
              name="otp_max_attempts"
              type="number"
              min={1}
              max={5}
              defaultValue={policy.otp_max_attempts}
            />
          </label>
          <label>
            Resend delay seconds
            <input
              name="resend_after_seconds"
              type="number"
              min={30}
              max={600}
              defaultValue={policy.resend_after_seconds}
            />
          </label>
          <label>
            Maximum generations
            <input
              name="max_generations"
              type="number"
              min={1}
              max={5}
              defaultValue={policy.max_generations}
            />
          </label>
          <label>
            Magic-link lifetime seconds
            <input
              name="magic_validity_seconds"
              type="number"
              min={30}
              max={600}
              defaultValue={policy.magic_validity_seconds}
            />
          </label>
          <label>
            <input name="signup_enabled" type="checkbox" defaultChecked={policy.signup_enabled} />{" "}
            Allow new email users
          </label>
          <label>
            <input
              name="transferred_magic_link_enabled"
              type="checkbox"
              defaultChecked={policy.transferred_magic_link_enabled}
            />{" "}
            Allow transferred-browser confirmation
          </label>
          <label>
            <input
              name="allow_deployment_default"
              type="checkbox"
              defaultChecked={policy.allow_deployment_default}
            />{" "}
            Allow deployment-default SMTP
          </label>
          <button type="submit">Update email policy</button>
        </form>
      )}
      <h4>Application assignments</h4>
      <ul className={styles["list"]}>
        {applications.map((application) => (
          <li key={application.id}>
            <span>{application.display_name}</span>{" "}
            <button type="button" onClick={() => void assign(application, true)}>
              Assign
            </button>{" "}
            <button type="button" onClick={() => void assign(application, false)}>
              Remove
            </button>
          </li>
        ))}
      </ul>
      <form className={styles["form"]} onSubmit={(event) => void createSmtp(event)}>
        <h4>Create SMTP generation</h4>
        <label>
          Hostname
          <input name="host" required maxLength={253} />
        </label>
        <label>
          Port
          <input name="port" type="number" min={1} max={65535} defaultValue={465} required />
        </label>
        <label>
          TLS mode
          <select name="tls_mode" defaultValue="implicit_tls">
            <option value="implicit_tls">Implicit TLS</option>
            <option value="starttls_required">STARTTLS required</option>
          </select>
        </label>
        <label>
          Sender address
          <input name="sender_address" type="email" required maxLength={254} />
        </label>
        <label>
          Sender name
          <input name="sender_name" maxLength={128} />
        </label>
        <label>
          Reply-to
          <input name="reply_to" type="email" maxLength={254} />
        </label>
        <label>
          SMTP username
          <input name="username" autoComplete="off" required maxLength={256} />
        </label>
        <label>
          SMTP password
          <input
            name="password"
            type="password"
            autoComplete="new-password"
            required
            maxLength={2048}
          />
        </label>
        <button type="submit">Create pending generation</button>
      </form>
      <h4>SMTP generations</h4>
      {smtp.length === 0 ? (
        <p>No SMTP generations.</p>
      ) : (
        <ul className={styles["list"]}>
          {smtp.map((configuration) => (
            <li key={configuration.id}>
              <p>
                Generation {String(configuration.generation)} — {configuration.status};{" "}
                {configuration.host}:{String(configuration.port)}; fingerprint{" "}
                <code>{configuration.safe_fingerprint}</code>
              </p>
              <TestRecipient configuration={configuration} onTest={test} />
              {configuration.status === "pending" ? (
                <button type="button" onClick={() => void transition(configuration, "activate")}>
                  Activate
                </button>
              ) : null}{" "}
              {!(["disabled", "compromised", "retired"] as string[]).includes(
                configuration.status,
              ) ? (
                <button type="button" onClick={() => void transition(configuration, "disable")}>
                  Disable
                </button>
              ) : null}{" "}
              {!(["compromised", "retired"] as string[]).includes(configuration.status) ? (
                <button
                  type="button"
                  className={styles["danger"]}
                  onClick={() => void transition(configuration, "compromise")}
                >
                  Mark compromised
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function TestRecipient({
  configuration,
  onTest,
}: {
  readonly configuration: SmtpConfiguration;
  readonly onTest: (configuration: SmtpConfiguration, recipient: string) => Promise<void>;
}) {
  const input = useRef<HTMLInputElement | null>(null);
  return (
    <span>
      <label>
        Test recipient
        <input ref={input} type="email" maxLength={254} />
      </label>
      <button
        type="button"
        onClick={() => {
          const recipient = input.current?.value ?? "";
          if (input.current !== null) input.current.value = "";
          void onTest(configuration, recipient);
        }}
      >
        Send test
      </button>
    </span>
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
