import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { useState } from "react";
import { createMemoryRouter, RouterProvider } from "react-router";

import {
  ControlRequestError,
  type DisposableControlClient,
  type EmailMethodPolicy,
  type Project,
  type SmtpConfiguration,
  type SmtpTestOperation,
} from "../client";
import { ControlConfirmationProvider } from "../app/Confirmation";
import { EmailSettings } from "./EmailSettings";

const initialProject: Project = {
  id: "11111111-1111-4111-8111-111111111111",
  public_id: "prj_public123",
  display_name: "Production",
  belongs_to: null,
  status: "active",
  metadata_revision: 1,
  security_revision: 7,
};

const smtpConfiguration: SmtpConfiguration = {
  id: "33333333-3333-4333-8333-333333333333",
  project_id: initialProject.id,
  generation: 1,
  host: "smtp.example.com",
  port: 465,
  tls_mode: "implicit_tls",
  sender_address: "sender@example.com",
  sender_name: null,
  reply_to: null,
  status: "pending",
  safe_fingerprint: "sha256:test",
  revision: 1,
  security_eligibility_revision: 1,
};

const policy: EmailMethodPolicy = {
  project_id: initialProject.id,
  enabled: true,
  otp_enabled: true,
  magic_link_enabled: true,
  otp_digits: 6,
  otp_validity_seconds: 300,
  otp_max_attempts: 3,
  resend_after_seconds: 30,
  max_generations: 3,
  magic_validity_seconds: 300,
  signup_enabled: true,
  transferred_magic_link_enabled: false,
  allow_deployment_default: false,
  policy_revision: 2,
  security_revision: 3,
};

function successful<T>(data: T) {
  return { data, error: undefined, response: Response.json(data) };
}

async function openSmtpForm() {
  fireEvent.click(await screen.findByRole("button", { name: "Create SMTP generation" }));
  await screen.findByRole("dialog", { name: "Create SMTP generation" });
}

function fillSmtpForm(suffix: string) {
  fireEvent.change(screen.getByLabelText("Hostname"), {
    target: { value: `smtp-${suffix}.example` },
  });
  fireEvent.change(screen.getByLabelText("Sender address"), {
    target: { value: `sender-${suffix}@example.com` },
  });
  fireEvent.change(screen.getByLabelText("SMTP username"), {
    target: { value: `operator-${suffix}` },
  });
  fireEvent.change(screen.getByLabelText("SMTP password"), {
    target: { value: `credential-${suffix}` },
  });
}

function renderHarness(options?: {
  failSmtp?: boolean;
  conflictPolicy?: boolean;
  smtp?: SmtpConfiguration;
}) {
  let authoritativeProject = initialProject;
  let authoritativePolicy = policy;
  const put = vi.fn((path: string, request: { body: { enabled: boolean } }) => {
    if (path.endsWith("/email-method") && options?.conflictPolicy === true) {
      authoritativePolicy = {
        ...authoritativePolicy,
        otp_digits: 8,
        policy_revision: authoritativePolicy.policy_revision + 1,
        security_revision: authoritativePolicy.security_revision + 1,
      };
      return Promise.reject(new ControlRequestError(undefined, 409));
    }
    throw new Error(`unexpected PUT ${path} ${String(request.body.enabled)}`);
  });
  const post = vi.fn((path: string, request: { body: Record<string, unknown> }) => {
    if (path.endsWith("/test")) {
      const operation: SmtpTestOperation = {
        id: "44444444-4444-4444-8444-444444444444",
        project_id: initialProject.id,
        smtp_configuration_id: smtpConfiguration.id,
        status: "pending",
        outcome: null,
        created_at: "2026-08-07T00:00:00Z",
        completed_at: null,
      };
      return Promise.resolve(successful(operation));
    }
    if (!path.endsWith("/smtp-configurations")) throw new Error(`unexpected POST ${path}`);
    if (options?.failSmtp === true) return Promise.reject(new Error("dispatch failed"));
    if (
      request.body["expected_project_security_revision"] !== authoritativeProject.security_revision
    ) {
      return Promise.reject(new Error("stale Project revision"));
    }
    authoritativeProject = {
      ...authoritativeProject,
      security_revision: authoritativeProject.security_revision + 1,
    };
    return Promise.resolve(successful({ id: crypto.randomUUID() }));
  });
  let smtpTestReads = 0;
  const get = vi.fn((path: string) => {
    if (path.endsWith("/email-method")) {
      return Promise.resolve(successful(authoritativePolicy));
    }
    if (path.endsWith("/smtp-configurations")) {
      return Promise.resolve(
        successful({ items: options?.smtp === undefined ? [] : [options.smtp] }),
      );
    }
    if (path.includes("/tests/")) {
      smtpTestReads += 1;
      const operation: SmtpTestOperation = {
        id: "44444444-4444-4444-8444-444444444444",
        project_id: initialProject.id,
        smtp_configuration_id: smtpConfiguration.id,
        status: smtpTestReads > 1 ? "delivered" : "submitting",
        outcome: smtpTestReads > 1 ? "delivered" : null,
        created_at: "2026-08-07T00:00:00Z",
        completed_at: smtpTestReads > 1 ? "2026-08-07T00:00:01Z" : null,
      };
      return Promise.resolve(successful(operation));
    }
    throw new Error(`unexpected GET ${path}`);
  });
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

  function Harness() {
    const [project, setProject] = useState(initialProject);
    return (
      <EmailSettings
        session={session}
        project={project}
        onProjectChanged={() => {
          setProject(authoritativeProject);
          return Promise.resolve();
        }}
        onError={onError}
        setMessage={setMessage}
      />
    );
  }

  const router = createMemoryRouter([
    {
      path: "*",
      element: (
        <ControlConfirmationProvider>
          <Harness />
        </ControlConfirmationProvider>
      ),
    },
  ]);
  render(<RouterProvider router={router} />);
  return { onError, post, put, setMessage };
}

describe("Email Console owner revisions", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("expands SMTP details from the table row", async () => {
    renderHarness({ smtp: smtpConfiguration });

    const disclosure = await screen.findByRole("button", {
      name: "Expand SMTP generation 1 details",
    });
    expect(screen.queryByText("sha256:test")).not.toBeInTheDocument();
    fireEvent.click(disclosure);

    expect(screen.getByText("sha256:test")).toBeVisible();
    expect(disclosure).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(disclosure);
    expect(screen.queryByText("sha256:test")).not.toBeInTheDocument();
  });

  it("uses the refreshed Project revision for a replacement generation without a reload", async () => {
    const { post, setMessage } = renderHarness();

    await openSmtpForm();
    fillSmtpForm("first");
    fireEvent.click(screen.getByRole("button", { name: "Create pending generation" }));
    await waitFor(() => {
      expect(setMessage).toHaveBeenCalledTimes(1);
    });
    await openSmtpForm();
    fillSmtpForm("replacement");
    fireEvent.click(screen.getByRole("button", { name: "Create pending generation" }));
    await waitFor(() => {
      expect(post).toHaveBeenCalledTimes(2);
    });

    expect(post.mock.calls[0]?.[1]).toMatchObject({
      body: { expected_project_security_revision: 7 },
    });
    expect(post.mock.calls[0]?.[1].body).not.toHaveProperty("explicitly_allowed_private_ips");
    expect(post.mock.calls[1]?.[1]).toMatchObject({
      body: { expected_project_security_revision: 8 },
    });
    expect(post.mock.calls[1]?.[1].body).not.toHaveProperty("explicitly_allowed_private_ips");
  });

  it("reports observed SMTP evidence without overriding the durable server gate", async () => {
    const { post, setMessage } = renderHarness({ smtp: smtpConfiguration });

    expect(await screen.findByRole("button", { name: "Activate" })).toBeEnabled();
    expect(screen.getByText(/server validates durable evidence/u)).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    fireEvent.change(screen.getByLabelText("Test recipient"), {
      target: { value: "recipient@example.com" },
    });
    const dialog = screen.getByRole("dialog", { name: "Send SMTP test" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Send test" }));

    await waitFor(() => {
      expect(setMessage).toHaveBeenCalledWith(
        "SMTP test accepted. Its delivery result is being checked.",
      );
    });
    expect(post).toHaveBeenCalledWith(
      "/v1/projects/{project_id}/smtp-configurations/{smtp_id}/test",
      expect.objectContaining({
        body: { recipient: "recipient@example.com", expected_revision: 1 },
      }),
    );
    expect(await screen.findByText("SMTP test status: pending")).toBeVisible();
    expect(
      await screen.findByText("SMTP test status: delivered", {}, { timeout: 3000 }),
    ).toBeVisible();
    expect(screen.getByText(/Activation remains a separate explicit action/u)).toBeVisible();
    expect(screen.getByRole("button", { name: "Activate" })).toBeEnabled();
    expect(screen.getByText(/Delivered test observed for this revision/u)).toBeVisible();
  });

  it("closes a stale policy draft and remounts committed state after a conflict", async () => {
    const { put } = renderHarness({ conflictPolicy: true });
    fireEvent.click(await screen.findByRole("button", { name: "Edit policy" }));
    const digits = screen.getByLabelText("OTP digits");
    fireEvent.change(digits, { target: { value: "9" } });
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));

    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Edit passwordless policy" })).toBeNull();
    });
    fireEvent.click(screen.getByRole("button", { name: "Edit policy" }));
    expect(screen.getByLabelText("OTP digits")).toHaveValue(8);
    expect(put).toHaveBeenCalledTimes(1);
  });

  it("discards write-only credential input when dispatch fails", async () => {
    const { onError } = renderHarness({ failSmtp: true });
    await openSmtpForm();
    fillSmtpForm("retry");

    fireEvent.click(screen.getByRole("button", { name: "Create pending generation" }));
    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: "dispatch failed" }),
        expect.any(Function),
      );
    });

    expect(screen.getByLabelText<HTMLInputElement>("SMTP username").value).toBe("");
    expect(screen.getByLabelText<HTMLInputElement>("SMTP password").value).toBe("");
  });
});
