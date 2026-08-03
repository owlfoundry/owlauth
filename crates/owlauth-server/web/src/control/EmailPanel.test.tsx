import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";

import {
  type Application,
  type DisposableControlClient,
  type EmailMethodPolicy,
  type Project,
} from "./client";
import { EmailPanel } from "./EmailPanel";

const initialProject: Project = {
  id: "11111111-1111-4111-8111-111111111111",
  public_id: "prj_public123",
  display_name: "Production",
  belongs_to: null,
  status: "active",
  metadata_revision: 1,
  security_revision: 7,
};

const initialApplication: Application = {
  id: "22222222-2222-4222-8222-222222222222",
  project_id: initialProject.id,
  public_id: "app_public123",
  display_name: "Native client",
  application_type: "native",
  configuration: {
    allowed_origins: [],
    publishable_keys: ["pk_test"],
    redirect_uris: ["com.example.app:/callback"],
  },
  status: "active",
  metadata_revision: 1,
  security_revision: 11,
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

function renderHarness(options?: { failSmtp?: boolean }) {
  let authoritativeApplication = initialApplication;
  let authoritativeProject = initialProject;
  const put = vi.fn((path: string, request: { body: { enabled: boolean } }) => {
    if (path.includes("/applications/")) {
      authoritativeApplication = {
        ...authoritativeApplication,
        security_revision: authoritativeApplication.security_revision + 1,
      };
      return Promise.resolve(successful(policy));
    }
    throw new Error(`unexpected PUT ${path} ${String(request.body.enabled)}`);
  });
  const post = vi.fn(
    (path: string, request: { body: { expected_project_security_revision?: number } }) => {
      if (!path.endsWith("/smtp-configurations")) throw new Error(`unexpected POST ${path}`);
      if (options?.failSmtp === true) return Promise.reject(new Error("dispatch failed"));
      if (
        request.body.expected_project_security_revision !== authoritativeProject.security_revision
      ) {
        return Promise.reject(new Error("stale Project revision"));
      }
      authoritativeProject = {
        ...authoritativeProject,
        security_revision: authoritativeProject.security_revision + 1,
      };
      return Promise.resolve(successful({ id: crypto.randomUUID() }));
    },
  );
  const get = vi.fn((path: string) => {
    if (path.endsWith("/email-method")) return Promise.resolve(successful(policy));
    if (path.endsWith("/smtp-configurations")) {
      return Promise.resolve(successful({ items: [] }));
    }
    throw new Error(`unexpected GET ${path}`);
  });
  const onError = vi.fn(() => Promise.resolve());
  const setMessage = vi.fn();
  const session = {
    client: { GET: get, PUT: put, POST: post },
    dispose: vi.fn(),
  } as unknown as DisposableControlClient;

  function Harness() {
    const [project, setProject] = useState(initialProject);
    const [applications, setApplications] = useState([initialApplication]);
    return (
      <EmailPanel
        session={session}
        project={project}
        applications={applications}
        onApplicationsChanged={() => {
          setApplications([authoritativeApplication]);
          return Promise.resolve();
        }}
        onProjectChanged={() => {
          setProject(authoritativeProject);
          return Promise.resolve();
        }}
        onError={onError}
        setMessage={setMessage}
      />
    );
  }

  render(<Harness />);
  return { onError, post, put, setMessage };
}

describe("Email Console owner revisions", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("uses the refreshed Application revision for assign then remove without a reload", async () => {
    const { put, setMessage } = renderHarness();

    fireEvent.click(screen.getByRole("button", { name: "Assign" }));
    await waitFor(() => {
      expect(setMessage).toHaveBeenCalledWith("Email method assigned to Native client.");
    });
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    await waitFor(() => {
      expect(put).toHaveBeenCalledTimes(2);
    });

    expect(put.mock.calls[0]?.[1]).toMatchObject({
      body: { enabled: true, expected_application_security_revision: 11 },
    });
    expect(put.mock.calls[1]?.[1]).toMatchObject({
      body: { enabled: false, expected_application_security_revision: 12 },
    });
  });

  it("uses the refreshed Project revision for a replacement generation without a reload", async () => {
    const { post, setMessage } = renderHarness();

    fillSmtpForm("first");
    fireEvent.click(screen.getByRole("button", { name: "Create pending generation" }));
    await waitFor(() => {
      expect(setMessage).toHaveBeenCalledTimes(1);
    });
    fillSmtpForm("replacement");
    fireEvent.click(screen.getByRole("button", { name: "Create pending generation" }));
    await waitFor(() => {
      expect(post).toHaveBeenCalledTimes(2);
    });

    expect(post.mock.calls[0]?.[1]).toMatchObject({
      body: { expected_project_security_revision: 7 },
    });
    expect(post.mock.calls[1]?.[1]).toMatchObject({
      body: { expected_project_security_revision: 8 },
    });
  });

  it("retains write-only credential input when dispatch fails", async () => {
    const { onError } = renderHarness({ failSmtp: true });
    fillSmtpForm("retry");

    fireEvent.click(screen.getByRole("button", { name: "Create pending generation" }));
    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(expect.objectContaining({ message: "dispatch failed" }));
    });

    expect(screen.getByLabelText<HTMLInputElement>("SMTP username").value).toBe("operator-retry");
    expect(screen.getByLabelText<HTMLInputElement>("SMTP password").value).toBe("credential-retry");
  });
});
