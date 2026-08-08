import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { useState } from "react";
import { createMemoryRouter, RouterProvider } from "react-router";

import type {
  Application,
  DisposableControlClient,
  EmailAssignment,
  EmailMethodPolicy,
  Provider,
} from "../client";
import { ControlConfirmationProvider } from "../app/Confirmation";
import { ApplicationAuthentication } from "./ApplicationAuthentication";

const projectId = "11111111-1111-4111-8111-111111111111";
const applicationId = "22222222-2222-4222-8222-222222222222";

const initialApplication: Application = {
  id: applicationId,
  project_id: projectId,
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

const initialProvider: Provider = {
  id: "33333333-3333-4333-8333-333333333333",
  project_id: projectId,
  provider_key: "workforce",
  display_name: "Workforce SSO",
  kind: "oidc",
  issuer: "https://issuer.example",
  client_id: "client-id",
  callback_url: "https://runtime.example/callback",
  status: "active",
  revision: 5,
  secret_replacement_pending: false,
  login_supported: true,
  identity_proof_supported: true,
  assigned_application_ids: [],
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

const policy: EmailMethodPolicy = {
  project_id: projectId,
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

function renderHarness() {
  let authoritativeApplication = initialApplication;
  let provider = initialProvider;
  let assignments: EmailAssignment[] = [];

  const get = vi.fn((path: string) => {
    if (path.endsWith("/providers")) return Promise.resolve(successful({ items: [provider] }));
    if (path.endsWith("/email-method")) return Promise.resolve(successful(policy));
    if (path.endsWith("/email-method/assignments")) {
      return Promise.resolve(successful({ items: assignments }));
    }
    throw new Error(`unexpected GET ${path}`);
  });
  const put = vi.fn(
    (
      path: string,
      request: {
        body: {
          enabled?: boolean;
          expected_application_revision?: number;
          expected_application_security_revision?: number;
        };
      },
    ) => {
      authoritativeApplication = {
        ...authoritativeApplication,
        security_revision: authoritativeApplication.security_revision + 1,
      };
      if (path.includes("/providers/")) {
        provider = { ...provider, assigned_application_ids: [applicationId] };
        return Promise.resolve(successful(provider));
      }
      assignments = [
        {
          project_id: projectId,
          application_id: applicationId,
          enabled: request.body.enabled === true,
          security_revision: authoritativeApplication.security_revision,
        },
      ];
      return Promise.resolve(successful(assignments[0]));
    },
  );
  const post = vi.fn(
    (path: string, request: { body: { expected_application_revision: number } }) => {
      void path;
      void request;
      authoritativeApplication = {
        ...authoritativeApplication,
        security_revision: authoritativeApplication.security_revision + 1,
      };
      provider = { ...provider, assigned_application_ids: [] };
      return Promise.resolve(successful(provider));
    },
  );
  const session = {
    client: { GET: get, PUT: put, POST: post },
    dispose: vi.fn(),
  } as unknown as DisposableControlClient;
  const setMessage = vi.fn();
  const onError = vi.fn(() => Promise.resolve());

  function Harness() {
    const [application, setApplication] = useState(initialApplication);
    return (
      <ApplicationAuthentication
        session={session}
        application={application}
        editable
        onApplicationChanged={() => {
          setApplication(authoritativeApplication);
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
  return { post, put, setMessage };
}

function methodRow(name: RegExp) {
  return screen.getByRole("row", { name });
}

describe("Application authentication assignments", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("uses the refreshed Application security revision for provider assign then remove", async () => {
    const { post, put, setMessage } = renderHarness();
    const row = await screen.findByRole("row", { name: /Workforce SSO/u });

    fireEvent.click(within(row).getByRole("button", { name: "Assign" }));
    await waitFor(() => {
      expect(
        within(methodRow(/Workforce SSO/u)).getByRole("button", { name: "Remove" }),
      ).toBeEnabled();
    });
    fireEvent.click(within(methodRow(/Workforce SSO/u)).getByRole("button", { name: "Remove" }));
    fireEvent.click(
      within(screen.getByRole("dialog", { name: "Remove authentication provider" })).getByRole(
        "button",
        { name: "Remove provider" },
      ),
    );

    await waitFor(() => {
      expect(post).toHaveBeenCalledTimes(1);
    });
    expect(put.mock.calls[0]?.[1]).toMatchObject({
      body: { expected_application_revision: 11 },
    });
    expect(post.mock.calls[0]?.[1]).toMatchObject({
      body: { expected_application_revision: 12 },
    });
    expect(setMessage).toHaveBeenCalledWith("Workforce SSO removed from this Application.");
  });

  it("assigns passwordless email from the Application surface", async () => {
    const { put, setMessage } = renderHarness();
    const row = await screen.findByRole("row", { name: /Passwordless email/u });

    fireEvent.click(within(row).getByRole("button", { name: "Assign" }));

    await waitFor(() => {
      expect(setMessage).toHaveBeenCalledWith("Passwordless email assigned to this Application.");
    });
    expect(put).toHaveBeenCalledWith(
      "/v1/projects/{project_id}/applications/{application_id}/email-method",
      expect.objectContaining({
        body: { enabled: true, expected_application_security_revision: 11 },
      }),
    );
  });
});
