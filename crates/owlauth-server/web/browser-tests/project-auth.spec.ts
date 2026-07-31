import { execFile } from "node:child_process";
import { resolve } from "node:path";

import { expect, test, type APIRequestContext } from "@playwright/test";

const controlBase = requiredEnvironment("OWLAUTH_E2E_CONTROL_BASE");
const runtimeBase = requiredEnvironment("OWLAUTH_E2E_RUNTIME_BASE");
const operatorKey = requiredEnvironment("OWLAUTH_E2E_OPERATOR_KEY");
const providerOrigin = requiredEnvironment("OWLAUTH_E2E_PROVIDER_ORIGIN");
const providerClientId = requiredEnvironment("OWLAUTH_E2E_PROVIDER_CLIENT_ID");
const providerClientSecret = requiredEnvironment("OWLAUTH_E2E_PROVIDER_CLIENT_SECRET");
const applicationOrigin = requiredEnvironment("OWLAUTH_E2E_APPLICATION_ORIGIN");
const browserDriverUrl = requiredEnvironment("OWLAUTH_E2E_BROWSER_DRIVER_URL");
const browserDriverToken = requiredEnvironment("OWLAUTH_E2E_BROWSER_DRIVER_TOKEN");

interface Project {
  readonly id: string;
  readonly metadata_revision: number;
  readonly public_id: string;
}

interface Application {
  readonly configuration: { readonly publishable_keys: readonly string[] };
  readonly id: string;
  readonly public_id: string;
  readonly security_revision: number;
}

interface ProjectPolicy {
  readonly claims_revision: number;
}

interface SigningKey {
  readonly id: string;
  readonly ring_revision: number;
}

interface Provider {
  readonly id: string;
}

interface ProvisionedContext {
  readonly application: Application;
  readonly claimsRevision: number;
  readonly otherApplication: Application;
  readonly otherProject: Project;
  readonly project: Project;
}

test("same SDK artifact completes browser-direct and backend-custody Project Auth", async ({
  page,
  browserName,
}) => {
  test.setTimeout(360_000);
  if (browserName !== "chromium" && browserName !== "firefox") {
    throw new Error("browser project is outside the declared support matrix");
  }
  const context = await provision(page.request, `${browserName}-${Date.now().toString(36)}`);
  const publishableKey = context.application.configuration.publishable_keys[0];
  expect(publishableKey).toBeDefined();

  const startParallelInteraction = async (state: string): Promise<string> => {
    const response = await page.request.post(
      `${runtimeBase}v1/projects/${encodeURIComponent(context.project.public_id)}/auth/login/start`,
      {
        data: {
          application_id: context.application.public_id,
          pkce_challenge: "A".repeat(43),
          presentation_hint: null,
          publishable_key: publishableKey ?? "",
          redirect_uri: `${applicationOrigin}/sdk/callback`,
          state,
        },
        headers: { origin: applicationOrigin },
      },
    );
    expect(response.status()).toBe(201);
    const body = (await response.json()) as { hosted_url?: unknown };
    expect(typeof body.hosted_url).toBe("string");
    return body.hosted_url as string;
  };
  const [firstHostedUrl, secondHostedUrl] = await Promise.all([
    startParallelInteraction(`parallel-first-${browserName}`),
    startParallelInteraction(`parallel-second-${browserName}`),
  ]);
  const firstInteraction = await page.context().newPage();
  const secondInteraction = await page.context().newPage();
  await firstInteraction.goto(firstHostedUrl);
  await secondInteraction.goto(secondHostedUrl);
  for (const interaction of [firstInteraction, secondInteraction]) {
    await expect(interaction.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  }
  for (const interaction of [firstInteraction, secondInteraction]) {
    await interaction
      .getByRole("button", { name: "Controlled Provider" })
      .click({ noWaitAfter: true });
    await expect
      .poll(
        () => {
          const current = new URL(interaction.url());
          return `${current.origin}${current.pathname}`;
        },
        { timeout: 30_000 },
      )
      .toBe(`${applicationOrigin}/sdk/callback`);
  }
  await firstInteraction.close();
  await secondInteraction.close();

  const browserParameters = new URLSearchParams({
    application: context.application.public_id,
    key: publishableKey ?? "",
    project: context.project.public_id,
    runtime: runtimeBase,
  });
  const observedUrls: string[] = [];
  const browserErrors: string[] = [];
  const requestFailures: string[] = [];
  page.on("request", (request) => observedUrls.push(request.url()));
  page.on("requestfailed", (request) =>
    requestFailures.push(`${request.url()}: ${request.failure()?.errorText ?? "unknown"}`),
  );
  page.on("pageerror", (error) => browserErrors.push(error.message));
  await page.goto(`${applicationOrigin}/browser/?${browserParameters.toString()}`);
  const popupReady = page.waitForEvent("popup");
  await page.getByRole("button", { name: "Start browser sign-in" }).click();
  const popup = await popupReady;
  await page.waitForTimeout(500);
  if (browserErrors.length > 0) {
    throw new Error(
      `browser Application failed: ${browserErrors.join("; ")}; requests: ${observedUrls.join(", ")}; failures: ${requestFailures.join(", ")}`,
    );
  }
  await expect(popup.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  await expect(popup.getByText("controlled-provider", { exact: false })).toBeVisible();
  await popup.getByRole("button", { name: "Controlled Provider" }).click();
  await expect(page.locator("#status")).toHaveText("Browser session ready");

  await page.getByRole("button", { name: "Read current user" }).click();
  await expect(page.locator("#status")).toHaveText("Current user verified");
  await expect(page.locator("output")).toHaveText("Ada Integration");
  await page.getByRole("button", { name: "Refresh session" }).click();
  await expect(page.locator("#status")).toHaveText("Credentials replaced atomically");
  await expect(page.locator("output")).toHaveText("generation 2");

  const storage = await page.evaluate(async () => ({
    caches: (await caches.keys()).length,
    databases: typeof indexedDB.databases === "function" ? (await indexedDB.databases()).length : 0,
    local: localStorage.length,
    session: sessionStorage.length,
  }));
  expect(storage).toEqual({ caches: 0, databases: 0, local: 0, session: 0 });
  expect(page.url()).not.toMatch(/handoff|access_token|refresh_token/u);
  expect(observedUrls.every((url) => !/[?&](?:access_token|refresh_token)=/u.test(url))).toBe(true);
  await expect(page.locator("body")).not.toContainText(/eyJ[A-Za-z0-9_-]+\./u);

  await page.getByRole("button", { name: "Application logout" }).click();
  await expect(page.locator("#status")).toHaveText("Application session ended");

  const forbidden = await page.request.get(
    `${runtimeBase}v1/projects/${encodeURIComponent(context.project.public_id)}/auth/config?application_id=${encodeURIComponent(context.application.public_id)}`,
    { headers: { origin: "https://attacker.example" } },
  );
  expect(forbidden.status()).toBe(403);
  expect(forbidden.headers()["access-control-allow-origin"]).toBeUndefined();

  const crossApplication = await page.request.get(
    `${runtimeBase}v1/projects/${encodeURIComponent(context.project.public_id)}/auth/config?application_id=${encodeURIComponent(context.otherApplication.public_id)}`,
    { headers: { origin: applicationOrigin } },
  );
  expect(crossApplication.status()).toBe(403);
  expect(crossApplication.headers()["access-control-allow-origin"]).toBeUndefined();

  const backendParameters = new URLSearchParams({
    application: context.application.public_id,
    claims_revision: String(context.claimsRevision),
    key: publishableKey ?? "",
    other_project: context.otherProject.public_id,
    project: context.project.public_id,
    runtime: runtimeBase,
  });
  await page.goto(`${applicationOrigin}/backend/start?${backendParameters.toString()}`);
  await expect(page.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  await page.getByRole("button", { name: "Controlled Provider" }).click();
  await expect(page.getByRole("heading", { name: "Backend-custody Application" })).toBeVisible();
  await expect(page.getByText("Session verified")).toBeVisible();
  await expect(page.getByText("verified", { exact: true })).toBeVisible();
  await expect(page.getByText("rejected", { exact: true })).toHaveCount(2);
  await expect(page.getByText("2", { exact: true })).toBeVisible();
  expect(page.url()).not.toMatch(/handoff|access_token|refresh_token/u);
  await expect(page.locator("body")).not.toContainText(/eyJ[A-Za-z0-9_-]+\./u);

  await page.getByRole("button", { name: "Application logout" }).click();
  await expect(page.getByRole("heading", { name: "Backend session ended" })).toBeVisible();
  await expect(page.getByRole("status")).toHaveText("Application logout was confirmed.");

  await runSdkE2Es(context, publishableKey ?? "", browserName);
});

async function runSdkE2Es(
  context: ProvisionedContext,
  publishableKey: string,
  browserName: "chromium" | "firefox",
): Promise<void> {
  const repository = resolve(import.meta.dirname, "../../../..");
  const sharedEnvironment = {
    ...process.env,
    OWLAUTH_E2E_ALLOW_INSECURE_LOOPBACK: "1",
    OWLAUTH_E2E_APPLICATION_ID: context.application.public_id,
    OWLAUTH_E2E_PROJECT_ID: context.project.public_id,
    OWLAUTH_E2E_PUBLISHABLE_KEY: publishableKey,
    OWLAUTH_E2E_REDIRECT_URI: `${applicationOrigin}/sdk/callback`,
  };
  await runSdkCommand(
    repository,
    "TypeScript",
    "pnpm",
    ["--filter", "@owlauth/client", "test:e2e"],
    {
      ...sharedEnvironment,
      OWLAUTH_E2E_BROWSER_DRIVER_TOKEN: browserDriverToken,
      OWLAUTH_E2E_BROWSER_DRIVER_URL: browserDriverUrl,
      OWLAUTH_E2E_BROWSER_NAME: browserName,
      OWLAUTH_E2E_PROVIDER_KEY: "controlled-provider",
      OWLAUTH_E2E_RUNTIME_BASE_URL: runtimeBase,
    },
    "TypeScript real-server Project Auth E2E passed.",
  );
  if (browserName !== "chromium") return;

  await runSdkCommand(
    repository,
    "Python",
    "uv",
    ["run", "--project", "sdks/python", "python", "sdks/python/tests/runtime_e2e.py"],
    { ...sharedEnvironment, OWLAUTH_E2E_RUNTIME_URL: runtimeBase },
    "Python SDK real-Runtime Project Auth E2E passed",
  );
  await runSdkCommand(
    repository,
    "Rust",
    "cargo",
    [
      "test",
      "-p",
      "owlauth-client",
      "--test",
      "server_e2e",
      "--",
      "--ignored",
      "--exact",
      "real_runtime_project_auth_lifecycle",
    ],
    {
      ...sharedEnvironment,
      OWLAUTH_E2E_PROVIDER_KEY: "controlled-provider",
      OWLAUTH_E2E_RUNTIME_URL: runtimeBase,
    },
    "test real_runtime_project_auth_lifecycle ... ok",
  );
}

async function runSdkCommand(
  repository: string,
  sdk: string,
  executable: string,
  arguments_: string[],
  environment: NodeJS.ProcessEnv,
  successMarker: string,
): Promise<void> {
  await new Promise<void>((resolveRun, reject) => {
    execFile(
      executable,
      arguments_,
      { cwd: repository, env: environment, maxBuffer: 1024 * 1024, timeout: 180_000 },
      (error, stdout, stderr) => {
        if (error === null) {
          expect(stdout).toContain(successMarker);
          resolveRun();
          return;
        }
        reject(
          new Error(
            `${sdk} SDK real-server command failed: ${error.message}\n${stdout}\n${stderr}`,
          ),
        );
      },
    );
  });
}

async function provision(request: APIRequestContext, suffix: string): Promise<ProvisionedContext> {
  const project = await control<Project>(
    request,
    "POST",
    "projects",
    {
      display_name: `E2E Project ${suffix}`,
      belongs_to: null,
    },
    `project-${suffix}`,
  );
  const policy = await controlGet<ProjectPolicy>(request, `projects/${project.id}/policy`);
  const otherProject = await control<Project>(
    request,
    "POST",
    "projects",
    {
      display_name: `Isolated Project ${suffix}`,
      belongs_to: null,
    },
    `other-project-${suffix}`,
  );
  let application = await control<Application>(
    request,
    "POST",
    `projects/${project.id}/applications`,
    { application_type: "web", display_name: "E2E Application" },
    `application-${suffix}`,
  );
  application = await control<Application>(
    request,
    "PUT",
    `projects/${project.id}/applications/${application.id}/configuration`,
    {
      allowed_origins: [applicationOrigin],
      expected_security_revision: application.security_revision,
      redirect_uris: [
        `${applicationOrigin}/browser/callback`,
        `${applicationOrigin}/backend/callback`,
        `${applicationOrigin}/sdk/callback`,
      ],
    },
  );
  let otherApplication = await control<Application>(
    request,
    "POST",
    `projects/${project.id}/applications`,
    { application_type: "web", display_name: "Other Application" },
    `other-application-${suffix}`,
  );
  otherApplication = await control<Application>(
    request,
    "PUT",
    `projects/${project.id}/applications/${otherApplication.id}/configuration`,
    {
      allowed_origins: ["https://other-application.example"],
      expected_security_revision: otherApplication.security_revision,
      redirect_uris: ["https://other-application.example/callback"],
    },
  );

  const signingKey = await control<SigningKey>(
    request,
    "POST",
    `projects/${project.id}/signing-keys`,
    { expected_project_revision: project.metadata_revision },
    `signing-key-${suffix}`,
  );
  const jwks = await request.get(
    `${runtimeBase}projects/${encodeURIComponent(project.public_id)}/.well-known/jwks.json`,
  );
  expect(jwks.ok()).toBe(true);
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 150));
  await control<SigningKey>(
    request,
    "POST",
    `projects/${project.id}/signing-keys/${signingKey.id}/activate`,
    { expected_ring_revision: signingKey.ring_revision },
  );

  const provider = await control<Provider>(
    request,
    "POST",
    `projects/${project.id}/providers`,
    {
      client_id: providerClientId,
      client_secret: providerClientSecret,
      display_name: "Controlled Provider",
      expected_project_revision: project.metadata_revision,
      issuer: providerOrigin,
      provider_key: "controlled-provider",
    },
    `provider-${suffix}`,
  );
  await control<Provider>(
    request,
    "PUT",
    `projects/${project.id}/providers/${provider.id}/assignments/${application.id}`,
    { expected_application_revision: application.security_revision },
  );
  return {
    application,
    claimsRevision: policy.claims_revision,
    otherApplication,
    otherProject,
    project,
  };
}

async function controlGet<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(`${controlBase}v1/${path}`, {
    headers: { authorization: `Bearer ${operatorKey}` },
  });
  expect(response.ok(), `GET ${path}: ${await response.text()}`).toBe(true);
  return (await response.json()) as T;
}

async function control<T>(
  request: APIRequestContext,
  method: "POST" | "PUT",
  path: string,
  data: unknown,
  idempotencyKey?: string,
): Promise<T> {
  const response = await request.fetch(`${controlBase}v1/${path}`, {
    data,
    headers: {
      authorization: `Bearer ${operatorKey}`,
      ...(idempotencyKey === undefined ? {} : { "idempotency-key": idempotencyKey }),
    },
    method,
  });
  expect(response.ok(), `${method} ${path}: ${await response.text()}`).toBe(true);
  return (await response.json()) as T;
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}
