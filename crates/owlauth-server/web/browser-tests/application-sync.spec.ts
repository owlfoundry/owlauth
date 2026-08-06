import AxeBuilder from "@axe-core/playwright";
import { execFile } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

import { expect, test, type APIRequestContext } from "@playwright/test";

const controlBase = requiredEnvironment("OWLAUTH_E2E_CONTROL_BASE");
const runtimeBase = requiredEnvironment("OWLAUTH_E2E_RUNTIME_BASE");
const operatorKey = requiredEnvironment("OWLAUTH_E2E_OPERATOR_KEY");
const providerOrigin = requiredEnvironment("OWLAUTH_E2E_PROVIDER_ORIGIN");
const providerClientId = requiredEnvironment("OWLAUTH_E2E_PROVIDER_CLIENT_ID");
const providerClientSecret = requiredEnvironment("OWLAUTH_E2E_PROVIDER_CLIENT_SECRET");
const applicationOrigin = requiredEnvironment("OWLAUTH_E2E_APPLICATION_ORIGIN");
const webhookCaptureUrl = requiredEnvironment("OWLAUTH_E2E_WEBHOOK_CAPTURE_URL");
const webhookEndpointUrl = requiredEnvironment("OWLAUTH_E2E_WEBHOOK_ENDPOINT_URL");

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

interface SigningKey {
  readonly id: string;
  readonly ring_revision: number;
}

interface Provider {
  readonly id: string;
}

interface ProjectionPolicy {
  readonly revision: number;
  readonly verified_email_enabled: boolean;
}

interface WebhookEndpoint {
  readonly id: string;
  readonly revision: number;
  readonly status: string;
}

interface UserEvent {
  readonly event_id: string;
  readonly event_type: string;
  readonly projection_revision: number;
  readonly user_revision: number;
}

interface WebhookDelivery {
  readonly attempt_count: number;
  readonly event_id: string;
  readonly id: string;
  readonly replay_of_delivery_id: string | null;
  readonly replay_sequence: number;
  readonly state: string;
}

interface CapturedWebhook {
  readonly body: string;
  readonly eventId: string;
  readonly signature: string;
  readonly timestamp: string;
}

interface ProvisionedAuthority {
  readonly application: Application;
  readonly otherProject: Project;
  readonly project: Project;
}

test("Block D public journey delivers immutable events and dispatches through Console, CLI, and MCP", async ({
  browserName,
  page,
}) => {
  test.skip(
    browserName !== "chromium",
    "one process-level journey is sufficient; accessibility runs in both browsers",
  );
  test.setTimeout(360_000);
  const suffix = `block-d-${Date.now().toString(36)}`;
  const secret = "block-d-webhook-secret-0000000000";
  const repository = resolve(import.meta.dirname, "../../../..");
  const configDirectory = await mkdtemp(resolve(tmpdir(), "owlauth-cli-e2e-"));
  await page.request.delete(webhookCaptureUrl);

  try {
    const authority = await provision(page.request, suffix);
    let endpoint = await control<WebhookEndpoint>(
      page.request,
      "POST",
      `projects/${authority.project.id}/applications/${authority.application.id}/webhook-endpoints`,
      {
        secret,
        subscribed_event_types: ["user.projection.created", "user.projection.updated"],
        url: webhookEndpointUrl,
      },
      `block-d-webhook-${suffix}`,
    );
    endpoint = await control<WebhookEndpoint>(
      page.request,
      "POST",
      `projects/${authority.project.id}/applications/${authority.application.id}/webhook-endpoints/${endpoint.id}/test`,
      { expected_revision: endpoint.revision },
    );
    endpoint = await control<WebhookEndpoint>(
      page.request,
      "POST",
      `projects/${authority.project.id}/applications/${authority.application.id}/webhook-endpoints/${endpoint.id}/activate`,
      { expected_revision: endpoint.revision },
    );
    expect(endpoint.status).toBe("active");

    const armedFailure = await page.request.post(`${webhookCaptureUrl}/fail-next`);
    expect(armedFailure.ok()).toBe(true);
    const publishableKey = authority.application.configuration.publishable_keys[0];
    expect(publishableKey).toBeDefined();
    const parameters = new URLSearchParams({
      application: authority.application.public_id,
      claims_revision: "1",
      key: publishableKey ?? "",
      other_project: authority.otherProject.public_id,
      project: authority.project.public_id,
      runtime: runtimeBase,
    });
    await page.goto(`${applicationOrigin}/backend/start?${parameters.toString()}`);
    await page
      .getByRole("button", { name: "Continue with Controlled Provider", exact: true })
      .click();
    await expect(page.getByRole("heading", { name: "Backend-custody Application" })).toBeVisible();

    const retried = await waitForWebhookRetry(page.request);
    expect(retried.first.body).toBe(retried.retry.body);
    for (const item of retried.items) assertWebhookSignature(item, secret);

    let events = await waitForEvents(
      page.request,
      authority.project.id,
      authority.application.id,
      1,
    );
    const createdEvent = events.find((event) => event.event_type === "user.projection.created");
    expect(createdEvent).toBeDefined();
    const eventCountBeforeExpansion = events.length;
    const captureCountBeforeExpansion = retried.items.length;

    const projection = await controlGet<ProjectionPolicy>(
      page.request,
      `projects/${authority.project.id}/applications/${authority.application.id}/projection-policy`,
    );
    expect(projection.verified_email_enabled).toBe(false);
    const preview = await mcpCall("owlauth_projection_policy_update_preview", {
      application_id: authority.application.id,
      expected_revision: projection.revision,
      project_id: authority.project.id,
      verified_email_enabled: true,
    });
    const capability = preview["capability"];
    expect(typeof capability).toBe("string");
    const committed = await mcpCall("owlauth_projection_policy_update_commit", {
      application_id: authority.application.id,
      capability,
      expected_revision: projection.revision,
      project_id: authority.project.id,
      verified_email_enabled: true,
    });
    expect(committed["revision"]).toBe(projection.revision + 1);
    expect(committed["verified_email_enabled"]).toBe(true);

    events = await waitForEvents(
      page.request,
      authority.project.id,
      authority.application.id,
      eventCountBeforeExpansion + 1,
    );
    expect(events[0]?.event_type).toBe("user.projection.updated");
    expect(events.at(-1)?.event_type).toBe("user.projection.created");
    expect(
      events.filter((event) => event.event_type === "user.projection.updated").length,
    ).toBeGreaterThanOrEqual(1);
    for (let index = 1; index < events.length; index += 1) {
      const previous = requiredValue(events[index - 1], "missing previous event");
      const current = requiredValue(events[index], "missing current event");
      expect(previous.projection_revision).toBeGreaterThan(current.projection_revision);
      expect(previous.user_revision).toBeGreaterThanOrEqual(current.user_revision);
    }
    const afterExpansion = await waitForWebhookItems(page.request, captureCountBeforeExpansion + 1);
    assertWebhookSignature(
      requiredValue(afterExpansion.at(-1), "missing expanded webhook"),
      secret,
    );

    await run(repository, "cargo", ["build", "--quiet", "--locked", "-p", "owlauth-cli"]);
    const cli = resolve(
      repository,
      "target",
      "debug",
      process.platform === "win32" ? "owlauth.exe" : "owlauth",
    );
    const cliEnvironment = {
      ...process.env,
      OWLAUTH_CONFIG_DIR: configDirectory,
      OWLAUTH_E2E_CLI_OPERATOR: operatorKey,
    };
    await run(
      repository,
      cli,
      [
        "profile",
        "add",
        "block-d",
        "--endpoint",
        controlBase,
        "--credential-env",
        "OWLAUTH_E2E_CLI_OPERATOR",
        "--yes",
      ],
      cliEnvironment,
    );
    const cliEvents = JSON.parse(
      await run(
        repository,
        cli,
        [
          "application",
          "user-event",
          "list",
          authority.project.id,
          authority.application.id,
          "--limit",
          "10",
        ],
        cliEnvironment,
      ),
    ) as { items: UserEvent[] };
    expect(cliEvents.items.map((event) => event.event_id)).toEqual(
      events.map((event) => event.event_id),
    );
    const cliDeliveries = JSON.parse(
      await run(
        repository,
        cli,
        [
          "webhook",
          "delivery",
          "list",
          authority.project.id,
          authority.application.id,
          "--endpoint-id",
          endpoint.id,
          "--limit",
          "10",
        ],
        cliEnvironment,
      ),
    ) as { items: WebhookDelivery[] };
    const retriedDelivery = cliDeliveries.items.find(
      (delivery) =>
        delivery.event_id === retried.first.eventId &&
        delivery.replay_sequence === 0 &&
        delivery.attempt_count === 2,
    );
    const deliveredRetry = requiredValue(retriedDelivery, "missing delivered retry");
    expect(deliveredRetry.state).toBe("delivered");
    const replay = JSON.parse(
      await run(
        repository,
        cli,
        [
          "webhook",
          "delivery",
          "replay",
          authority.project.id,
          authority.application.id,
          deliveredRetry.id,
          "--yes",
        ],
        cliEnvironment,
      ),
    ) as WebhookDelivery;
    expect(replay.replay_of_delivery_id).toBe(deliveredRetry.id);
    expect(replay.replay_sequence).toBe(1);
    const replayed = await waitForWebhookItems(page.request, afterExpansion.length + 1);
    const replayAttempt = requiredValue(replayed.at(-1), "missing replay attempt");
    expect(replayAttempt.eventId).toBe(retried.first.eventId);
    expect(replayAttempt.body).toBe(retried.first.body);
    assertWebhookSignature(replayAttempt, secret);

    await page.goto(`${controlBase}console/`);
    await page.getByLabel("Operator API key").fill(operatorKey);
    await page.getByRole("button", { name: "Unlock console" }).click();
    await page.getByRole("link", { name: new RegExp(`Block D ${suffix}`, "u") }).click();
    await page.getByRole("link", { name: "Applications", exact: true }).click();
    await page
      .getByRole("link", { name: new RegExp(`Block D Application ${suffix}`, "u") })
      .click();
    await expect(
      page.getByRole("heading", { name: new RegExp(`Block D Application ${suffix}`, "u") }),
    ).toBeVisible();
    await expect(page.getByRole("heading", { name: "Immutable user events" })).toBeVisible();
    await expect(
      page.locator("code").filter({ hasText: "user.projection.created" }).first(),
    ).toBeVisible();
    await expect(
      page.locator("code").filter({ hasText: "user.projection.updated" }).first(),
    ).toBeVisible();
    await expect(page.getByText(/Status: delivered/u).first()).toBeVisible();
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    expect(page.url()).not.toContain(operatorKey);
  } finally {
    await rm(configDirectory, { recursive: true, force: true });
  }
});

test("Application sync Console is keyboard and accessibility safe", async ({
  browserName,
  page,
}) => {
  test.setTimeout(180_000);
  const suffix = `block-d-a11y-${browserName}-${Date.now().toString(36)}`;
  const authority = await provision(page.request, suffix);
  await page.goto(`${controlBase}console/`);
  await page.getByLabel("Operator API key").fill(operatorKey);
  await page.getByRole("button", { name: "Unlock console" }).press("Enter");
  await page.getByRole("link", { name: new RegExp(`Block D ${suffix}`, "u") }).press("Enter");
  await page.getByRole("link", { name: "Applications", exact: true }).press("Enter");
  await page
    .getByRole("link", { name: new RegExp(`Block D Application ${suffix}`, "u") })
    .press("Enter");
  await expect(
    page.getByRole("heading", { name: new RegExp(`Block D Application ${suffix}`, "u") }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Create webhook endpoint" }).focus();
  await page.getByRole("button", { name: "Create webhook endpoint" }).press("Enter");
  const dialog = page.getByRole("dialog", { name: "Create webhook endpoint" });
  await expect(dialog).toBeVisible();
  await dialog.getByLabel("HTTPS URL").focus();
  await expect(dialog.getByLabel("HTTPS URL")).toBeFocused();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  expect(authority.application.id).not.toBe("");
});

async function provision(
  request: APIRequestContext,
  suffix: string,
): Promise<ProvisionedAuthority> {
  let project = await control<Project>(
    request,
    "POST",
    "projects",
    { belongs_to: null, display_name: `Block D ${suffix}` },
    `block-d-project-${suffix}`,
  );
  const otherProject = await control<Project>(
    request,
    "POST",
    "projects",
    { belongs_to: null, display_name: `Block D Other ${suffix}` },
    `block-d-other-${suffix}`,
  );
  let application = await control<Application>(
    request,
    "POST",
    `projects/${project.id}/applications`,
    { application_type: "web", display_name: `Block D Application ${suffix}` },
    `block-d-application-${suffix}`,
  );
  application = await control<Application>(
    request,
    "PUT",
    `projects/${project.id}/applications/${application.id}/configuration`,
    {
      allowed_origins: [applicationOrigin],
      expected_security_revision: application.security_revision,
      redirect_uris: [`${applicationOrigin}/backend/callback`],
    },
  );
  const signingKey = await control<SigningKey>(
    request,
    "POST",
    `projects/${project.id}/signing-keys`,
    { expected_project_revision: project.metadata_revision },
    `block-d-signing-${suffix}`,
  );
  expect(
    (
      await request.get(
        `${runtimeBase}projects/${encodeURIComponent(project.public_id)}/.well-known/jwks.json`,
      )
    ).ok(),
  ).toBe(true);
  await delay(150);
  await control<SigningKey>(
    request,
    "POST",
    `projects/${project.id}/signing-keys/${signingKey.id}/activate`,
    { expected_ring_revision: signingKey.ring_revision },
  );
  project = await controlGet<Project>(request, `projects/${project.id}`);
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
      kind: "oidc",
      managed_profile_enabled: true,
      provider_key: "controlled-provider",
    },
    `block-d-provider-${suffix}`,
  );
  await control<Provider>(
    request,
    "PUT",
    `projects/${project.id}/providers/${provider.id}/assignments/${application.id}`,
    { expected_application_revision: application.security_revision },
  );
  application = await controlGet<Application>(
    request,
    `projects/${project.id}/applications/${application.id}`,
  );
  return { application, otherProject, project };
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

async function mcpCall(
  name: string,
  arguments_: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const response = await fetch(`${controlBase}mcp`, {
    body: JSON.stringify({
      id: `block-d-${name}`,
      jsonrpc: "2.0",
      method: "tools/call",
      params: { arguments: arguments_, name },
    }),
    headers: {
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${operatorKey}`,
      "content-type": "application/json",
      "mcp-protocol-version": "2025-06-18",
      origin: new URL(controlBase).origin,
    },
    method: "POST",
  });
  const document = await response.text();
  expect(response.ok, `${name}: ${document}`).toBe(true);
  const result = JSON.parse(document) as {
    result?: { isError?: boolean; structuredContent?: Record<string, unknown> };
  };
  expect(result.result?.isError).toBe(false);
  expect(result.result?.structuredContent).toBeDefined();
  return result.result?.structuredContent ?? {};
}

async function waitForEvents(
  request: APIRequestContext,
  projectId: string,
  applicationId: string,
  count: number,
): Promise<UserEvent[]> {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    const result = await controlGet<{ items: UserEvent[] }>(
      request,
      `projects/${projectId}/applications/${applicationId}/user-events?limit=10`,
    );
    if (result.items.length >= count) return result.items;
    await delay(250);
  }
  throw new Error(`timed out waiting for ${String(count)} Application user events`);
}

async function waitForWebhookRetry(request: APIRequestContext): Promise<{
  first: CapturedWebhook;
  items: CapturedWebhook[];
  retry: CapturedWebhook;
}> {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const response = await request.get(webhookCaptureUrl);
    expect(response.ok()).toBe(true);
    const result = (await response.json()) as { items: CapturedWebhook[] };
    for (const [index, item] of result.items.entries()) {
      const retry = result.items
        .slice(index + 1)
        .find((candidate) => candidate.eventId === item.eventId);
      if (retry !== undefined) return { first: item, items: result.items, retry };
    }
    await delay(250);
  }
  throw new Error("timed out waiting for a webhook retry with a stable event ID");
}

async function waitForWebhookItems(
  request: APIRequestContext,
  count: number,
): Promise<CapturedWebhook[]> {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const response = await request.get(webhookCaptureUrl);
    expect(response.ok()).toBe(true);
    const result = (await response.json()) as { items: CapturedWebhook[] };
    if (result.items.length >= count) return result.items;
    await delay(250);
  }
  throw new Error(`timed out waiting for ${String(count)} webhook attempts`);
}

function assertWebhookSignature(item: CapturedWebhook, secret: string): void {
  expect(item.eventId).not.toBe("");
  expect(Number(item.timestamp)).toBeGreaterThan(0);
  const expected = `v1=${createHmac("sha256", secret)
    .update(`${item.timestamp}.${item.eventId}.${item.body}`)
    .digest("base64url")}`;
  expect(item.signature).toBe(expected);
  const body = JSON.parse(item.body) as { event_id?: unknown };
  expect(body.event_id).toBe(item.eventId);
}

async function run(
  repository: string,
  executable: string,
  arguments_: string[],
  environment: NodeJS.ProcessEnv = process.env,
): Promise<string> {
  return new Promise((resolveRun, reject) => {
    execFile(
      executable,
      arguments_,
      { cwd: repository, env: environment, maxBuffer: 1024 * 1024, timeout: 180_000 },
      (error, stdout, stderr) => {
        if (error === null) {
          resolveRun(stdout);
          return;
        }
        reject(new Error(`${executable} failed: ${error.message}\n${stdout}\n${stderr}`));
      },
    );
  });
}

function requiredValue<T>(value: T | undefined, message: string): T {
  if (value === undefined) throw new Error(message);
  return value;
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}

async function delay(milliseconds: number): Promise<void> {
  await new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}
