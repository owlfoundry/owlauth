import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

import {
  BrowserEvidence,
  type BrowserEvidenceSnapshot,
  type LifecycleSample,
  type NetworkRecord,
} from "./browser-evidence";

const controlBase = requiredEnvironment("OWLAUTH_E2E_CONTROL_BASE");
const runtimeBase = requiredEnvironment("OWLAUTH_E2E_RUNTIME_BASE");
const operatorKey = requiredEnvironment("OWLAUTH_E2E_OPERATOR_KEY");
const providerOrigin = requiredEnvironment("OWLAUTH_E2E_PROVIDER_ORIGIN");
const providerClientId = requiredEnvironment("OWLAUTH_E2E_PROVIDER_CLIENT_ID");
const providerClientSecret = requiredEnvironment("OWLAUTH_E2E_PROVIDER_CLIENT_SECRET");
const applicationOrigin = requiredEnvironment("OWLAUTH_E2E_APPLICATION_ORIGIN");
const browserDriverUrl = requiredEnvironment("OWLAUTH_E2E_BROWSER_DRIVER_URL");
const browserDriverToken = requiredEnvironment("OWLAUTH_E2E_BROWSER_DRIVER_TOKEN");
const faultProxyBase = requiredEnvironment("OWLAUTH_E2E_FAULT_PROXY_BASE");
const faultProxyToken = requiredEnvironment("OWLAUTH_E2E_FAULT_PROXY_TOKEN");
const typescriptArchive = requiredEnvironment("OWLAUTH_E2E_TYPESCRIPT_ARCHIVE");
const typescriptRunner = requiredEnvironment("OWLAUTH_E2E_TYPESCRIPT_RUNNER");
const typescriptVersion = requiredEnvironment("OWLAUTH_E2E_TYPESCRIPT_VERSION");
const frozenTypescriptSdkDigest = requiredEnvironment("OWLAUTH_E2E_TYPESCRIPT_SDK_DIGEST");
const pythonExecutable = requiredEnvironment("OWLAUTH_E2E_PYTHON_EXECUTABLE");
const pythonRunner = requiredEnvironment("OWLAUTH_E2E_PYTHON_RUNNER");
const pythonVersion = requiredEnvironment("OWLAUTH_E2E_PYTHON_VERSION");
const rustManifest = requiredEnvironment("OWLAUTH_E2E_RUST_MANIFEST");
const rustVersion = requiredEnvironment("OWLAUTH_E2E_RUST_VERSION");
const pythonSdkDigest = requiredEnvironment("OWLAUTH_E2E_PYTHON_SDK_DIGEST");
const rustSdkDigest = requiredEnvironment("OWLAUTH_E2E_RUST_SDK_DIGEST");
const sourceCommit = requiredEnvironment("OWLAUTH_E2E_SOURCE_COMMIT");
const expectedOperationIds = [
  "get_public_application_config",
  "get_project_jwks",
  "start_login",
  "exchange_handoff",
  "refresh_session",
  "get_current_user",
  "logout_application_session",
  "prepare_browser_logout",
] as const;
const expectedFaultOperationIds = [
  "exchange_handoff",
  "refresh_session",
  "logout_application_session",
] as const;

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
  readonly access_token_lifetime_seconds: number;
  readonly browser_session_reuse: boolean;
  readonly claims_revision: number;
  readonly session_revision: number;
}

interface SigningKey {
  readonly id: string;
  readonly kid: string;
  readonly state: string;
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

interface SdkE2EResult {
  readonly assignments: Readonly<
    Record<string, { readonly application: string; readonly project: string }>
  >;
  readonly browserEvidence: readonly BrowserEvidenceSnapshot[];
  readonly faultInjectedOperationIds: Readonly<Record<string, readonly string[]>>;
  readonly observedOperationIds: Readonly<Record<string, readonly string[]>>;
}

interface MeasuredSdkEvidence {
  readonly faultInjectedOperationIds: readonly string[];
  readonly observedOperationIds: readonly string[];
}

type SecretKind = "access" | "csrf" | "handoff" | "preparation" | "refresh";

interface SecretValue {
  readonly kind: SecretKind;
  readonly value: string;
}

type RuntimeCookieKind = "interaction" | "project";

interface RuntimeCookieSecret {
  readonly kind: RuntimeCookieKind;
  readonly name: string;
  readonly path: string;
  readonly value: string;
}

interface RuntimeCookieEvent {
  readonly disposition: "deletion" | "issuance";
  readonly kind: RuntimeCookieKind;
  readonly name: string;
  readonly value: string;
}

interface ParsedSetCookie {
  readonly attributes: ReadonlyMap<string, string>;
  readonly name: string;
  readonly value: string;
}

interface HostedBootstrap {
  readonly csrf: string;
  readonly project_id: string;
  readonly revision: number;
}

interface MutationResult {
  readonly body: unknown;
  readonly status: number;
}

interface ProviderRequestCounts {
  readonly authorization_requests: number;
  readonly token_confinement_violations: number;
  readonly token_requests: number;
  readonly revocation_requests: number;
  readonly userinfo_requests: number;
}

interface ProjectUserList {
  readonly items: readonly { readonly id: string }[];
}

interface ManagedConnection {
  readonly credential_generation: number;
  readonly generation: number;
  readonly id: string;
  readonly last_safe_outcome: string;
  readonly last_synchronized_at?: string | null;
  readonly revision: number;
  readonly state: string;
}

interface ManagedConnectionList {
  readonly items: readonly ManagedConnection[];
}

interface ManagedReauthorization {
  readonly hosted_target?: string;
  readonly id: string;
  readonly revision: number;
  readonly status: string;
}

test("same SDK artifact completes browser-direct and backend-custody Project Auth", async ({
  browser,
  context: browserContext,
  page,
  browserName,
}) => {
  test.setTimeout(900_000);
  if (browserName !== "chromium" && browserName !== "firefox") {
    throw new Error("browser project is outside the declared support matrix");
  }
  expect(await fileSha256(typescriptArchive)).toBe(frozenTypescriptSdkDigest);
  const evidence = await BrowserEvidence.create(browserContext);
  const context = await provision(page.request, `${browserName}-${Date.now().toString(36)}`);
  const publishableKey = context.application.configuration.publishable_keys[0];
  expect(publishableKey).toBeDefined();

  const startInteraction = async (state: string): Promise<string> => {
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

  const countsBeforeSelectionRace = await providerRequestCounts(page.request);
  const selectionRaceContext = await browser.newContext();
  const selectionEvidence = await BrowserEvidence.create(selectionRaceContext);
  const selectionPage = await selectionRaceContext.newPage();
  await selectionPage.goto(await startInteraction(`selection-race-${browserName}`));
  await expect(selectionPage.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  const selectionBootstrap = await observedBootstrap(selectionEvidence, selectionPage.url());
  const selectionResults = await raceHostedMutation(
    selectionPage,
    `${runtimeBase}v1/projects/${encodeURIComponent(context.project.public_id)}/auth/interactions/${encodeURIComponent(interactionHandle(selectionPage.url()))}/method`,
    {
      csrf: selectionBootstrap.csrf,
      expected_revision: selectionBootstrap.revision,
      provider_key: "controlled-provider",
    },
  );
  expect(selectionResults.filter(({ status }) => status === 200)).toHaveLength(1);
  expect(selectionResults.filter(({ status }) => status !== 200)).toHaveLength(1);
  expect(await providerRequestCounts(page.request)).toEqual(countsBeforeSelectionRace);
  await selectionEvidence.settle();
  await assertEvidenceConfinement([selectionEvidence]);
  await selectionRaceContext.close();

  // A standards-shaped provider denial is owned and terminalized by the exact ordinary-login
  // interaction. Raw upstream description/URI never become rendered or persisted output, and a
  // duplicate callback replay cannot reactivate the terminal interaction.
  const denialContext = await browser.newContext();
  const denialPage = await denialContext.newPage();
  await denialPage.goto(await startInteraction(`ordinary-denial-${browserName}`));
  await expect(denialPage.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  const countsBeforeOrdinaryDenial = await providerRequestCounts(page.request);
  await armProviderDenial(page.request);
  await denialPage
    .getByRole("button", { name: "Continue with Controlled Provider", exact: true })
    .click();
  await expect(
    denialPage.getByRole("heading", { name: "Provider authorization was not approved" }),
  ).toBeVisible();
  await expect(denialPage.locator("body")).not.toContainText("controlled raw denial prose");
  await expect(denialPage.locator("body")).not.toContainText("private-upstream-error");
  const deniedCallback = denialPage.url();
  const countsAfterOrdinaryDenial = await providerRequestCounts(page.request);
  expect(countsAfterOrdinaryDenial.token_requests).toBe(countsBeforeOrdinaryDenial.token_requests);
  await denialPage.goto(deniedCallback);
  await expect(denialPage.getByRole("heading", { name: "Sign-in unavailable" })).toBeVisible();
  await denialContext.close();

  const countsBeforeBrowserSignIn = await providerRequestCounts(page.request);
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
  const popupReady = page.waitForEvent("popup", { timeout: 30_000 });
  await page.getByRole("button", { name: "Start browser sign-in" }).click();
  const popup = await popupReady;
  await page.waitForTimeout(500);
  if (browserErrors.length > 0) {
    throw new Error(
      `browser Application failed: ${browserErrors.join("; ")}; requests: ${observedUrls.join(", ")}; failures: ${requestFailures.join(", ")}`,
    );
  }
  await expect(popup.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  await expect(
    popup.getByRole("button", { name: "Continue with Controlled Provider", exact: true }),
  ).toBeVisible();
  await expect(
    popup.getByRole("button", { name: "Continue with current session", exact: true }),
  ).toHaveCount(0);
  await observedBootstrap(evidence, popup.url());
  await assertPageSecretFree(popup, await currentSecrets(evidence));
  await popup
    .getByRole("button", { name: "Continue with Controlled Provider", exact: true })
    .click();
  await expect(page.locator("#status")).toHaveText("Browser session ready");

  await page.getByRole("button", { name: "Read current user" }).click();
  // A successful SDK read already verifies the Project, Application, user, and projection
  // bindings. The immediate managed sync may legitimately update the callback profile first.
  await expect(page.locator("#status")).toHaveText("Current user verified");

  if (browserName === "firefox") {
    // Firefox qualifies the same browser-direct and backend-custody surfaces plus the complete
    // TypeScript exact artifact. Chromium alone carries the much longer managed-connection
    // reauthorization/rotation/recovery journey, which is server behavior rather than an SDK
    // browser-portability dimension.
    await page.getByRole("button", { name: "Refresh session" }).click();
    await expect(page.locator("#status")).toHaveText("Credentials replaced atomically");
    await page.getByRole("button", { name: "Application logout" }).click();
    await expect(page.locator("#status")).toHaveText("Application session ended");
    await evidence.settle();
    await assertPageSecretFree(page, await currentSecrets(evidence));
    const backendContext = await completeBackendCustodyJourney(page, browserName);
    await completeSdkQualification(page, evidence, browserName, context, backendContext);
    return;
  }

  // Control creates a fixed-provider, single-connection reauthorization. It is a separate
  // top-level journey: no Application sign-in or browser-session reuse is offered.
  const users = await controlGet<ProjectUserList>(
    page.request,
    `projects/${context.project.id}/users`,
  );
  expect(users.items).toHaveLength(1);
  const userId = users.items[0]?.id;
  if (userId === undefined) throw new Error("managed user was not materialized");
  const managedBefore = await controlGet<ManagedConnectionList>(
    page.request,
    `projects/${context.project.id}/users/${userId}/managed-provider-connections`,
  );
  expect(managedBefore.items).toHaveLength(1);
  const predecessor = managedBefore.items[0];
  if (predecessor === undefined) throw new Error("managed connection was not materialized");
  expect(predecessor.state).toBe("active");
  const predecessorSynchronizedAt = predecessor.last_synchronized_at;
  const predecessorProfileCommitted =
    predecessor.last_safe_outcome === "read_succeeded" &&
    typeof predecessorSynchronizedAt === "string" &&
    !Number.isNaN(Date.parse(predecessorSynchronizedAt));
  await expect
    .poll(
      async () => {
        const counts = await providerRequestCounts(page.request);
        return (
          counts.token_confinement_violations === 0 &&
          counts.token_requests >= countsBeforeBrowserSignIn.token_requests + 2 &&
          counts.userinfo_requests > countsBeforeBrowserSignIn.userinfo_requests
        );
      },
      { timeout: 45_000 },
    )
    .toBe(true);
  // The provider-count barrier proves the bounded managed-profile request occurred. Its transaction
  // may commit immediately before or after the Control snapshot above, so require successor
  // generations only when that snapshot did not already contain the successful outcome.
  let reauthorizationPredecessor: ManagedConnection | undefined;
  await expect
    .poll(
      async () => {
        const managed = await controlGet<ManagedConnectionList>(
          page.request,
          `projects/${context.project.id}/users/${userId}/managed-provider-connections`,
        );
        const current = managed.items.find(({ id }) => id === predecessor.id);
        const synchronizedAt = current?.last_synchronized_at;
        const generationsCommitted =
          current !== undefined &&
          (predecessorProfileCommitted
            ? current.generation >= predecessor.generation &&
              current.credential_generation >= predecessor.credential_generation
            : current.generation > predecessor.generation &&
              current.credential_generation > predecessor.credential_generation);
        const profileCommitted =
          current?.state === "active" &&
          generationsCommitted &&
          current.last_safe_outcome === "read_succeeded" &&
          typeof synchronizedAt === "string" &&
          !Number.isNaN(Date.parse(synchronizedAt));
        if (profileCommitted) reauthorizationPredecessor = current;
        return profileCommitted;
      },
      { timeout: 45_000 },
    )
    .toBe(true);
  if (reauthorizationPredecessor === undefined) {
    throw new Error("background-synchronized managed connection was not visible");
  }
  expect(reauthorizationPredecessor.state).toBe("active");
  expect(reauthorizationPredecessor.generation).toBeGreaterThanOrEqual(predecessor.generation);
  expect(reauthorizationPredecessor.credential_generation).toBeGreaterThanOrEqual(
    predecessor.credential_generation,
  );
  if (!predecessorProfileCommitted) {
    expect(reauthorizationPredecessor.generation).toBeGreaterThan(predecessor.generation);
    expect(reauthorizationPredecessor.credential_generation).toBeGreaterThan(
      predecessor.credential_generation,
    );
  }
  expect(reauthorizationPredecessor.last_safe_outcome).toBe("read_succeeded");
  expect(Date.parse(reauthorizationPredecessor.last_synchronized_at ?? "")).not.toBeNaN();
  await page.getByRole("button", { name: "Read current user" }).click();
  await expect(page.locator("output")).toHaveText("Ada Managed Integration");

  const deniedReauthorization = await control<ManagedReauthorization>(
    page.request,
    "POST",
    `projects/${context.project.id}/users/${userId}/managed-provider-connections/${predecessor.id}/reauthorizations`,
    {
      application_id: context.application.id,
      expected_connection_generation: reauthorizationPredecessor.generation,
      expected_connection_revision: reauthorizationPredecessor.revision,
      expected_credential_generation: reauthorizationPredecessor.credential_generation,
    },
    `managed-denial-${browserName}-${Date.now().toString(36)}`,
  );
  if (deniedReauthorization.hosted_target === undefined) {
    throw new Error("managed denial omitted its create-only hosted target");
  }
  const managedDenialPage = await browserContext.newPage();
  const managedDenialSetCookies: string[] = [];
  const managedDenialHeaderReads: Promise<void>[] = [];
  managedDenialPage.on("response", (response) => {
    if (!response.url().startsWith(runtimeBase)) return;
    managedDenialHeaderReads.push(
      response.headersArray().then((headers) => {
        for (const { name, value } of headers) {
          if (name.toLowerCase() === "set-cookie") managedDenialSetCookies.push(value);
        }
      }),
    );
  });
  await managedDenialPage.goto(deniedReauthorization.hosted_target);
  await expect(
    managedDenialPage.getByRole("heading", {
      name: "Reauthorize managed connection",
      exact: true,
    }),
    `managed denial Hosted target remained on ${managedDenialPage.url()}`,
  ).toBeVisible({ timeout: 30_000 });
  await expect(managedDenialPage.getByRole("button")).toHaveCount(1);
  await armProviderDenial(page.request);
  await managedDenialPage.getByRole("button").click();
  await expect(
    managedDenialPage.getByRole("heading", { name: "Provider authorization was not approved" }),
  ).toBeVisible();
  await Promise.all(managedDenialHeaderReads);
  const managedInteractionCookieWrites = managedDenialSetCookies
    .map(parseSetCookie)
    .filter(({ name }) => runtimeCookieKind(name) === "interaction");
  const issuedManagedInteractionCookies = managedInteractionCookieWrites.filter(
    ({ attributes, value }) => value !== "" && attributes.get("max-age") !== "0",
  );
  expect(issuedManagedInteractionCookies).toHaveLength(1);
  const managedInteractionCookieName = issuedManagedInteractionCookies[0]?.name;
  expect(
    managedInteractionCookieWrites.some(
      ({ attributes, name, value }) =>
        name === managedInteractionCookieName &&
        value === "deleted" &&
        attributes.get("max-age") === "0",
    ),
  ).toBe(true);
  const cookiesAfterManagedDenial = await browserContext.cookies(
    deniedReauthorization.hosted_target,
  );
  expect(cookiesAfterManagedDenial.some(({ name }) => name === managedInteractionCookieName)).toBe(
    false,
  );
  await expect(managedDenialPage.locator("body")).not.toContainText("controlled raw denial prose");
  await expect
    .poll(
      async () => {
        const current = await controlGet<ManagedReauthorization>(
          page.request,
          `projects/${context.project.id}/users/${userId}/managed-provider-connections/${predecessor.id}/reauthorizations/${deniedReauthorization.id}`,
        );
        return current.status;
      },
      { timeout: 30_000 },
    )
    .toBe("provider_exchange_failed");
  await managedDenialPage.close();

  const afterManagedDenial = await controlGet<ManagedConnectionList>(
    page.request,
    `projects/${context.project.id}/users/${userId}/managed-provider-connections`,
  );
  expect(afterManagedDenial.items.find(({ id }) => id === predecessor.id)).toMatchObject({
    generation: reauthorizationPredecessor.generation,
    credential_generation: reauthorizationPredecessor.credential_generation,
    revision: reauthorizationPredecessor.revision,
    state: "active",
  });

  const rejectedReauthorization = await control<ManagedReauthorization>(
    page.request,
    "POST",
    `projects/${context.project.id}/users/${userId}/managed-provider-connections/${predecessor.id}/reauthorizations`,
    {
      application_id: context.application.id,
      expected_connection_generation: reauthorizationPredecessor.generation,
      expected_connection_revision: reauthorizationPredecessor.revision,
      expected_credential_generation: reauthorizationPredecessor.credential_generation,
    },
    `managed-rejection-${browserName}-${Date.now().toString(36)}`,
  );
  if (rejectedReauthorization.hosted_target === undefined) {
    throw new Error("managed rejection omitted its create-only hosted target");
  }
  const rejectedManagedPage = await browserContext.newPage();
  const rejectedManagedSetCookies: string[] = [];
  const rejectedManagedHeaderReads: Promise<void>[] = [];
  rejectedManagedPage.on("response", (response) => {
    if (!response.url().startsWith(runtimeBase)) return;
    rejectedManagedHeaderReads.push(
      response.headersArray().then((headers) => {
        for (const { name, value } of headers) {
          if (name.toLowerCase() === "set-cookie") rejectedManagedSetCookies.push(value);
        }
      }),
    );
  });
  await rejectedManagedPage.goto(rejectedReauthorization.hosted_target);
  await expect(
    rejectedManagedPage.getByRole("heading", {
      name: "Reauthorize managed connection",
      exact: true,
    }),
    `managed rejection Hosted target remained on ${rejectedManagedPage.url()}`,
  ).toBeVisible({ timeout: 30_000 });
  await expect(rejectedManagedPage.getByRole("button")).toHaveCount(1);
  const countsBeforeManagedRejection = await providerRequestCounts(page.request);
  await armProviderCodeRejection(page.request);
  await rejectedManagedPage.getByRole("button").click();
  await expect(
    rejectedManagedPage.getByRole("heading", { name: "Reauthorization could not be completed" }),
  ).toBeVisible();
  const rejectedTerminalUrl = rejectedManagedPage.url();
  await Promise.all(rejectedManagedHeaderReads);
  const rejectedManagedCookieWrites = rejectedManagedSetCookies
    .map(parseSetCookie)
    .filter(({ name }) => runtimeCookieKind(name) === "interaction");
  const issuedRejectedManagedCookies = rejectedManagedCookieWrites.filter(
    ({ attributes, value }) => value !== "" && attributes.get("max-age") !== "0",
  );
  expect(issuedRejectedManagedCookies).toHaveLength(1);
  const rejectedBindingCookie = issuedRejectedManagedCookies[0];
  if (rejectedBindingCookie === undefined) throw new Error("rejected callback cookie missing");
  const rejectedManagedCookieName = rejectedBindingCookie.name;
  expect(
    rejectedManagedCookieWrites.some(
      ({ attributes, name, value }) =>
        name === rejectedManagedCookieName &&
        value === "deleted" &&
        attributes.get("max-age") === "0",
    ),
  ).toBe(true);
  const cookiesAfterManagedRejection = await browserContext.cookies(
    rejectedReauthorization.hosted_target,
  );
  expect(cookiesAfterManagedRejection.some(({ name }) => name === rejectedManagedCookieName)).toBe(
    false,
  );
  const countsAfterManagedRejection = await providerRequestCounts(page.request);
  expect(countsAfterManagedRejection.token_requests).toBe(
    countsBeforeManagedRejection.token_requests + 1,
  );
  const afterManagedRejection = await controlGet<ManagedConnectionList>(
    page.request,
    `projects/${context.project.id}/users/${userId}/managed-provider-connections`,
  );
  expect(afterManagedRejection.items.find(({ id }) => id === predecessor.id)).toMatchObject({
    generation: reauthorizationPredecessor.generation,
    credential_generation: reauthorizationPredecessor.credential_generation,
    revision: reauthorizationPredecessor.revision,
    state: "active",
  });
  await expect
    .poll(
      async () => {
        const current = await controlGet<ManagedReauthorization>(
          page.request,
          `projects/${context.project.id}/users/${userId}/managed-provider-connections/${predecessor.id}/reauthorizations/${rejectedReauthorization.id}`,
        );
        return current.status;
      },
      { timeout: 30_000 },
    )
    .toBe("provider_exchange_failed");
  await rejectedManagedPage.close();

  const reauthorization = await control<ManagedReauthorization>(
    page.request,
    "POST",
    `projects/${context.project.id}/users/${userId}/managed-provider-connections/${predecessor.id}/reauthorizations`,
    {
      application_id: context.application.id,
      expected_connection_generation: reauthorizationPredecessor.generation,
      expected_connection_revision: reauthorizationPredecessor.revision,
      expected_credential_generation: reauthorizationPredecessor.credential_generation,
    },
    `managed-reauthorization-${browserName}-${Date.now().toString(36)}`,
  );
  expect(reauthorization.status).toBe("awaiting_browser_binding");
  if (reauthorization.hosted_target === undefined) {
    throw new Error("managed reauthorization omitted its create-only hosted target");
  }
  const successfulManagedContext = await browser.newContext();
  const managedPage = await successfulManagedContext.newPage();
  const successfulManagedSetCookies: string[] = [];
  const successfulManagedHeaderReads: Promise<void>[] = [];
  managedPage.on("response", (response) => {
    if (!response.url().startsWith(runtimeBase)) return;
    successfulManagedHeaderReads.push(
      response.headersArray().then((headers) => {
        for (const { name, value } of headers) {
          if (name.toLowerCase() === "set-cookie") successfulManagedSetCookies.push(value);
        }
      }),
    );
  });
  await managedPage.goto(reauthorization.hosted_target);
  await expect(
    managedPage.getByRole("heading", { name: "Reauthorize managed connection", exact: true }),
  ).toBeVisible();
  await expect(managedPage.getByText("does not sign you in to an Application")).toBeVisible();
  await expect(managedPage.getByRole("button")).toHaveCount(1);
  await managedPage.getByRole("button").click();
  await expect
    .poll(
      async () => {
        const current = await controlGet<ManagedReauthorization>(
          page.request,
          `projects/${context.project.id}/users/${userId}/managed-provider-connections/${predecessor.id}/reauthorizations/${reauthorization.id}`,
        );
        return current.status;
      },
      { timeout: 30_000 },
    )
    .toBe("completed");
  const successfulTerminalUrl = managedPage.url();
  await Promise.all(successfulManagedHeaderReads);
  const issuedSuccessfulManagedCookies = successfulManagedSetCookies
    .map(parseSetCookie)
    .filter(
      ({ attributes, name, value }) =>
        runtimeCookieKind(name) === "interaction" &&
        value !== "" &&
        attributes.get("max-age") !== "0",
    );
  expect(issuedSuccessfulManagedCookies).toHaveLength(1);
  const successfulBindingCookie = issuedSuccessfulManagedCookies[0];
  if (successfulBindingCookie === undefined) throw new Error("successful callback cookie missing");
  const managedAfter = await controlGet<ManagedConnectionList>(
    page.request,
    `projects/${context.project.id}/users/${userId}/managed-provider-connections`,
  );
  const successor = managedAfter.items.find(({ id }) => id === predecessor.id);
  expect(successor?.state).toBe("active");
  expect(successor?.generation).toBe(reauthorizationPredecessor.generation + 1);
  expect(successor?.credential_generation).toBe(
    reauthorizationPredecessor.credential_generation + 1,
  );
  if (successor === undefined) throw new Error("managed successor was not visible");
  const countsBeforeSuccessfulRetry = await providerRequestCounts(page.request);
  const successfulRetryContext = await browser.newContext();
  const successfulRetryResponse = await successfulRetryContext.request.get(successfulTerminalUrl, {
    headers: {
      cookie: `${successfulBindingCookie.name}=${successfulBindingCookie.value}`,
    },
  });
  expect(successfulRetryResponse.ok()).toBe(true);
  expect(await successfulRetryResponse.text()).toContain("managed_reauthorization");
  const successfulRetrySetCookies = successfulRetryResponse
    .headersArray()
    .filter(({ name }) => name.toLowerCase() === "set-cookie")
    .map(({ value }) => parseSetCookie(value));
  await successfulRetryContext.close();
  expect(await providerRequestCounts(page.request)).toEqual(countsBeforeSuccessfulRetry);
  const afterSuccessfulRetry = await controlGet<ManagedConnectionList>(
    page.request,
    `projects/${context.project.id}/users/${userId}/managed-provider-connections`,
  );
  expect(afterSuccessfulRetry.items.find(({ id }) => id === successor.id)).toMatchObject({
    generation: successor.generation,
    credential_generation: successor.credential_generation,
    revision: successor.revision,
    state: "active",
  });
  expect(
    successfulRetrySetCookies.some(
      ({ attributes, name }) =>
        name === successfulBindingCookie.name && attributes.get("max-age") === "0",
    ),
  ).toBe(true);

  // Retry the earlier failed terminal callback only after successful completion evidence has been
  // captured. The isolated client restores exactly its HttpOnly binding, receives the bounded
  // failure and deletion header, and cannot replay provider or connection effects.
  const countsBeforeRejectedRetry = await providerRequestCounts(page.request);
  const beforeRejectedRetry = await controlGet<ManagedConnectionList>(
    page.request,
    `projects/${context.project.id}/users/${userId}/managed-provider-connections`,
  );
  const rejectedRetryContext = await browser.newContext();
  const rejectedRetryResponse = await rejectedRetryContext.request.get(rejectedTerminalUrl, {
    headers: {
      cookie: `${rejectedBindingCookie.name}=${rejectedBindingCookie.value}`,
    },
  });
  expect(rejectedRetryResponse.ok()).toBe(true);
  expect(await rejectedRetryResponse.text()).toContain("Reauthorization could not be completed");
  const rejectedRetrySetCookies = rejectedRetryResponse
    .headersArray()
    .filter(({ name }) => name.toLowerCase() === "set-cookie")
    .map(({ value }) => parseSetCookie(value));
  await rejectedRetryContext.close();
  expect(await providerRequestCounts(page.request)).toEqual(countsBeforeRejectedRetry);
  const afterRejectedRetry = await controlGet<ManagedConnectionList>(
    page.request,
    `projects/${context.project.id}/users/${userId}/managed-provider-connections`,
  );
  expect(afterRejectedRetry.items.find(({ id }) => id === predecessor.id)).toEqual(
    beforeRejectedRetry.items.find(({ id }) => id === predecessor.id),
  );
  expect(
    rejectedRetrySetCookies.some(
      ({ attributes, name }) =>
        name === rejectedBindingCookie.name && attributes.get("max-age") === "0",
    ),
  ).toBe(true);
  await successfulManagedContext.close();

  const revocationRequested = await control<ManagedConnection>(
    page.request,
    "POST",
    `projects/${context.project.id}/users/${userId}/managed-provider-connections/${successor.id}/revoke`,
    {
      confirm: true,
      expected_generation: successor.generation,
      expected_revision: successor.revision,
    },
  );
  expect(revocationRequested.state).toBe("active");
  await expect
    .poll(
      async () => {
        const list = await controlGet<ManagedConnectionList>(
          page.request,
          `projects/${context.project.id}/users/${userId}/managed-provider-connections`,
        );
        return list.items.find(({ id }) => id === successor.id);
      },
      { timeout: 45_000 },
    )
    .toMatchObject({ state: "revoked" });
  const revokedList = await controlGet<ManagedConnectionList>(
    page.request,
    `projects/${context.project.id}/users/${userId}/managed-provider-connections`,
  );
  const revokedConnection = revokedList.items.find(({ id }) => id === successor.id);
  if (revokedConnection === undefined) throw new Error("revoked connection disappeared");
  const disconnected = await control<ManagedConnection>(
    page.request,
    "POST",
    `projects/${context.project.id}/users/${userId}/managed-provider-connections/${successor.id}/disconnect`,
    {
      confirm: true,
      expected_generation: revokedConnection.generation,
      expected_revision: revokedConnection.revision,
    },
  );
  expect(disconnected.state).toBe("disconnected");

  // Disconnection destroys the predecessor material but intentionally leaves explicit Hosted
  // reauthorization available. Only that exact successor transaction may return the connection
  // to active, with both lifecycle generations advanced.
  const disconnectedRecovery = await control<ManagedReauthorization>(
    page.request,
    "POST",
    `projects/${context.project.id}/users/${userId}/managed-provider-connections/${successor.id}/reauthorizations`,
    {
      application_id: context.application.id,
      expected_connection_generation: disconnected.generation,
      expected_connection_revision: disconnected.revision,
      expected_credential_generation: disconnected.credential_generation,
    },
    `managed-disconnected-recovery-${browserName}-${Date.now().toString(36)}`,
  );
  expect(disconnectedRecovery.status).toBe("awaiting_browser_binding");
  if (disconnectedRecovery.hosted_target === undefined) {
    throw new Error("disconnected recovery omitted its create-only Hosted target");
  }
  const disconnectedRecoveryPage = await browserContext.newPage();
  await disconnectedRecoveryPage.goto(disconnectedRecovery.hosted_target);
  await expect(
    disconnectedRecoveryPage.getByRole("heading", {
      name: "Reauthorize managed connection",
      exact: true,
    }),
  ).toBeVisible();
  await expect(disconnectedRecoveryPage.getByRole("button")).toHaveCount(1);
  await disconnectedRecoveryPage.getByRole("button").click();
  await expect
    .poll(
      async () => {
        const current = await controlGet<ManagedReauthorization>(
          page.request,
          `projects/${context.project.id}/users/${userId}/managed-provider-connections/${successor.id}/reauthorizations/${disconnectedRecovery.id}`,
        );
        return current.status;
      },
      { timeout: 30_000 },
    )
    .toBe("completed");
  const recoveredConnections = await controlGet<ManagedConnectionList>(
    page.request,
    `projects/${context.project.id}/users/${userId}/managed-provider-connections`,
  );
  const recovered = recoveredConnections.items.find(({ id }) => id === successor.id);
  expect(recovered).toMatchObject({ state: "active" });
  expect(recovered?.generation).toBe(disconnected.generation + 1);
  expect(recovered?.credential_generation).toBe(disconnected.credential_generation + 1);
  await disconnectedRecoveryPage.close();

  await page.getByRole("button", { name: "Refresh session" }).click();
  await expect(page.locator("#status")).toHaveText("Credentials replaced atomically");
  await expect(page.locator("output")).toHaveText("generation 2");

  await evidence.settle();
  await assertPageSecretFree(page, await currentSecrets(evidence));

  await page.getByRole("button", { name: "Application logout" }).click();
  await expect(page.locator("#status")).toHaveText("Application session ended");

  const countsBeforeReuse = await providerRequestCounts(page.request);
  const reusePopupReady = page.waitForEvent("popup", { timeout: 30_000 });
  await page.getByRole("button", { name: "Start browser sign-in" }).click();
  const reusePopup = await reusePopupReady;
  await expect(reusePopup.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  await expect(
    reusePopup.getByRole("button", {
      name: "Continue with Controlled Provider",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    reusePopup.getByRole("button", { name: "Continue with current session", exact: true }),
  ).toBeVisible();
  const reuseBootstrap = await observedBootstrap(evidence, reusePopup.url());
  await assertPageSecretFree(reusePopup, await currentSecrets(evidence));
  const reuseResults = await raceHostedMutation(
    reusePopup,
    `${runtimeBase}v1/projects/${encodeURIComponent(context.project.public_id)}/auth/interactions/${encodeURIComponent(interactionHandle(reusePopup.url()))}/session/reuse`,
    { csrf: reuseBootstrap.csrf, expected_revision: reuseBootstrap.revision },
  );
  const successfulReuse = reuseResults.filter(({ status }) => status === 200);
  expect(successfulReuse).toHaveLength(1);
  expect(reuseResults.filter(({ status }) => status !== 200)).toHaveLength(1);
  const reuseNavigation = parseNavigationUrl(successfulReuse[0]?.body);
  await reusePopup.evaluate((target) => {
    location.replace(target);
  }, reuseNavigation);
  await expect(page.locator("#status")).toHaveText("Browser session ready");
  await expect(page.locator("output")).toHaveText("generation 1");
  expect(await providerRequestCounts(page.request)).toEqual(countsBeforeReuse);

  const browserLogoutPopupReady = page.waitForEvent("popup", { timeout: 30_000 });
  await page.getByRole("button", { name: "Project browser logout" }).click();
  const browserLogoutPopup = await browserLogoutPopupReady;
  await expect(
    browserLogoutPopup.getByRole("heading", { name: "Sign out", exact: true }),
  ).toBeVisible();
  await expect(
    browserLogoutPopup.getByRole("heading", { name: "Sign out of this Project?" }),
  ).toBeVisible();
  await observedBootstrap(evidence, browserLogoutPopup.url());
  await evidence.settle();
  await assertPageSecretFree(browserLogoutPopup, await currentSecrets(evidence));
  await browserLogoutPopup.getByRole("button", { name: "Confirm sign out" }).click();
  await expect(browserLogoutPopup.getByRole("heading", { name: "Signed out" })).toBeVisible();
  await expect(
    browserLogoutPopup.getByText("Your Project browser session has ended."),
  ).toBeVisible();
  await evidence.settle();
  await assertPageSecretFree(browserLogoutPopup, await currentSecrets(evidence));

  await page.getByRole("button", { name: "Verify browser logout" }).click();
  await expect(page.locator("#status")).toHaveText(
    "Browser logout confirmed; refresh rejected; caller state cleared",
  );

  const countsAfterLogout = await providerRequestCounts(page.request);
  expect(countsAfterLogout).toEqual(countsBeforeReuse);
  const afterLogoutPopupReady = page.waitForEvent("popup", { timeout: 30_000 });
  await page.getByRole("button", { name: "Start browser sign-in" }).click();
  const afterLogoutPopup = await afterLogoutPopupReady;
  await expect(afterLogoutPopup.getByRole("heading", { name: "E2E Application" })).toBeVisible();
  await expect(
    afterLogoutPopup.getByRole("button", {
      name: "Continue with Controlled Provider",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    afterLogoutPopup.getByRole("button", {
      name: "Continue with current session",
      exact: true,
    }),
  ).toHaveCount(0);
  const afterLogoutBootstrap = await observedBootstrap(evidence, afterLogoutPopup.url());
  const rejectedReuse = await hostedMutation(
    afterLogoutPopup,
    `${runtimeBase}v1/projects/${encodeURIComponent(context.project.public_id)}/auth/interactions/${encodeURIComponent(interactionHandle(afterLogoutPopup.url()))}/session/reuse`,
    { csrf: afterLogoutBootstrap.csrf, expected_revision: afterLogoutBootstrap.revision },
  );
  expect(rejectedReuse.status).not.toBe(200);
  expect(await providerRequestCounts(page.request)).toEqual(countsAfterLogout);
  await evidence.settle();
  const browserSnapshots = await assertEvidenceConfinement([evidence]);
  expect(new Set(evidenceSecrets(browserSnapshots).map(({ kind }) => kind))).toEqual(
    new Set<SecretKind>(["access", "csrf", "handoff", "preparation", "refresh"]),
  );
  expect(new Set(runtimeCookieSecrets(browserSnapshots).map(({ kind }) => kind))).toEqual(
    new Set<RuntimeCookieKind>(["interaction", "project"]),
  );
  await afterLogoutPopup.close();

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

  const backendContext = await completeBackendCustodyJourney(page, browserName);
  await completeSdkQualification(page, evidence, browserName, context, backendContext);
});

test("browser evidence rejects unreviewed secret and cookie placements", async ({ browser }) => {
  const handoff: SecretValue = {
    kind: "handoff",
    value: "handoff-negative-fixture-value",
  };
  const refresh: SecretValue = {
    kind: "refresh",
    value: "refresh-negative-fixture-value",
  };
  const access: SecretValue = {
    kind: "access",
    value: "access-negative-fixture-value",
  };
  const wrongOrigin = "https://attacker.example/v1/projects/project/auth/handoff/exchange";
  expect(() => {
    assertRequestConfinement(
      {
        body: JSON.stringify({ handoff: handoff.value }),
        headers: [],
        method: "POST",
        url: wrongOrigin,
      },
      [handoff],
    );
  }).toThrow();
  expect(() => {
    assertResponseConfinement(
      {
        body: JSON.stringify({ refresh_token: refresh.value }),
        headers: [],
        method: "POST",
        status: 200,
        url: "https://attacker.example/v1/projects/project/auth/sessions/refresh",
      },
      [refresh],
    );
  }).toThrow();
  expect(() => {
    assertRequestConfinement(
      {
        body: "",
        headers: [{ name: "authorization", value: `Bearer ${access.value}` }],
        method: "GET",
        url: runtimeFixtureUrl("v1/projects/project/auth/config"),
      },
      [access],
    );
  }).toThrow();

  const interactionName = `owl_runtime_${"a".repeat(24)}`;
  const projectName = `owl_project_${"b".repeat(24)}`;
  const interactionRoute = runtimeFixtureUrl("auth/interactions/interaction-fixture");
  const projectRouteUrl = runtimeFixtureUrl("projects/project/auth/callback/provider");
  const validAttributes = `Path=${runtimeCookiePath()}; Secure; HttpOnly; SameSite=Lax`;
  const invalidCookieLines = [
    `${interactionName}=interaction-cookie-value; Path=${runtimeCookiePath()}; Max-Age=600; Secure; HttpOnly; SameSite=Lax; Domain=${runtimeUrl().hostname}`,
    `${interactionName}=interaction-cookie-value; Path=${runtimeCookiePath()}; Max-Age=86400; Secure; HttpOnly; SameSite=Lax`,
    `${projectName}=project-cookie-value; Path=${runtimeCookiePath()}; Max-Age=600; Secure; HttpOnly; SameSite=Lax`,
    `${interactionName}=interaction-cookie-value; Path=${runtimeCookiePath()}; Max-Age=600; Secure; HttpOnly; SameSite=Lax; Priority=High`,
  ] as const;
  for (const [index, line] of invalidCookieLines.entries()) {
    const url = index === 2 ? projectRouteUrl : interactionRoute;
    expect(() => runtimeCookieSecrets([cookieFixtureSnapshot(url, line)])).toThrow();
  }
  expect(() =>
    runtimeCookieSecrets([
      cookieFixtureSnapshot(
        runtimeFixtureUrl("v1/projects/project/auth/interactions/interaction/session/reuse"),
        `${interactionName}=deleted; Max-Age=0; ${validAttributes}`,
        "POST",
      ),
    ]),
  ).toThrow();

  const context = await browser.newContext();
  try {
    const evidence = await BrowserEvidence.create(context);
    const page = await context.newPage();
    await page.goto(`${applicationOrigin}/sdk/callback`);
    const transient: SecretValue = {
      kind: "access",
      value: "same-task-transient-dom-secret",
    };
    await page.evaluate((value) => {
      const node = document.createElement("span");
      node.textContent = value;
      document.body.appendChild(node);
      node.remove();
    }, transient.value);
    await expect
      .poll(() =>
        evidence.lifecycle.some(
          ({ body, html }) => body.includes(transient.value) || html.includes(transient.value),
        ),
      )
      .toBe(true);
    const snapshot = await evidence.snapshot();
    expect(() => {
      for (const sample of snapshot.lifecycle) assertLifecycleConfinement(sample, [transient]);
    }).toThrow();
  } finally {
    await context.close();
  }
});

function runtimeFixtureUrl(path: string): string {
  return new URL(
    path,
    runtimeCookiePath() === "/" ? runtimeBase : `${runtimeUrl().origin}${runtimeCookiePath()}`,
  ).href;
}

function cookieFixtureSnapshot(
  url: string,
  setCookie: string,
  method = "GET",
): BrowserEvidenceSnapshot {
  return {
    consoleMessages: [],
    lifecycle: [],
    pageCount: 1,
    requests: [],
    responses: [
      {
        body: "",
        headers: [{ name: "set-cookie", value: setCookie }],
        method,
        status: 200,
        url,
      },
    ],
    storageState: '{"cookies":[],"origins":[]}',
  };
}

async function armProviderDenial(request: APIRequestContext): Promise<void> {
  const response = await request.post(`${providerOrigin}__e2e/deny-next-authorization`);
  expect(response.ok()).toBe(true);
}

async function armProviderCodeRejection(request: APIRequestContext): Promise<void> {
  const response = await request.post(`${providerOrigin}__e2e/reject-next-code-exchange`);
  expect(response.ok()).toBe(true);
}

async function providerRequestCounts(request: APIRequestContext): Promise<ProviderRequestCounts> {
  const response = await request.get(`${providerOrigin}__e2e/request-counts`);
  expect(response.ok()).toBe(true);
  const document = (await response.json()) as Partial<ProviderRequestCounts>;
  expect(typeof document.authorization_requests).toBe("number");
  expect(typeof document.token_requests).toBe("number");
  return document as ProviderRequestCounts;
}

function parseJsonObject(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function parseHostedBootstrap(document: string): HostedBootstrap | null {
  const tag = /<meta\s+[^>]*name="owlauth-runtime-bootstrap"[^>]*>/iu.exec(document)?.[0];
  const encoded = tag === undefined ? undefined : /\scontent="([^"]*)"/iu.exec(tag)?.[1];
  if (encoded === undefined) return null;
  const decoded = encoded
    .replaceAll("&quot;", '"')
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");
  const parsed = parseJsonObject(decoded);
  if (
    typeof parsed?.["csrf"] !== "string" ||
    parsed["csrf"].length < 16 ||
    typeof parsed["project_id"] !== "string" ||
    typeof parsed["revision"] !== "number" ||
    !Number.isSafeInteger(parsed["revision"])
  ) {
    return null;
  }
  return {
    csrf: parsed["csrf"],
    project_id: parsed["project_id"],
    revision: parsed["revision"],
  };
}

function interactionHandle(value: string): string {
  const segment = new URL(value).pathname.split("/").at(-1);
  if (segment === undefined || !/^[A-Za-z0-9._-]{16,256}$/u.test(segment)) {
    throw new Error("Hosted interaction URL did not contain a bounded opaque handle");
  }
  return segment;
}

async function hostedMutation(
  page: Page,
  url: string,
  body: Readonly<Record<string, unknown>>,
): Promise<MutationResult> {
  return page.evaluate(
    async ({ target, document }) => {
      const response = await fetch(target, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(document),
      });
      const text = await response.text();
      let parsed: unknown = null;
      try {
        parsed = JSON.parse(text) as unknown;
      } catch {
        parsed = text;
      }
      return { body: parsed, status: response.status };
    },
    { target: url, document: body },
  );
}

async function raceHostedMutation(
  page: Page,
  url: string,
  body: Readonly<Record<string, unknown>>,
): Promise<readonly [MutationResult, MutationResult]> {
  return page.evaluate(
    async ({ target, document }) => {
      const submit = async () => {
        const response = await fetch(target, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(document),
        });
        const text = await response.text();
        let parsed: unknown = null;
        try {
          parsed = JSON.parse(text) as unknown;
        } catch {
          parsed = text;
        }
        return { body: parsed, status: response.status };
      };
      return Promise.all([submit(), submit()]);
    },
    { target: url, document: body },
  );
}

function parseNavigationUrl(value: unknown): string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("successful Hosted mutation omitted its navigation document");
  }
  const target = (value as Record<string, unknown>)["url"];
  if (typeof target !== "string" || target.length > 4096) {
    throw new Error("successful Hosted mutation returned an invalid navigation URL");
  }
  const parsed = new URL(target);
  if (parsed.origin !== applicationOrigin || parsed.pathname !== "/browser/callback") {
    throw new Error("successful reuse escaped the controlled Application callback");
  }
  return parsed.href;
}

async function observedBootstrap(evidence: BrowserEvidence, url: string): Promise<HostedBootstrap> {
  await expect
    .poll(
      async () => {
        await evidence.settle();
        return evidence.responses
          .filter((record) => record.url === url)
          .map((record) => parseHostedBootstrap(record.body))
          .find((bootstrap) => bootstrap !== null);
      },
      { timeout: 10_000 },
    )
    .toBeDefined();
  const bootstrap = evidence.responses
    .filter((record) => record.url === url)
    .map((record) => parseHostedBootstrap(record.body))
    .find((candidate) => candidate !== null);
  if (bootstrap === undefined) throw new Error("Hosted bootstrap observation disappeared");
  return bootstrap;
}

async function assertEvidenceConfinement(
  evidences: readonly BrowserEvidence[],
  additionalSnapshots: readonly BrowserEvidenceSnapshot[] = [],
): Promise<readonly BrowserEvidenceSnapshot[]> {
  const snapshots = [
    ...(await Promise.all(evidences.map(async (evidence) => evidence.snapshot()))),
    ...additionalSnapshots,
  ];
  const secrets = evidenceSecrets(snapshots);
  const runtimeCookies = runtimeCookieSecrets(snapshots);
  expect(runtimeCookies.length, "no Runtime browser cookie evidence was captured").toBeGreaterThan(
    0,
  );

  for (const snapshot of snapshots) {
    expect(snapshot.pageCount, "browser context evidence did not own any page").toBeGreaterThan(0);
    const consoleDocument = snapshot.consoleMessages.join("\n");
    for (const secret of secrets) {
      expect(
        !consoleDocument.includes(secret.value),
        `${secret.kind} escaped into a browser console message`,
      ).toBe(true);
      expect(
        !snapshot.storageState.includes(secret.value),
        `${secret.kind} escaped into final browser-context storage state`,
      ).toBe(true);
    }
    for (const record of snapshot.requests) assertRequestConfinement(record, secrets);
    for (const record of snapshot.responses) assertResponseConfinement(record, secrets);
    for (const sample of snapshot.lifecycle) assertLifecycleConfinement(sample, secrets);
    assertRuntimeCookieConfinement(snapshot, runtimeCookies);
    const initializedPages = new Set(
      snapshot.lifecycle
        .filter(({ reason }) => reason !== "navigation" && reason !== "final")
        .map(({ pageId }) => pageId),
    );
    expect(
      initializedPages.size,
      "init-script lifecycle observation did not cover every browser page",
    ).toBe(snapshot.pageCount);
  }
  return snapshots;
}

function evidenceSecrets(snapshots: readonly BrowserEvidenceSnapshot[]): readonly SecretValue[] {
  const remembered = new Map<string, SecretValue>();
  const remember = (kind: SecretKind, value: unknown): void => {
    if (typeof value !== "string" || value.length < 16) return;
    remembered.set(`${kind}:${value}`, { kind, value });
  };
  const captureHandoff = (value: string): void => {
    try {
      remember("handoff", new URL(value).searchParams.get("handoff"));
    } catch {
      // Only absolute observed URLs are relevant.
    }
  };

  for (const snapshot of snapshots) {
    for (const record of [...snapshot.requests, ...snapshot.responses]) {
      captureHandoff(record.url);
      let url: URL;
      try {
        url = new URL(record.url);
      } catch {
        continue;
      }
      const document = parseJsonObject(record.body);
      if (
        isRuntimeRecord(record, url, "POST", projectRoute("auth/handoff/exchange")) ||
        isRuntimeRecord(record, url, "POST", projectRoute("auth/sessions/refresh"))
      ) {
        remember("access", document?.["access_token"]);
        remember("refresh", document?.["refresh_token"]);
      }
      if (isRuntimeRecord(record, url, "POST", projectRoute("auth/browser-logout/prepare"))) {
        const hostedUrl = document?.["hosted_url"];
        if (typeof hostedUrl === "string") {
          try {
            const parsed = new URL(hostedUrl);
            const preparation = runtimeRouteMatch(parsed, /^auth\/browser-logout\/([^/]+)$/u)?.[1];
            remember("preparation", preparation);
          } catch {
            // Invalid navigation is rejected by the SDK; evidence collection remains passive.
          }
        }
      }
      if (
        isRuntimeRecord(
          record,
          url,
          "POST",
          projectRoute("auth/interactions/[^/]+/session/reuse"),
        ) &&
        typeof document?.["url"] === "string"
      ) {
        captureHandoff(document["url"]);
      }
      if (isRuntimeRecord(record, url, "GET", /^auth\/(?:interactions|browser-logout)\/[^/]+$/u)) {
        const bootstrap = parseHostedBootstrap(record.body);
        if (bootstrap !== null) remember("csrf", bootstrap.csrf);
      }
    }
  }
  return [...remembered.values()];
}

function runtimeCookieSecrets(
  snapshots: readonly BrowserEvidenceSnapshot[],
): readonly RuntimeCookieSecret[] {
  const expectedPath = runtimeCookiePath();
  const secrets = new Map<string, RuntimeCookieSecret>();
  const events: RuntimeCookieEvent[] = [];
  for (const snapshot of snapshots) {
    for (const response of snapshot.responses) {
      for (const header of response.headers) {
        if (header.name.toLowerCase() !== "set-cookie") continue;
        const parsed = parseSetCookie(header.value);
        const kind = runtimeCookieKind(parsed.name);
        if (runtimeCookieCandidate(parsed.name)) {
          expect(kind, `${parsed.name} did not use an exact Runtime cookie name`).not.toBeNull();
        }
        if (kind === null) continue;
        const disposition = parsed.value === "deleted" ? "deletion" : "issuance";
        assertRuntimeCookieLine(response, parsed, kind, disposition, expectedPath);
        events.push({ disposition, kind, name: parsed.name, value: parsed.value });
        if (disposition === "issuance") {
          secrets.set(`${parsed.name}:${parsed.value}`, {
            kind,
            name: parsed.name,
            path: expectedPath,
            value: parsed.value,
          });
        }
      }
    }
  }

  const issuedNames = new Set(
    events.filter(({ disposition }) => disposition === "issuance").map(({ name }) => name),
  );
  for (const event of events) {
    if (event.disposition === "deletion") {
      expect(
        issuedNames.has(event.name),
        `${event.kind} cookie deletion was not correlated with an observed issuance`,
      ).toBe(true);
    }
  }
  return [...secrets.values()];
}

function assertRuntimeCookieLine(
  response: NetworkRecord,
  parsed: ParsedSetCookie,
  kind: RuntimeCookieKind,
  disposition: RuntimeCookieEvent["disposition"],
  expectedPath: string,
): void {
  const expectedAttributes = new Set(["httponly", "max-age", "path", "samesite", "secure"]);
  expect(
    new Set(parsed.attributes.keys()),
    `${parsed.name} used missing, Domain, or unexpected cookie attributes`,
  ).toEqual(expectedAttributes);
  expect(parsed.attributes.get("path"), `${parsed.name} used the wrong Path`).toBe(expectedPath);
  expect(parsed.attributes.get("secure"), `${parsed.name} omitted Secure`).toBe("");
  expect(parsed.attributes.get("httponly"), `${parsed.name} omitted HttpOnly`).toBe("");
  expect(parsed.attributes.get("samesite"), `${parsed.name} used the wrong SameSite`).toBe("Lax");

  const expectedMaxAge =
    disposition === "deletion" ? "0" : kind === "interaction" ? "600" : "86400";
  expect(
    parsed.attributes.get("max-age"),
    `${parsed.name} used the wrong kind-specific Max-Age`,
  ).toBe(expectedMaxAge);
  if (disposition === "issuance") {
    expect(
      parsed.value.length,
      `${parsed.name} had a short credential value`,
    ).toBeGreaterThanOrEqual(16);
  }

  let url: URL;
  try {
    url = new URL(response.url);
  } catch {
    throw new Error(`${parsed.name} was set on a malformed response URL`);
  }
  expect(
    isRuntimeCookieRoute(response, url, kind, disposition),
    `${parsed.name} ${disposition} used an unreviewed Runtime origin, route, or method`,
  ).toBe(true);
}

function isRuntimeCookieRoute(
  record: NetworkRecord,
  url: URL,
  kind: RuntimeCookieKind,
  disposition: RuntimeCookieEvent["disposition"],
): boolean {
  const providerCallback = /^projects\/[^/]+\/auth\/callback\/[^/]+$/u;
  if (kind === "interaction" && disposition === "issuance") {
    return isRuntimeRecord(
      record,
      url,
      "GET",
      /^auth\/(?:interactions|managed-reauthorizations)\/[^/]+$/u,
    );
  }
  if (kind === "interaction") {
    return (
      isRuntimeRecord(record, url, "GET", providerCallback) ||
      isRuntimeRecord(record, url, "POST", projectRoute("auth/interactions/[^/]+/session/reuse"))
    );
  }
  if (disposition === "issuance") {
    return isRuntimeRecord(record, url, "GET", providerCallback);
  }
  return isRuntimeRecord(record, url, "POST", projectRoute("auth/browser-logout/[^/]+/confirm"));
}

function assertRuntimeCookieConfinement(
  snapshot: BrowserEvidenceSnapshot,
  secrets: readonly RuntimeCookieSecret[],
): void {
  const runtimeOrigin = runtimeUrl().origin;
  for (const secret of secrets) {
    const consoleDocument = snapshot.consoleMessages.join("\n");
    expect(consoleDocument, `${secret.kind} cookie escaped into browser console`).not.toContain(
      secret.value,
    );
    for (const request of snapshot.requests) {
      expect(request.url, `${secret.kind} cookie escaped into a request URL`).not.toContain(
        secret.value,
      );
      expect(request.body, `${secret.kind} cookie escaped into a request body`).not.toContain(
        secret.value,
      );
      for (const header of request.headers) {
        if (!header.value.includes(secret.value)) continue;
        expect(header.name.toLowerCase(), `${secret.kind} cookie used a non-Cookie header`).toBe(
          "cookie",
        );
        expect(
          parseCookieHeader(header.value).get(secret.name),
          `${secret.kind} cookie header did not preserve its exact name/value pair`,
        ).toBe(secret.value);
        const requestUrl = new URL(request.url);
        expect(requestUrl.origin, `${secret.kind} cookie escaped the Runtime origin`).toBe(
          runtimeOrigin,
        );
        expect(
          pathContains(secret.path, requestUrl.pathname),
          `${secret.kind} cookie escaped its Runtime Path`,
        ).toBe(true);
      }
    }
    for (const response of snapshot.responses) {
      expect(response.url, `${secret.kind} cookie escaped into a response URL`).not.toContain(
        secret.value,
      );
      expect(response.body, `${secret.kind} cookie escaped into a response body`).not.toContain(
        secret.value,
      );
      for (const header of response.headers) {
        if (!header.value.includes(secret.value)) continue;
        expect(
          header.name.toLowerCase(),
          `${secret.kind} cookie used a non-Set-Cookie response header`,
        ).toBe("set-cookie");
        const parsed = parseSetCookie(header.value);
        expect(parsed.name).toBe(secret.name);
        expect(parsed.value).toBe(secret.value);
        expect(new URL(response.url).origin, `${secret.kind} cookie was set outside Runtime`).toBe(
          runtimeOrigin,
        );
      }
    }
    for (const sample of snapshot.lifecycle) {
      for (const [surface, document] of [
        ["page URL", sample.url],
        ["DOM", sample.html],
        ["page text", sample.body],
        ["history.state", sample.history],
        ["document.cookie", sample.cookies],
        ["localStorage", JSON.stringify(sample.local)],
        ["sessionStorage", JSON.stringify(sample.session)],
      ] as const) {
        expect(document, `${secret.kind} HttpOnly cookie escaped into ${surface}`).not.toContain(
          secret.value,
        );
      }
    }
  }

  const stored = parseStorageCookies(snapshot.storageState);
  for (const cookie of stored) {
    const kind = runtimeCookieKind(cookie.name);
    if (runtimeCookieCandidate(cookie.name)) {
      expect(kind, `${cookie.name} did not use an exact Runtime cookie name`).not.toBeNull();
    }
    if (kind === null) continue;
    const issued = secrets.find(
      ({ name, value }) => name === cookie.name && value === cookie.value,
    );
    expect(issued, `${kind} cookie in storage was not observed in a Set-Cookie line`).toBeDefined();
    expect(cookie.domain).toBe(runtimeUrl().hostname);
    expect(cookie.path).toBe(runtimeCookiePath());
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.secure).toBe(true);
    expect(cookie.sameSite).toBe("Lax");
  }

  for (const request of snapshot.requests) {
    for (const header of request.headers) {
      if (header.name.toLowerCase() !== "cookie") continue;
      for (const [name, value] of parseCookieHeader(header.value)) {
        const kind = runtimeCookieKind(name);
        if (runtimeCookieCandidate(name)) {
          expect(kind, `${name} did not use an exact Runtime cookie name`).not.toBeNull();
        }
        if (kind === null) continue;
        const issued = secrets.find((secret) => secret.name === name && secret.value === value);
        expect(
          issued,
          `${kind} request cookie was not observed in Set-Cookie evidence`,
        ).toBeDefined();
        const requestUrl = new URL(request.url);
        expect(requestUrl.origin, `${kind} cookie reached a non-Runtime plane`).toBe(runtimeOrigin);
        expect(
          issued === undefined ? false : pathContains(issued.path, requestUrl.pathname),
          `${kind} request cookie escaped its Runtime Path`,
        ).toBe(true);
      }
    }
  }
}

function runtimeCookieKind(name: string): RuntimeCookieKind | null {
  if (/^owl_runtime_[A-Za-z0-9_-]{24}$/u.test(name)) return "interaction";
  if (/^owl_project_[A-Za-z0-9_-]{24}$/u.test(name)) return "project";
  return null;
}

function runtimeCookieCandidate(name: string): boolean {
  return name.startsWith("owl_runtime_") || name.startsWith("owl_project_");
}

function parseSetCookie(value: string): ParsedSetCookie {
  const [pair, ...attributeParts] = value.split(";");
  const separator = pair?.indexOf("=") ?? -1;
  if (pair === undefined || separator <= 0) throw new Error("malformed Set-Cookie evidence");
  const attributes = new Map<string, string>();
  for (const part of attributeParts) {
    const trimmed = part.trim();
    const attributeSeparator = trimmed.indexOf("=");
    const name = (
      attributeSeparator === -1 ? trimmed : trimmed.slice(0, attributeSeparator)
    ).toLowerCase();
    if (name === "" || attributes.has(name)) {
      throw new Error("malformed or duplicate Set-Cookie attribute evidence");
    }
    attributes.set(name, attributeSeparator === -1 ? "" : trimmed.slice(attributeSeparator + 1));
  }
  return {
    attributes,
    name: pair.slice(0, separator).trim(),
    value: pair.slice(separator + 1),
  };
}

function parseCookieHeader(value: string): ReadonlyMap<string, string> {
  const cookies = new Map<string, string>();
  for (const part of value.split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) throw new Error("malformed Cookie evidence");
    const name = part.slice(0, separator).trim();
    if (cookies.has(name)) throw new Error("duplicate Cookie name evidence");
    cookies.set(name, part.slice(separator + 1));
  }
  return cookies;
}

function parseStorageCookies(storageState: string): readonly {
  readonly domain: string;
  readonly httpOnly: boolean;
  readonly name: string;
  readonly path: string;
  readonly sameSite: string;
  readonly secure: boolean;
  readonly value: string;
}[] {
  const parsed = JSON.parse(storageState) as unknown;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("malformed browser storage-state evidence");
  }
  const cookies = (parsed as Record<string, unknown>)["cookies"];
  if (!Array.isArray(cookies)) throw new Error("browser storage-state omitted cookies");
  return cookies as ReturnType<typeof parseStorageCookies>;
}

function pathContains(cookiePath: string, requestPath: string): boolean {
  return (
    requestPath === cookiePath ||
    requestPath.startsWith(cookiePath.endsWith("/") ? cookiePath : `${cookiePath}/`)
  );
}

function assertRequestConfinement(record: NetworkRecord, secrets: readonly SecretValue[]): void {
  const url = new URL(record.url);
  for (const secret of secrets) {
    if (record.url.includes(secret.value)) {
      expect(
        (secret.kind === "handoff" && record.method === "GET" && isCallbackUrl(url)) ||
          (secret.kind === "preparation" && isPreparationNetworkRoute(record, url, secret.value)),
        `${secret.kind} appeared in an unrelated request URL: ${url.pathname}`,
      ).toBe(true);
    }
    for (const header of record.headers) {
      if (!header.value.includes(secret.value)) continue;
      const name = header.name.toLowerCase();
      expect(
        secret.kind === "access" &&
          name === "authorization" &&
          header.value === `Bearer ${secret.value}` &&
          isReviewedAccessTokenRoute(record, url),
        `${secret.kind} appeared in unrelated request header ${header.name}: ${url.pathname}`,
      ).toBe(true);
    }
    if (record.body.includes(secret.value)) {
      expect(
        (secret.kind === "refresh" &&
          isRuntimeRecord(record, url, "POST", projectRoute("auth/sessions/refresh"))) ||
          (secret.kind === "handoff" &&
            isRuntimeRecord(record, url, "POST", projectRoute("auth/handoff/exchange"))) ||
          (secret.kind === "csrf" && isReviewedCsrfMutation(record, url)),
        `${secret.kind} appeared in an unrelated request body: ${url.pathname}`,
      ).toBe(true);
    }
  }
}

function assertResponseConfinement(record: NetworkRecord, secrets: readonly SecretValue[]): void {
  const url = new URL(record.url);
  for (const secret of secrets) {
    if (record.url.includes(secret.value)) {
      expect(
        (secret.kind === "handoff" && record.method === "GET" && isCallbackUrl(url)) ||
          (secret.kind === "preparation" && isPreparationNetworkRoute(record, url, secret.value)),
        `${secret.kind} appeared in an unrelated response URL: ${url.pathname}`,
      ).toBe(true);
    }
    for (const header of record.headers) {
      if (!header.value.includes(secret.value)) continue;
      const name = header.name.toLowerCase();
      let location: URL | null = null;
      if (name === "location") {
        try {
          location = new URL(header.value, record.url);
        } catch {
          // The assertion below rejects the malformed sensitive location.
        }
      }
      expect(
        secret.kind === "handoff" &&
          location !== null &&
          isCallbackUrl(location) &&
          isRuntimeRecord(record, url, "GET", /^projects\/[^/]+\/auth\/callback\/[^/]+$/u),
        `${secret.kind} appeared in unrelated response header ${header.name}: ${url.pathname}`,
      ).toBe(true);
    }
    if (record.body.includes(secret.value)) {
      const credentialResponse =
        isRuntimeRecord(record, url, "POST", projectRoute("auth/handoff/exchange")) ||
        isRuntimeRecord(record, url, "POST", projectRoute("auth/sessions/refresh"));
      expect(
        ((secret.kind === "access" || secret.kind === "refresh") && credentialResponse) ||
          (secret.kind === "preparation" &&
            isRuntimeRecord(record, url, "POST", projectRoute("auth/browser-logout/prepare"))) ||
          (secret.kind === "csrf" &&
            isRuntimeRecord(
              record,
              url,
              "GET",
              /^auth\/(?:interactions|browser-logout)\/[^/]+$/u,
            )) ||
          (secret.kind === "handoff" &&
            isRuntimeRecord(
              record,
              url,
              "POST",
              projectRoute("auth/interactions/[^/]+/session/reuse"),
            )),
        `${secret.kind} appeared in an unrelated response body: ${url.pathname}`,
      ).toBe(true);
    }
  }
}

function assertLifecycleConfinement(
  sample: LifecycleSample,
  secrets: readonly SecretValue[],
): void {
  let url: URL | null = null;
  try {
    url = new URL(sample.url);
  } catch {
    // about:blank and incomplete navigation samples contain no sensitive material.
  }
  expect(sample.local, `page ${String(sample.pageId)} wrote localStorage`).toEqual([]);
  expect(sample.session, `page ${String(sample.pageId)} wrote sessionStorage`).toEqual([]);

  for (const secret of secrets) {
    const allowedUrl =
      url !== null &&
      ((secret.kind === "handoff" && isCallbackUrl(url)) ||
        (secret.kind === "preparation" && isLogoutPreparationUrl(url, secret.value)));
    expect(
      !sample.url.includes(secret.value) || allowedUrl,
      `${secret.kind} escaped into ${sample.reason} page URL`,
    ).toBe(true);

    const bootstrapDom =
      secret.kind === "csrf" &&
      url !== null &&
      isHostedBootstrapUrl(url) &&
      sample.html.includes('name="owlauth-runtime-bootstrap"');
    expect(
      !sample.body.includes(secret.value) || bootstrapDom,
      `${secret.kind} escaped into ${sample.reason} page text`,
    ).toBe(true);
    expect(
      !sample.html.includes(secret.value) || bootstrapDom,
      `${secret.kind} escaped into ${sample.reason} page DOM`,
    ).toBe(true);
    expect(
      !sample.history.includes(secret.value),
      `${secret.kind} escaped into ${sample.reason} history.state`,
    ).toBe(true);
    expect(
      !sample.cookies.includes(secret.value),
      `${secret.kind} escaped into ${sample.reason} document.cookie`,
    ).toBe(true);
  }
}

function isCallbackUrl(url: URL): boolean {
  return (
    url.origin === applicationOrigin &&
    ["/backend/callback", "/browser/callback", "/sdk/callback"].includes(url.pathname)
  );
}

function isHostedBootstrapUrl(url: URL): boolean {
  return runtimeRouteMatch(url, /^auth\/(?:interactions|browser-logout)\/[^/]+$/u) !== null;
}

function isLogoutPreparationUrl(url: URL, preparation: string): boolean {
  const match = runtimeRouteMatch(url, /^auth\/browser-logout\/([^/]+)$/u);
  return match?.[1] === preparation;
}

function isPreparationNetworkRoute(record: NetworkRecord, url: URL, preparation: string): boolean {
  return (
    (record.method === "GET" && isLogoutPreparationUrl(url, preparation)) ||
    (record.method === "POST" &&
      runtimeRouteMatch(url, projectRoute("auth/browser-logout/([^/]+)/confirm"))?.[1] ===
        preparation)
  );
}

function isReviewedAccessTokenRoute(record: NetworkRecord, url: URL): boolean {
  return (
    isRuntimeRecord(record, url, "GET", projectRoute("auth/users/me")) ||
    isRuntimeRecord(record, url, "POST", projectRoute("auth/sessions/logout")) ||
    isRuntimeRecord(record, url, "POST", projectRoute("auth/browser-logout/prepare"))
  );
}

function isReviewedCsrfMutation(record: NetworkRecord, url: URL): boolean {
  return (
    isRuntimeRecord(record, url, "POST", projectRoute("auth/interactions/[^/]+/method")) ||
    isRuntimeRecord(record, url, "POST", projectRoute("auth/interactions/[^/]+/session/reuse")) ||
    isRuntimeRecord(record, url, "POST", projectRoute("auth/browser-logout/[^/]+/confirm"))
  );
}

function runtimeUrl(): URL {
  return new URL(runtimeBase);
}

function runtimeCookiePath(): string {
  const path = runtimeUrl().pathname;
  return path.endsWith("/") ? path : `${path}/`;
}

function runtimeRouteMatch(url: URL, route: RegExp): RegExpExecArray | null {
  const runtime = runtimeUrl();
  if (url.origin !== runtime.origin) return null;
  const basePath = runtimeCookiePath();
  if (!url.pathname.startsWith(basePath)) return null;
  const relative = url.pathname.slice(basePath.length);
  return route.exec(relative);
}

function isRuntimeRecord(
  record: NetworkRecord,
  url: URL,
  method: "GET" | "POST",
  route: RegExp,
): boolean {
  return record.method === method && runtimeRouteMatch(url, route) !== null;
}

function projectRoute(suffix: string): RegExp {
  return new RegExp(`^v1/projects/[^/]+/${suffix}$`, "u");
}

async function currentSecrets(evidence: BrowserEvidence): Promise<readonly SecretValue[]> {
  await evidence.settle();
  return evidenceSecrets([
    {
      consoleMessages: evidence.consoleMessages,
      lifecycle: evidence.lifecycle,
      pageCount: evidence.pages().length,
      requests: evidence.requests,
      responses: evidence.responses,
      storageState: "",
    },
  ]);
}

async function assertPageSecretFree(page: Page, secrets: readonly SecretValue[]): Promise<void> {
  const state = await page.evaluate(async () => ({
    body: document.body.textContent,
    html: document.documentElement.outerHTML,
    url: location.href,
    history: JSON.stringify(history.state),
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
    cookies: document.cookie,
    caches: await caches.keys(),
    databases:
      typeof indexedDB.databases === "function"
        ? (await indexedDB.databases()).map((database) => database.name)
        : [],
  }));
  expect(state.caches).toEqual([]);
  expect(state.databases).toEqual([]);
  assertLifecycleConfinement(
    {
      body: state.body,
      cookies: state.cookies,
      history: state.history,
      html: state.html,
      local: state.local,
      pageId: 0,
      reason: "explicit assertion",
      session: state.session,
      url: state.url,
    },
    secrets,
  );
}
async function completeBackendCustodyJourney(
  page: Page,
  browserName: "chromium" | "firefox",
): Promise<ProvisionedContext> {
  const backendContext = await provision(
    page.request,
    `${browserName}-backend-${Date.now().toString(36)}`,
  );
  const backendPublishableKey = backendContext.application.configuration.publishable_keys[0];
  if (backendPublishableKey === undefined) throw new Error("backend Application has no key");
  const backendParameters = new URLSearchParams({
    application: backendContext.application.public_id,
    claims_revision: String(backendContext.claimsRevision),
    key: backendPublishableKey,
    other_project: backendContext.otherProject.public_id,
    project: backendContext.project.public_id,
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
  return backendContext;
}

async function completeSdkQualification(
  page: Page,
  evidence: BrowserEvidence,
  browserName: "chromium" | "firefox",
  browserContext: ProvisionedContext,
  backendContext: ProvisionedContext,
): Promise<void> {
  await assertEvidenceConfinement([evidence]);
  const sdkResult = await runSdkE2Es(page.request, browserName);
  expect(sdkResult.browserEvidence).toHaveLength(6);
  await assertEvidenceConfinement([evidence], sdkResult.browserEvidence);
  await writeBrowserEvidence(browserName, browserContext, backendContext, sdkResult);
  const finalProviderCounts = await providerRequestCounts(page.request);
  expect(finalProviderCounts.token_confinement_violations).toBe(0);
  // Upstream credential revocation belongs to Chromium's managed-connection lifecycle. Firefox
  // qualifies browser portability and the exact TypeScript artifact without repeating that server
  // journey; Application and browser logout do not revoke the provider credential.
  if (browserName === "chromium") {
    expect(finalProviderCounts.revocation_requests).toBeGreaterThan(0);
  }
  expect(finalProviderCounts.userinfo_requests).toBeGreaterThan(0);
  expect(await fileSha256(typescriptArchive)).toBe(frozenTypescriptSdkDigest);
}

async function runSdkE2Es(
  request: APIRequestContext,
  browserName: "chromium" | "firefox",
): Promise<SdkE2EResult> {
  const repository = resolve(import.meta.dirname, "../../../..");
  const evidenceRunId = `${browserName}-${randomBytes(18).toString("base64url")}`;
  const typescriptContext = await provision(
    request,
    `${browserName}-sdk-typescript-${Date.now().toString(36)}`,
  );
  await resetSdkEvidence(typescriptContext);
  const typescriptEnvironment = sdkEnvironment(typescriptContext);
  await runSdkCommand(
    repository,
    "TypeScript",
    "node",
    [typescriptRunner],
    {
      ...typescriptEnvironment,
      OWLAUTH_E2E_EXPECTED_SDK_VERSION: typescriptVersion,
      OWLAUTH_E2E_FAULT_PROXY_BASE: faultProxyBase,
      OWLAUTH_E2E_FAULT_PROXY_TOKEN: faultProxyToken,
      OWLAUTH_E2E_REPOSITORY: repository,
      OWLAUTH_E2E_BROWSER_DRIVER_TOKEN: browserDriverToken,
      OWLAUTH_E2E_BROWSER_DRIVER_URL: browserDriverUrl,
      OWLAUTH_E2E_BROWSER_EVIDENCE_RUN_ID: evidenceRunId,
      OWLAUTH_E2E_BROWSER_NAME: browserName,
      OWLAUTH_E2E_PROVIDER_KEY: "controlled-provider",
      OWLAUTH_E2E_RUNTIME_BASE_URL: runtimeBase,
    },
    "TypeScript real-server Project Auth E2E passed.",
  );
  const typescriptMeasured = await measuredSdkEvidence(typescriptContext);
  const unauthorizedDrain = await fetch(new URL("/sdk/browser-evidence/drain", browserDriverUrl), {
    body: JSON.stringify({ runId: evidenceRunId }),
    headers: { "content-type": "application/json" },
    method: "POST",
    redirect: "error",
  });
  expect(unauthorizedDrain.status).toBe(401);
  expect(await drainSdkBrowserEvidence(`${evidenceRunId}-isolated`)).toEqual([]);
  const browserEvidence = await drainSdkBrowserEvidence(evidenceRunId);
  expect(
    browserEvidence,
    "TypeScript SDK must report ordinary, replay/race, and fault-injected browser journeys",
  ).toHaveLength(6);
  if (browserName !== "chromium") {
    return {
      assignments: { typescript: assignment(typescriptContext) },
      browserEvidence,
      faultInjectedOperationIds: {
        typescript: typescriptMeasured.faultInjectedOperationIds,
      },
      observedOperationIds: { typescript: typescriptMeasured.observedOperationIds },
    };
  }

  // Python and Rust exercise raw HTTP SDK transports; they are deliberately not
  // represented as browser contexts in the confinement evidence union. Each receives
  // a distinct Project/Application and therefore cannot share mutable credentials.
  const pythonContext = await provision(request, `sdk-python-${Date.now().toString(36)}`);
  await resetSdkEvidence(pythonContext);
  await runSdkCommand(
    repository,
    "Python",
    pythonExecutable,
    [pythonRunner],
    {
      ...sdkEnvironment(pythonContext),
      OWLAUTH_E2E_EXPECTED_SDK_VERSION: pythonVersion,
      OWLAUTH_E2E_FAULT_PROXY_BASE: faultProxyBase,
      OWLAUTH_E2E_FAULT_PROXY_TOKEN: faultProxyToken,
      OWLAUTH_E2E_REPOSITORY: repository,
      OWLAUTH_E2E_RUNTIME_URL: runtimeBase,
      PYTHONNOUSERSITE: "1",
    },
    "Python SDK real-Runtime Project Auth E2E passed",
  );
  const pythonMeasured = await measuredSdkEvidence(pythonContext);
  const rustContext = await provision(request, `sdk-rust-${Date.now().toString(36)}`);
  await resetSdkEvidence(rustContext);
  await runSdkCommand(
    repository,
    "Rust",
    "cargo",
    [
      "test",
      "--manifest-path",
      rustManifest,
      "--test",
      "server_e2e",
      "--",
      "--ignored",
      "--exact",
      "real_runtime_project_auth_lifecycle",
    ],
    {
      ...sdkEnvironment(rustContext),
      OWLAUTH_E2E_EXPECTED_SDK_VERSION: rustVersion,
      OWLAUTH_E2E_FAULT_PROXY_BASE: faultProxyBase,
      OWLAUTH_E2E_FAULT_PROXY_TOKEN: faultProxyToken,
      OWLAUTH_E2E_PROVIDER_KEY: "controlled-provider",
      OWLAUTH_E2E_RUNTIME_URL: runtimeBase,
    },
    "test real_runtime_project_auth_lifecycle ... ok",
  );
  const rustMeasured = await measuredSdkEvidence(rustContext);
  return {
    assignments: {
      python: assignment(pythonContext),
      rust: assignment(rustContext),
      typescript: assignment(typescriptContext),
    },
    browserEvidence,
    faultInjectedOperationIds: {
      python: pythonMeasured.faultInjectedOperationIds,
      rust: rustMeasured.faultInjectedOperationIds,
      typescript: typescriptMeasured.faultInjectedOperationIds,
    },
    observedOperationIds: {
      python: pythonMeasured.observedOperationIds,
      rust: rustMeasured.observedOperationIds,
      typescript: typescriptMeasured.observedOperationIds,
    },
  };
}

function assignment(context: ProvisionedContext): {
  readonly application: string;
  readonly project: string;
} {
  return {
    application: context.application.public_id,
    project: context.project.public_id,
  };
}

function sdkEnvironment(context: ProvisionedContext): NodeJS.ProcessEnv {
  const publishableKey = context.application.configuration.publishable_keys[0];
  if (publishableKey === undefined) {
    throw new Error("provisioned SDK Application has no publishable key");
  }
  const environment: NodeJS.ProcessEnv = {};
  const inheritedNames = [
    "ALL_PROXY",
    "CARGO_HOME",
    "CARGO_NET_OFFLINE",
    "CARGO_REGISTRIES_CRATES_IO_PROTOCOL",
    "CARGO_TARGET_DIR",
    "CI",
    "DYLD_LIBRARY_PATH",
    "HOME",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "LANG",
    "LC_ALL",
    "LD_LIBRARY_PATH",
    "LOGNAME",
    "NODE_OPTIONS",
    "NO_COLOR",
    "NO_PROXY",
    "NPM_CONFIG_USERCONFIG",
    "PATH",
    "PYTHONIOENCODING",
    "PYTHONUTF8",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "SHELL",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SYSTEMROOT",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "USER",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
  ] as const;
  for (const name of inheritedNames) {
    const value = process.env[name];
    if (value !== undefined) environment[name] = value;
  }
  return {
    ...environment,
    OWLAUTH_E2E_ALLOW_INSECURE_LOOPBACK: "1",
    OWLAUTH_E2E_APPLICATION_ID: context.application.public_id,
    OWLAUTH_E2E_OTHER_APPLICATION_ID: context.otherApplication.public_id,
    OWLAUTH_E2E_OTHER_PROJECT_ID: context.otherProject.public_id,
    OWLAUTH_E2E_PROJECT_ID: context.project.public_id,
    OWLAUTH_E2E_PUBLISHABLE_KEY: publishableKey,
    OWLAUTH_E2E_REDIRECT_URI: `${applicationOrigin}/sdk/callback`,
  };
}

async function resetSdkEvidence(context: ProvisionedContext): Promise<void> {
  const url = sdkObservationUrl(context, "__e2e/observations/reset");
  const response = await fetch(url, {
    headers: { authorization: `Bearer ${faultProxyToken}` },
    method: "POST",
    redirect: "error",
  });
  expect(response.status).toBe(200);
  const document = (await response.json()) as {
    removedFaultInjectedOperationIds?: unknown;
    removedObservedOperationIds?: unknown;
  };
  measuredOperationIds(
    document.removedFaultInjectedOperationIds,
    [],
    "pre-candidate fault-injected",
  );
  measuredOperationIds(
    document.removedObservedOperationIds,
    ["get_project_jwks"],
    "pre-candidate harness",
  );

  // This live mutation proves provisioning cannot satisfy candidate coverage. If a runner omits
  // JWKS (or any other expected operation), the post-run exact-set check below must now fail.
  const cleared = await sdkEvidenceDocument(context);
  measuredOperationIds(cleared.faultInjectedOperationIds, [], "cleared fault-injected");
  measuredOperationIds(cleared.observedOperationIds, [], "cleared ordinary");
}

async function measuredSdkEvidence(context: ProvisionedContext): Promise<MeasuredSdkEvidence> {
  const document = await sdkEvidenceDocument(context);
  return {
    faultInjectedOperationIds: measuredOperationIds(
      document.faultInjectedOperationIds,
      expectedFaultOperationIds,
      "fault-injected",
    ),
    observedOperationIds: measuredOperationIds(
      document.observedOperationIds,
      expectedOperationIds,
      "ordinary",
    ),
  };
}

async function sdkEvidenceDocument(context: ProvisionedContext): Promise<{
  readonly faultInjectedOperationIds?: unknown;
  readonly observedOperationIds?: unknown;
}> {
  const response = await fetch(sdkObservationUrl(context, "__e2e/observations"), {
    headers: { authorization: `Bearer ${faultProxyToken}` },
    redirect: "error",
  });
  expect(response.status).toBe(200);
  return (await response.json()) as {
    faultInjectedOperationIds?: unknown;
    observedOperationIds?: unknown;
  };
}

function sdkObservationUrl(context: ProvisionedContext, path: string): URL {
  const url = new URL(path, faultProxyBase);
  url.searchParams.set("project_id", context.project.public_id);
  url.searchParams.set("application_id", context.application.public_id);
  return url;
}

function measuredOperationIds(
  value: unknown,
  expected: readonly string[],
  label: string,
): readonly string[] {
  if (
    !Array.isArray(value) ||
    value.some((operation) => typeof operation !== "string") ||
    new Set(value).size !== value.length
  ) {
    throw new Error(`${label} Runtime operation evidence is malformed`);
  }
  const measured = value as string[];
  expect([...measured].sort(), `${label} Runtime operation evidence is incomplete`).toEqual(
    [...expected].sort(),
  );
  return measured;
}

async function drainSdkBrowserEvidence(runId: string): Promise<readonly BrowserEvidenceSnapshot[]> {
  const drainUrl = new URL("/sdk/browser-evidence/drain", browserDriverUrl);
  const response = await fetch(drainUrl, {
    body: JSON.stringify({ runId }),
    headers: {
      accept: "application/json",
      authorization: `Bearer ${browserDriverToken}`,
      "content-type": "application/json",
    },
    method: "POST",
    redirect: "error",
  });
  expect(response.status).toBe(200);
  const document = (await response.json()) as { evidence?: unknown };
  if (!Array.isArray(document.evidence)) throw new Error("browser evidence drain was malformed");
  return document.evidence as BrowserEvidenceSnapshot[];
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
  let policy = await controlGet<ProjectPolicy>(request, `projects/${project.id}/policy`);
  policy = await control<ProjectPolicy>(request, "PUT", `projects/${project.id}/policy`, {
    access_token_lifetime_seconds: policy.access_token_lifetime_seconds,
    browser_session_reuse: true,
    expected_claims_revision: policy.claims_revision,
    expected_session_revision: policy.session_revision,
  });
  expect(policy.browser_session_reuse).toBe(true);
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

  await rotateSigningKey(request, project, `signing-key-${suffix}`);

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

async function rotateSigningKey(
  request: APIRequestContext,
  project: Project,
  idempotencyKey: string,
): Promise<void> {
  await waitForSigningKey(request, project, undefined);
  const currentProject = await controlGet<Project>(request, `projects/${project.id}`);
  const rotated = await control<SigningKey>(
    request,
    "POST",
    `projects/${project.id}/signing-keys/rotate`,
    { expected_project_revision: currentProject.metadata_revision },
    idempotencyKey,
  );
  const active = await waitForSigningKey(request, project, rotated.id);
  for (let attempt = 0; attempt < 80; attempt += 1) {
    const response = await request.get(
      `${runtimeBase}projects/${encodeURIComponent(project.public_id)}/.well-known/jwks.json`,
    );
    if (response.ok()) {
      const body = (await response.json()) as { keys?: { kid?: string }[] };
      if (body.keys?.some(({ kid }) => kid === active.kid) === true) return;
    }
    await delay(250);
  }
  throw new Error(`timed out waiting for signing key ${active.id} in Runtime JWKS`);
}

async function waitForSigningKey(
  request: APIRequestContext,
  project: Project,
  keyId: string | undefined,
): Promise<SigningKey> {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    const { items } = await controlGet<{ items: SigningKey[] }>(
      request,
      `projects/${project.id}/signing-keys`,
    );
    const candidate =
      keyId === undefined
        ? items.find(({ state }) => state === "active")
        : items.find(({ id, state }) => id === keyId && state === "active");
    if (candidate !== undefined) return candidate;
    await delay(250);
  }
  throw new Error(
    keyId === undefined
      ? `timed out waiting for Project ${project.id} initial signing key`
      : `timed out waiting for signing key ${keyId} to activate`,
  );
}

async function delay(milliseconds: number): Promise<void> {
  await new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

async function writeBrowserEvidence(
  browserName: "chromium" | "firefox",
  browserContext: ProvisionedContext,
  backendContext: ProvisionedContext,
  sdkResult: SdkE2EResult,
): Promise<void> {
  const directory = process.env["OWLAUTH_E2E_EVIDENCE_DIRECTORY"];
  if (directory === undefined || directory === "") return;
  await mkdir(directory, { recursive: true });
  const sdkNames = Object.keys(sdkResult.assignments).sort();
  expect(Object.keys(sdkResult.faultInjectedOperationIds).sort()).toEqual(sdkNames);
  expect(Object.keys(sdkResult.observedOperationIds).sort()).toEqual(sdkNames);
  const document = {
    assignments: {
      backendCustody: assignment(backendContext),
      browserDirect: assignment(browserContext),
      sdks: Object.fromEntries(sdkNames.map((name) => [name, sdkResult.assignments[name]])),
    },
    browser: browserName,
    candidates: {
      python: { sha256: pythonSdkDigest, version: pythonVersion },
      rust: { sha256: rustSdkDigest, version: rustVersion },
      typescript: { sha256: frozenTypescriptSdkDigest, version: typescriptVersion },
    },
    evidence: {
      exactArtifacts: true,
      faultInjectedOperationIds: Object.fromEntries(
        sdkNames.map((name) => [name, sdkResult.faultInjectedOperationIds[name]]),
      ),
      observedOperationIds: Object.fromEntries(
        sdkNames.map((name) => [name, sdkResult.observedOperationIds[name]]),
      ),
      sharedRuntime: true,
    },
    schemaVersion: 1,
    serverCommit: sourceCommit,
    status: "passed",
  };
  await writeFile(
    resolve(directory, `project-auth-${browserName}.json`),
    `${JSON.stringify(document, null, 2)}\n`,
  );
}

async function fileSha256(path: string): Promise<string> {
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}
