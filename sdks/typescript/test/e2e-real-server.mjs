import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import { Client, OwlAuthError, VERSION } from "@owlauth/client";

const required = [
  "OWLAUTH_E2E_RUNTIME_BASE_URL",
  "OWLAUTH_E2E_PROJECT_ID",
  "OWLAUTH_E2E_APPLICATION_ID",
  "OWLAUTH_E2E_OTHER_PROJECT_ID",
  "OWLAUTH_E2E_OTHER_APPLICATION_ID",
  "OWLAUTH_E2E_PUBLISHABLE_KEY",
  "OWLAUTH_E2E_REDIRECT_URI",
  "OWLAUTH_E2E_BROWSER_DRIVER_URL",
  "OWLAUTH_E2E_BROWSER_EVIDENCE_RUN_ID",
  "OWLAUTH_E2E_EXPECTED_SDK_VERSION",
  "OWLAUTH_E2E_REPOSITORY",
  "OWLAUTH_E2E_FAULT_PROXY_BASE",
  "OWLAUTH_E2E_FAULT_PROXY_TOKEN",
];

for (const name of required) {
  if (!process.env[name]) {
    throw new Error(
      `Missing ${name}. This explicit real-server suite never skips; see README.md for the E2E environment contract.`,
    );
  }
}

assert.equal(VERSION, process.env.OWLAUTH_E2E_EXPECTED_SDK_VERSION);
const packageOrigin = fileURLToPath(import.meta.resolve("@owlauth/client"));
assert.ok(packageOrigin.includes("node_modules/@owlauth/client/dist/index.js"), packageOrigin);
assert.equal(packageOrigin.startsWith(process.env.OWLAUTH_E2E_REPOSITORY), false, packageOrigin);

const driverUrl = new URL(process.env.OWLAUTH_E2E_BROWSER_DRIVER_URL);
if (
  driverUrl.username !== "" ||
  driverUrl.password !== "" ||
  driverUrl.hash !== "" ||
  (driverUrl.protocol !== "https:" &&
    !(
      process.env.OWLAUTH_E2E_ALLOW_INSECURE_LOOPBACK === "1" &&
      driverUrl.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(driverUrl.hostname)
    ))
) {
  throw new Error("OWLAUTH_E2E_BROWSER_DRIVER_URL must be secure or explicit loopback development HTTP.");
}

const client = sdkClient(process.env.OWLAUTH_E2E_RUNTIME_BASE_URL);

const configuration = await client.getPublicConfiguration();
assert.equal(configuration.loginAvailable, true);
assert.ok(configuration.providers.length > 0);
assert.equal(configuration.projectId, process.env.OWLAUTH_E2E_PROJECT_ID);
assert.equal(configuration.applicationId, process.env.OWLAUTH_E2E_APPLICATION_ID);
await assertContextRejected({ projectId: process.env.OWLAUTH_E2E_OTHER_PROJECT_ID });
await assertContextRejected({ applicationId: process.env.OWLAUTH_E2E_OTHER_APPLICATION_ID });
await assertContextRejected({ publishableKey: mutate(process.env.OWLAUTH_E2E_PUBLISHABLE_KEY) });
const jwks = await client.getProjectJwks();
assert.ok(jwks.revision > 0);
assert.ok(jwks.signingEpoch > 0);
assert.ok(jwks.keys.length > 0);

const credentials = await browserLogin(client, true);
const current = await client.currentUser(credentials.accessToken);
assert.equal(current.userId, credentials.userId);
assert.equal(current.projection.userId, credentials.projection.userId);
assert.equal(current.projection.projectionSchema, credentials.projection.projectionSchema);
assert.ok(current.projection.userRevision >= credentials.projection.userRevision);
assert.ok(current.projection.projectionRevision >= credentials.projection.projectionRevision);
if (current.projection.projectionRevision === credentials.projection.projectionRevision) {
  assert.deepEqual(current.projection, credentials.projection);
}

const successor = await client.refresh(credentials);
assert.equal(successor.refreshGeneration, credentials.refreshGeneration + 1);

await assert.rejects(client.refresh(credentials), (error) => {
  assert.ok(error instanceof OwlAuthError);
  assert.equal(error.category, "Refresh");
  assert.equal(error.action, "invalidate_credentials");
  return true;
});
await assert.rejects(client.refresh(successor), (error) => {
  assert.ok(error instanceof OwlAuthError);
  assert.equal(error.category, "Refresh");
  assertBoundedRequestId(error);
  return true;
});

const concurrentCredentials = await browserLogin(client);
const concurrentResults = await Promise.allSettled([
  client.refresh(concurrentCredentials),
  client.refresh(concurrentCredentials),
]);
assert.equal(concurrentResults.filter(({ status }) => status === "fulfilled").length, 1);
const concurrentFailure = concurrentResults.find(({ status }) => status === "rejected");
assert.ok(concurrentFailure && concurrentFailure.reason instanceof OwlAuthError);
assert.equal(concurrentFailure.reason.category, "Refresh");
const concurrentSuccess = concurrentResults.find(({ status }) => status === "fulfilled");
assert.ok(concurrentSuccess);
await assert.rejects(client.refresh(concurrentSuccess.value), OwlAuthError);

const logoutCredentials = await browserLogin(client);
const logoutPreparation = await client.prepareBrowserLogout(logoutCredentials.accessToken);
assert.ok(new URL(logoutPreparation.hostedUrl).pathname.includes("/auth/browser-logout/"));
await client.logoutApplication(logoutCredentials.accessToken);
await client.logoutApplication(logoutCredentials.accessToken);
await assert.rejects(client.currentUser(logoutCredentials.accessToken), (error) => {
  assert.ok(error instanceof OwlAuthError);
  assert.equal(error.category, "Authentication");
  return true;
});

const faultClient = sdkClient(process.env.OWLAUTH_E2E_FAULT_PROXY_BASE);
await assertRejectedFaultDoesNotRemainArmed();
const handoffFault = await browserCallback(faultClient);
await armFault("exchange_handoff", "typescript-handoff");
await assert.rejects(
  faultClient.completeLogin(handoffFault.callbackUrl, handoffFault.started.pending),
  indeterminate("quarantine_pending"),
);
await assertFaultObserved("typescript-handoff", "exchange_handoff");

const refreshFaultCredentials = await browserLogin(faultClient);
await armFault("refresh_session", "typescript-refresh");
await assert.rejects(
  faultClient.refresh(refreshFaultCredentials),
  indeterminate("quarantine_credentials"),
);
await assertFaultObserved("typescript-refresh", "refresh_session");
await assert.rejects(faultClient.refresh(refreshFaultCredentials), (error) => {
  assert.ok(error instanceof OwlAuthError);
  assert.equal(error.category, "Refresh");
  assert.equal(error.action, "invalidate_credentials");
  return true;
});

const logoutFaultCredentials = await browserLogin(faultClient);
await armFault("logout_application_session", "typescript-logout");
await assert.rejects(
  faultClient.logoutApplication(logoutFaultCredentials.accessToken),
  indeterminate("quarantine_credentials"),
);
await assertFaultObserved("typescript-logout", "logout_application_session");
await assert.rejects(faultClient.currentUser(logoutFaultCredentials.accessToken), (error) => {
  assert.ok(error instanceof OwlAuthError);
  assert.equal(error.category, "Authentication");
  return true;
});

process.stdout.write("TypeScript real-server Project Auth E2E passed.\n");

async function browserLogin(runtimeClient, verifyReplay = false) {
  const { callbackUrl, started } = await browserCallback(runtimeClient);
  const credentials = await runtimeClient.completeLogin(callbackUrl, started.pending);
  if (verifyReplay) {
    await assert.rejects(runtimeClient.completeLogin(callbackUrl, started.pending), (error) => {
      assert.ok(error instanceof OwlAuthError);
      assert.equal(error.category, "Handoff");
      assert.equal(error.action, "discard_pending");
      return true;
    });
  }
  return credentials;
}

async function browserCallback(runtimeClient) {
  const started = await runtimeClient.beginLogin({
    redirectUri: process.env.OWLAUTH_E2E_REDIRECT_URI,
    state: `typescript-e2e-${crypto.randomUUID()}`,
  });

  // The harness endpoint must drive a real top-level browser through the embedded Hosted UI,
  // select an admitted controlled provider, follow its authorization and Runtime callback,
  // and return the final exact Application callback URL. It must not intercept or fake Runtime.
  const driverResponse = await fetch(driverUrl, {
    method: "POST",
    redirect: "error",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      ...(process.env.OWLAUTH_E2E_BROWSER_DRIVER_TOKEN
        ? { authorization: `Bearer ${process.env.OWLAUTH_E2E_BROWSER_DRIVER_TOKEN}` }
        : {}),
    },
    body: JSON.stringify({
      hostedUrl: started.hostedUrl,
      redirectUri: process.env.OWLAUTH_E2E_REDIRECT_URI,
      providerKey: process.env.OWLAUTH_E2E_PROVIDER_KEY ?? null,
      browserName: process.env.OWLAUTH_E2E_BROWSER_NAME,
      evidenceRunId: process.env.OWLAUTH_E2E_BROWSER_EVIDENCE_RUN_ID,
    }),
  });
  assert.equal(driverResponse.status, 200, "real browser driver failed");
  const driverBody = await driverResponse.json();
  assert.equal(typeof driverBody.callbackUrl, "string");
  assert.ok(driverBody.callbackUrl.length <= 4096);
  return { callbackUrl: driverBody.callbackUrl, started };
}

function sdkClient(baseUrl) {
  return new Client({
    baseUrl,
    projectId: process.env.OWLAUTH_E2E_PROJECT_ID,
    applicationId: process.env.OWLAUTH_E2E_APPLICATION_ID,
    publishableKey: process.env.OWLAUTH_E2E_PUBLISHABLE_KEY,
    allowInsecureLoopback: process.env.OWLAUTH_E2E_ALLOW_INSECURE_LOOPBACK === "1",
    timeoutMs: 15_000,
  });
}

async function assertRejectedFaultDoesNotRemainArmed() {
  const label = "typescript-rejected-refresh";
  await armFault("refresh_session", label);
  const response = await fetch(
    new URL(
      `v1/projects/${encodeURIComponent(process.env.OWLAUTH_E2E_PROJECT_ID)}/auth/sessions/refresh`,
      process.env.OWLAUTH_E2E_FAULT_PROXY_BASE,
    ),
    {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: "{}",
    },
  );
  assert.notEqual(response.status, 200, "malformed refresh unexpectedly committed");
  const events = await fetch(
    new URL("__e2e/events", process.env.OWLAUTH_E2E_FAULT_PROXY_BASE),
    { headers: { authorization: `Bearer ${process.env.OWLAUTH_E2E_FAULT_PROXY_TOKEN}` } },
  );
  assert.equal(events.status, 200);
  const document = await events.json();
  assert.equal(
    document.items.some((item) => item.label === label),
    false,
    "a rejected Runtime response was recorded as an injected transport fault",
  );
}

async function armFault(operation, label) {
  const response = await fetch(new URL("__e2e/arm", process.env.OWLAUTH_E2E_FAULT_PROXY_BASE), {
    method: "POST",
    redirect: "error",
    headers: {
      authorization: `Bearer ${process.env.OWLAUTH_E2E_FAULT_PROXY_TOKEN}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ operation, label }),
  });
  assert.equal(response.status, 200);
}

async function assertFaultObserved(label, operation) {
  for (let attempt = 0; attempt < 300; attempt += 1) {
    const response = await fetch(new URL("__e2e/events", process.env.OWLAUTH_E2E_FAULT_PROXY_BASE), {
      headers: { authorization: `Bearer ${process.env.OWLAUTH_E2E_FAULT_PROXY_TOKEN}` },
    });
    assert.equal(response.status, 200);
    const document = await response.json();
    if (
      document.items.some(
        (item) =>
          item.label === label &&
          item.operation === operation &&
          item.projectId === process.env.OWLAUTH_E2E_PROJECT_ID &&
          item.upstreamStatus === 200,
      )
    ) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Runtime fault ${label} for ${operation} was not observed for this Project.`);
}

function indeterminate(action) {
  return (error) => {
    assert.ok(error instanceof OwlAuthError);
    assert.equal(error.category, "Indeterminate");
    assert.equal(error.code, "outcome_indeterminate");
    assert.equal(error.action, action);
    assert.equal(error.retry, "never");
    return true;
  };
}

async function assertContextRejected(overrides) {
  const isolated = new Client({
    baseUrl: process.env.OWLAUTH_E2E_RUNTIME_BASE_URL,
    projectId: overrides.projectId ?? process.env.OWLAUTH_E2E_PROJECT_ID,
    applicationId: overrides.applicationId ?? process.env.OWLAUTH_E2E_APPLICATION_ID,
    publishableKey: overrides.publishableKey ?? process.env.OWLAUTH_E2E_PUBLISHABLE_KEY,
    allowInsecureLoopback: true,
    timeoutMs: 15_000,
  });
  await assert.rejects(isolated.getPublicConfiguration(), (error) => {
    assert.ok(error instanceof OwlAuthError);
    assert.equal(error.operation, "get_public_application_config");
    assertBoundedRequestId(error);
    return true;
  });
}

function assertBoundedRequestId(error) {
  if (error.requestId !== undefined) {
    assert.equal(typeof error.requestId, "string");
    assert.ok(error.requestId.length > 0 && error.requestId.length <= 128);
  }
}

function mutate(value) {
  const last = value.at(-1);
  return `${value.slice(0, -1)}${last === "A" ? "B" : "A"}`;
}
