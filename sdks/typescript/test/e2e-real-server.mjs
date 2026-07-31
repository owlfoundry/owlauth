import assert from "node:assert/strict";

import { Client, OwlAuthError } from "../dist/index.js";

const required = [
  "OWLAUTH_E2E_RUNTIME_BASE_URL",
  "OWLAUTH_E2E_PROJECT_ID",
  "OWLAUTH_E2E_APPLICATION_ID",
  "OWLAUTH_E2E_PUBLISHABLE_KEY",
  "OWLAUTH_E2E_REDIRECT_URI",
  "OWLAUTH_E2E_BROWSER_DRIVER_URL",
  "OWLAUTH_E2E_BROWSER_EVIDENCE_RUN_ID",
];

for (const name of required) {
  if (!process.env[name]) {
    throw new Error(
      `Missing ${name}. This explicit real-server suite never skips; see README.md for the E2E environment contract.`,
    );
  }
}

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

const client = new Client({
  baseUrl: process.env.OWLAUTH_E2E_RUNTIME_BASE_URL,
  projectId: process.env.OWLAUTH_E2E_PROJECT_ID,
  applicationId: process.env.OWLAUTH_E2E_APPLICATION_ID,
  publishableKey: process.env.OWLAUTH_E2E_PUBLISHABLE_KEY,
  allowInsecureLoopback: process.env.OWLAUTH_E2E_ALLOW_INSECURE_LOOPBACK === "1",
  timeoutMs: 15_000,
});

const configuration = await client.getPublicConfiguration();
assert.equal(configuration.loginAvailable, true);
assert.ok(configuration.providers.length > 0);

const credentials = await browserLogin(client);
const current = await client.currentUser(credentials.accessToken);
assert.equal(current.userId, credentials.userId);
assert.deepEqual(current.projection, credentials.projection);

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
  return true;
});

const logoutCredentials = await browserLogin(client);
await client.logoutApplication(logoutCredentials.accessToken);
await client.logoutApplication(logoutCredentials.accessToken);
await assert.rejects(client.currentUser(logoutCredentials.accessToken), (error) => {
  assert.ok(error instanceof OwlAuthError);
  assert.equal(error.category, "Authentication");
  return true;
});

process.stdout.write("TypeScript real-server Project Auth E2E passed.\n");

async function browserLogin(runtimeClient) {
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
  return runtimeClient.completeLogin(driverBody.callbackUrl, started.pending);
}
