import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const packageSpecifier = process.env.OWLAUTH_TYPESCRIPT_PACKAGE ?? "../dist/index.js";
const internalTypesSpecifier =
  process.env.OWLAUTH_TYPESCRIPT_INTERNAL_TYPES ?? "../dist/types.js";
const {
  AccessToken,
  Client,
  CredentialPair,
  OwlAuthError,
  PendingLogin,
  ValidatedCallback,
} = await import(packageSpecifier);
const { createCredentialPair } = await import(internalTypesSpecifier);

const NOW = Date.parse("2026-07-31T00:00:00Z");
const PROJECT = "project_public";
const APPLICATION = "application_public";
const KEY = "publishable_key";

function jsonResponse(value, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", ...extraHeaders },
  });
}

function rawJsonResponse(value, status = 200) {
  return new Response(value, {
    status,
    headers: { "content-type": "application/json" },
  });
}

function queuedFetch(responses, calls = []) {
  return async (input, init) => {
    calls.push({ url: String(input), init });
    const next = responses.shift();
    if (next instanceof Error) throw next;
    if (next === undefined) throw new Error("unexpected request");
    return typeof next === "function" ? next(input, init) : next;
  };
}

function client(fetch, overrides = {}) {
  return new Client({
    baseUrl: "https://identity.example/runtime/",
    projectId: PROJECT,
    applicationId: APPLICATION,
    publishableKey: KEY,
    fetch,
    now: () => NOW,
    ...overrides,
  });
}

function projection(revision = 1) {
  return {
    user_id: "usr_public",
    user_revision: 1,
    projection_schema: "owlauth.user.v1",
    projection_revision: revision,
    display_name: "Ada",
    picture_url: null,
    locale: "en-GB",
    verified_email: null,
    status: "active",
    created_at: "2026-07-30T00:00:00Z",
    updated_at: "2026-07-30T00:00:00Z",
  };
}

function credentialResponse(generation = 1) {
  return {
    project_id: PROJECT,
    application_id: APPLICATION,
    user_id: "usr_public",
    session_id: "00000000-0000-4000-8000-000000000001",
    refresh_generation: generation,
    access_token: `access-token-${generation}`,
    refresh_token: `refresh-token-${generation}`,
    token_type: "Bearer",
    expires_in: 300,
    projection: projection(1),
    projection_revision: 1,
    session_expires_at: "2026-08-30T00:00:00Z",
  };
}

function boundCredential(overrides = {}) {
  return createCredentialPair({
    runtimeOrigin: "https://identity.example",
    runtimeBasePath: "/runtime/",
    projectId: PROJECT,
    applicationId: APPLICATION,
    userId: "usr_public",
    sessionId: "00000000-0000-4000-8000-000000000001",
    refreshGeneration: 1,
    accessToken: "access",
    refreshToken: "refresh",
    expiresIn: 60,
    projection: {
      userId: "usr_public",
      userRevision: 1,
      projectionSchema: "owlauth.user.v1",
      projectionRevision: 1,
      displayName: null,
      pictureUrl: null,
      locale: null,
      verifiedEmail: null,
      status: "active",
      createdAt: "2026-07-30T00:00:00Z",
      updatedAt: "2026-07-30T00:00:00Z",
    },
    projectionRevision: 1,
    sessionExpiresAt: "2026-08-30T00:00:00Z",
    ...overrides,
  });
}

function fixedCrypto(bytes) {
  return {
    subtle: globalThis.crypto.subtle,
    getRandomValues(target) {
      target.set(bytes.subarray(0, target.byteLength));
      return target;
    },
  };
}

function decodeBase64Url(value) {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  return new Uint8Array(Buffer.from(value.replaceAll("-", "+").replaceAll("_", "/") + padding, "base64"));
}

async function begin(clientInstance, responses) {
  responses.push(
    jsonResponse(
      {
        hosted_url: "https://identity.example/runtime/auth/interactions/opaque",
        expires_at: "2026-07-31T00:10:00Z",
      },
      201,
    ),
  );
  return clientInstance.beginLogin({
    redirectUri: "https://app.example/callback",
    state: "application-state",
  });
}

test("Client enforces secure immutable Runtime context and preserves a path prefix", async () => {
  assert.throws(
    () =>
      new Client({
        baseUrl: "http://identity.example/",
        projectId: PROJECT,
        applicationId: APPLICATION,
        publishableKey: KEY,
      }),
    (error) => error instanceof OwlAuthError && error.category === "Configuration",
  );
  assert.throws(
    () =>
      new Client({
        baseUrl: "http://127.0.0.1:8080/",
        projectId: PROJECT,
        applicationId: APPLICATION,
        publishableKey: KEY,
      }),
    OwlAuthError,
  );
  for (const baseUrl of [
    "https://identity.example/runtime\\control",
    "https://identity.example/runtime/%2f/control",
    "https://identity.example/runtime/%5c/control",
    "https://identity.example/runtime/../control",
    "https://identity.example/runtime/%2e%2e/control",
    "https://identity.example/runtime/%252e%252e/control",
  ]) {
    assert.throws(
      () =>
        new Client({
          baseUrl,
          projectId: PROJECT,
          applicationId: APPLICATION,
          publishableKey: KEY,
        }),
      OwlAuthError,
    );
  }
  const calls = [];
  const instance = new Client({
    baseUrl: "http://127.0.0.1:8080/prefix",
    projectId: PROJECT,
    applicationId: APPLICATION,
    publishableKey: KEY,
    allowInsecureLoopback: true,
    fetch: queuedFetch([
      jsonResponse({
        project_public_id: PROJECT,
        project_display_name: "Project",
        application_public_id: APPLICATION,
        application_display_name: "App",
        publishable_keys: [KEY],
        providers: [],
        email_available: true,
        email_otp_enabled: true,
        email_magic_link_enabled: true,
        login_available: true,
      }),
    ], calls),
  });
  await instance.getPublicConfiguration();
  assert.equal(new URL(calls[0].url).pathname, `/prefix/v1/projects/${PROJECT}/auth/config`);
});

test("beginLogin derives the RFC S256 vector and returns redacted explicit state", async () => {
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const calls = [];
  const responses = [];
  const instance = client(queuedFetch(responses, calls), {
    crypto: fixedCrypto(decodeBase64Url(verifier)),
  });
  const result = await begin(instance, responses);
  const request = JSON.parse(calls[0].init.body);
  assert.equal(request.pkce_challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  assert.equal(request.state, "application-state");
  assert.equal(result.hostedUrl, "https://identity.example/runtime/auth/interactions/opaque");
  assert.equal(result.pending.consumed, false);
  assert.match(String(result.pending), /REDACTED/u);
  assert.doesNotMatch(String(result.pending), new RegExp(verifier, "u"));
  const serialized = JSON.stringify(result.pending);
  assert.equal(serialized.includes(verifier), false);
  assert.equal(serialized.includes("application-state"), false);
  assert.equal(JSON.parse(serialized).state, "[REDACTED]");
});

test("redirect validation matches reviewed web, loopback, and private-scheme policy", async () => {
  const instance = client(queuedFetch([]));
  for (const redirectUri of [
    "javascript:alert(1)",
    "ftp://app.example/callback",
    "https://app.example/callback?error=reserved",
    "https://app.example/callback?handoff=reserved",
    "https://app.example/callback?state=reserved",
  ]) {
    await assert.rejects(
      instance.beginLogin({ redirectUri }),
      (error) => error instanceof OwlAuthError && error.code === "invalid_redirect_uri",
    );
  }

  const responses = [];
  const native = client(queuedFetch(responses));
  responses.push(
    jsonResponse(
      {
        hosted_url: "https://identity.example/runtime/auth/interactions/native",
        expires_at: "2026-07-31T00:10:00Z",
      },
      201,
    ),
  );
  const started = await native.beginLogin({ redirectUri: "com.example.app:/callback" });
  assert.equal(started.pending.redirectUri, "com.example.app:/callback");
});

test("callback validation is local, exact, expiring, and one-attempt", async () => {
  const calls = [];
  const responses = [];
  const instance = client(queuedFetch(responses, calls));
  const { pending } = await begin(instance, responses);
  assert.throws(
    () =>
      instance.validateCallback(
        "https://app.example/callback?handoff=ticket&state=wrong",
        pending,
      ),
    (error) =>
      error instanceof OwlAuthError &&
      error.category === "Handoff" &&
      error.action === "discard_pending",
  );
  assert.equal(calls.length, 1);
  assert.equal(pending.consumed, false);
  const callback = instance.validateCallback(
    "https://app.example/callback?handoff=ticket&state=application-state",
    pending,
  );
  assert.equal(pending.consumed, false);
  responses.push(jsonResponse(credentialResponse(1)));
  await instance.exchangeHandoff(callback);
  assert.equal(pending.consumed, true);
  assert.throws(
    () =>
      instance.validateCallback(
        "https://app.example/callback?handoff=ticket&state=application-state",
        pending,
      ),
    (error) => error instanceof OwlAuthError && error.code === "pending_consumed",
  );

  const expiringResponses = [];
  const expiring = client(queuedFetch(expiringResponses), { now: () => NOW + 700_000 });
  const originalNowResponses = [];
  const original = client(queuedFetch(originalNowResponses));
  const started = await begin(original, originalNowResponses);
  assert.throws(
    () =>
      expiring.validateCallback(
        "https://app.example/callback?handoff=ticket&state=application-state",
        started.pending,
      ),
    OwlAuthError,
  );
});

test("handoff, current user, refresh, and both logout modes preserve context", async () => {
  const calls = [];
  const responses = [];
  const instance = client(queuedFetch(responses, calls));
  const { pending } = await begin(instance, responses);
  const callback = instance.validateCallback(
    "https://app.example/callback?handoff=one-use-ticket&state=application-state",
    pending,
  );
  assert.equal(String(callback).includes("one-use-ticket"), false);
  assert.equal(JSON.stringify(callback).includes("one-use-ticket"), false);
  responses.push(jsonResponse(credentialResponse(1)));
  const credentials = await instance.exchangeHandoff(callback);
  assert.equal(credentials.projectId, PROJECT);
  assert.equal(credentials.refreshGeneration, 1);
  assert.equal(credentials.accessToken.expose(), "access-token-1");
  assert.match(String(credentials), /REDACTED/u);
  assert.equal(JSON.stringify(credentials).includes("refresh-token-1"), false);

  responses.push(
    jsonResponse({
      project_id: PROJECT,
      application_id: APPLICATION,
      user_id: "usr_public",
      projection: projection(1),
      projection_revision: 1,
      authenticated_at: "2026-07-31T00:00:00Z",
      session_expires_at: "2026-08-30T00:00:00Z",
    }),
  );
  const current = await instance.currentUser(credentials.accessToken);
  assert.equal(current.projection.displayName, "Ada");

  responses.push(jsonResponse(credentialResponse(2)));
  const successor = await instance.refresh(credentials);
  assert.equal(successor.refreshGeneration, 2);
  const refreshBody = JSON.parse(calls.at(-1).init.body);
  assert.equal(refreshBody.refresh_token, "refresh-token-1");

  responses.push(jsonResponse({ completed: true }));
  await instance.logoutApplication(successor.accessToken);
  assert.equal(calls.at(-1).init.headers.authorization, "Bearer access-token-2");

  responses.push(
    jsonResponse(
      {
        hosted_url: "https://identity.example/runtime/auth/browser-logout/preparation",
        expires_at: "2026-07-31T00:01:00Z",
      },
      201,
    ),
  );
  const logout = await instance.prepareBrowserLogout(successor.accessToken);
  assert.equal(logout.hostedUrl, "https://identity.example/runtime/auth/browser-logout/preparation");
  assert.equal(calls.filter((call) => call.init.method === "POST").length, 5);
});

test("public configuration and JWKS are bounded and context checked", async () => {
  const responses = [
    jsonResponse({
      project_public_id: PROJECT,
      project_display_name: "Project",
      application_public_id: APPLICATION,
      application_display_name: "App",
      publishable_keys: [KEY],
      providers: [{ key: "oidc", display_name: "OIDC", kind: "oidc", future: true }],
      email_available: false,
      email_otp_enabled: false,
      email_magic_link_enabled: false,
      login_available: true,
      future: "ignored",
    }),
    jsonResponse({
      keys: [{ kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig", kid: "kid", x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }],
      revision: 1,
      signing_epoch: 2,
    }),
  ];
  const instance = client(queuedFetch(responses));
  const config = await instance.getPublicConfiguration();
  assert.equal(config.providers[0].displayName, "OIDC");
  assert.equal(config.emailAvailable, false);
  const jwks = await instance.getProjectJwks();
  assert.equal(jwks.signingEpoch, 2);
});

test("optional debug hook emits one closed redacted completion event", async () => {
  const events = [];
  const instance = client(
    queuedFetch([
      jsonResponse({
        project_public_id: PROJECT,
        project_display_name: "Project",
        application_public_id: APPLICATION,
        application_display_name: "App",
        publishable_keys: [KEY],
        providers: [],
        email_available: false,
        email_otp_enabled: false,
        email_magic_link_enabled: false,
        login_available: true,
      }),
    ]),
    {
      debugHook(event) {
        events.push(event);
        throw new Error("observer failure must be isolated");
      },
    },
  );
  await instance.getPublicConfiguration();
  assert.deepEqual(events, [
    {
      operation: "get_public_application_config",
      method: "GET",
      outcome: "success",
      elapsedMs: 0,
      dispatched: true,
      status: 200,
    },
  ]);
  const serialized = JSON.stringify(events);
  assert.equal(serialized.includes(KEY), false);
  assert.equal(serialized.includes("identity.example"), false);
  assert.equal(serialized.includes("publishable_key"), false);
});

test("one-use transport ambiguity is Indeterminate and never retried", async () => {
  const calls = [];
  const responses = [];
  const instance = client(queuedFetch(responses, calls));
  const { pending } = await begin(instance, responses);
  const callback = instance.validateCallback(
    "https://app.example/callback?handoff=sentinel-handoff&state=application-state",
    pending,
  );
  responses.push(new Error("sentinel-handoff must not leak"));
  await assert.rejects(
    instance.exchangeHandoff(callback),
    (error) => {
      assert.ok(error instanceof OwlAuthError);
      assert.equal(error.category, "Indeterminate");
      assert.equal(error.retry, "never");
      assert.equal(error.action, "quarantine_pending");
      assert.equal(String(error).includes("sentinel-handoff"), false);
      assert.equal(String(error.cause).includes("sentinel-handoff"), false);
      return true;
    },
  );
  assert.equal(calls.length, 2);
  await assert.rejects(instance.exchangeHandoff(callback), (error) => error.code === "handoff_already_attempted");
  assert.equal(calls.length, 2);
});

test("handoff success-response failures quarantine pending state without retry", async (t) => {
  const cases = [
    {
      name: "malformed JSON",
      response: () => rawJsonResponse('{"access_token":"sentinel-response-secret"'),
      code: "invalid_response",
    },
    {
      name: "malformed shape",
      response: () => jsonResponse({ access_token: "sentinel-response-secret" }),
      code: "context_mismatch",
    },
    {
      name: "context mismatch",
      response: () =>
        jsonResponse({
          ...credentialResponse(1),
          project_id: "another_project",
          access_token: "sentinel-response-secret",
        }),
      code: "context_mismatch",
    },
    {
      name: "access token contains header controls",
      response: () => jsonResponse({ ...credentialResponse(1), access_token: "bad\r\nheader" }),
      code: "invalid_response",
    },
    {
      name: "refresh token is not opaque token grammar",
      response: () => jsonResponse({ ...credentialResponse(1), refresh_token: "bad token" }),
      code: "invalid_response",
    },
  ];

  for (const fixture of cases) {
    await t.test(fixture.name, async () => {
      const calls = [];
      const responses = [];
      const instance = client(queuedFetch(responses, calls));
      const { pending } = await begin(instance, responses);
      const callback = instance.validateCallback(
        "https://app.example/callback?handoff=sentinel-handoff&state=application-state",
        pending,
      );
      responses.push(fixture.response());

      await assert.rejects(instance.exchangeHandoff(callback), (error) => {
        assert.ok(error instanceof OwlAuthError);
        assert.equal(error.category, "Indeterminate");
        assert.equal(error.code, "invalid_response_after_dispatch");
        assert.equal(error.status, 200);
        assert.equal(error.retry, "never");
        assert.equal(error.action, "quarantine_pending");
        assert.equal(String(error).includes("sentinel"), false);
        assert.equal(String(error.cause).includes("sentinel"), false);
        return true;
      });
      assert.equal(calls.length, 2);
      await assert.rejects(
        instance.exchangeHandoff(callback),
        (error) => error instanceof OwlAuthError && error.code === "handoff_already_attempted",
      );
      assert.equal(calls.length, 2);
    });
  }
});

test("refresh success-response failures quarantine credentials without retry", async (t) => {
  const cases = [
    {
      name: "malformed JSON",
      response: () => rawJsonResponse('{"refresh_token":"sentinel-response-secret"'),
      code: "invalid_response",
    },
    {
      name: "malformed shape",
      response: () => jsonResponse({ refresh_token: "sentinel-response-secret" }),
      code: "context_mismatch",
    },
    {
      name: "context mismatch",
      response: () =>
        jsonResponse({
          ...credentialResponse(2),
          application_id: "another_application",
          refresh_token: "sentinel-response-secret",
        }),
      code: "context_mismatch",
    },
    {
      name: "non-successor generation",
      response: () => jsonResponse(credentialResponse(1)),
      code: "credential_generation_mismatch",
    },
  ];

  for (const fixture of cases) {
    await t.test(fixture.name, async () => {
      const calls = [];
      const instance = client(queuedFetch([fixture.response()], calls));
      const credentials = createCredentialPair({
        runtimeOrigin: "https://identity.example",
        runtimeBasePath: "/runtime/",
        projectId: PROJECT,
        applicationId: APPLICATION,
        userId: "usr_public",
        sessionId: "00000000-0000-4000-8000-000000000001",
        refreshGeneration: 1,
        accessToken: "sentinel-access",
        refreshToken: "sentinel-refresh",
        expiresIn: 60,
        projection: {
          userId: "usr_public",
          userRevision: 1,
          projectionSchema: "owlauth.user.v1",
          projectionRevision: 1,
          displayName: null,
          pictureUrl: null,
          locale: null,
          verifiedEmail: null,
          status: "active",
          createdAt: "2026-07-30T00:00:00Z",
          updatedAt: "2026-07-30T00:00:00Z",
        },
        projectionRevision: 1,
        sessionExpiresAt: "2026-08-30T00:00:00Z",
      });

      await assert.rejects(instance.refresh(credentials), (error) => {
        assert.ok(error instanceof OwlAuthError);
        assert.equal(error.category, "Indeterminate");
        assert.equal(error.code, "invalid_response_after_dispatch");
        assert.equal(error.status, 200);
        assert.equal(error.retry, "never");
        assert.equal(error.action, "quarantine_credentials");
        assert.equal(String(error).includes("sentinel"), false);
        assert.equal(String(error.cause).includes("sentinel"), false);
        return true;
      });
      assert.equal(calls.length, 1);
    });
  }
});

test("unknown Runtime errors remain conservative and secret-free", async () => {
  const responses = [
    jsonResponse(
      {
        code: "future_runtime_code",
        message: "unreviewed sentinel secret",
        request_id: "request-public",
      },
      404,
    ),
  ];
  const instance = client(queuedFetch(responses));
  await assert.rejects(instance.getProjectJwks(), (error) => {
    assert.ok(error instanceof OwlAuthError);
    assert.equal(error.code, "future_runtime_code");
    assert.equal(error.category, "Protocol");
    assert.equal(error.retry, "never");
    assert.equal(error.requestId, "request-public");
    assert.equal(String(error).includes("sentinel"), false);
    return true;
  });
});

test("secret-bearing lifecycle construction is reserved for Client results", () => {
  assert.throws(() => new AccessToken(Symbol("external"), "secret", {}), TypeError);
  assert.throws(() => new CredentialPair(Symbol("external"), {}), TypeError);
  assert.throws(() => new PendingLogin(Symbol("external"), {}), TypeError);
  assert.throws(() => new ValidatedCallback(Symbol("external"), "handoff", {}), TypeError);
});

test("credential context mismatch is a protocol error before refresh dispatch", async () => {
  const calls = [];
  const instance = client(queuedFetch([], calls));
  const foreign = createCredentialPair({
    runtimeOrigin: "https://identity.example",
    runtimeBasePath: "/runtime/",
    projectId: "another_project",
    applicationId: APPLICATION,
    userId: "usr_public",
    sessionId: "session",
    refreshGeneration: 1,
    accessToken: "access",
    refreshToken: "refresh",
    expiresIn: 60,
    projection: {
      userId: "usr_public",
      userRevision: 1,
      projectionSchema: "owlauth.user.v1",
      projectionRevision: 1,
      displayName: null,
      pictureUrl: null,
      locale: null,
      verifiedEmail: null,
      status: "active",
      createdAt: "2026-07-30T00:00:00Z",
      updatedAt: "2026-07-30T00:00:00Z",
    },
    projectionRevision: 1,
    sessionExpiresAt: "2026-08-30T00:00:00Z",
  });
  await assert.rejects(instance.refresh(foreign), (error) => error.category === "Protocol");
  assert.equal(calls.length, 0);
});

test("credentials are bound to exact Runtime origin and base path before dispatch", async () => {
  for (const overrides of [
    { runtimeOrigin: "https://other.example" },
    { runtimeBasePath: "/other/" },
  ]) {
    const calls = [];
    const instance = client(queuedFetch([], calls));
    const foreign = boundCredential(overrides);
    await assert.rejects(instance.refresh(foreign), (error) => error.code === "credential_context_mismatch");
    await assert.rejects(
      instance.currentUser(foreign.accessToken),
      (error) => error.code === "credential_context_mismatch",
    );
    assert.equal(calls.length, 0);
  }
});

test("explicit pending and credential records restore only into the exact Client context", async () => {
  const responses = [];
  const instance = client(queuedFetch(responses));
  const started = await begin(instance, responses);
  const pendingRecord = started.pending.exportRecord();
  assert.equal(pendingRecord.state, "application-state");
  assert.equal(JSON.stringify(started.pending).includes(pendingRecord.verifier), false);
  const restoredPending = instance.restorePendingLogin(structuredClone(pendingRecord));
  responses.push(jsonResponse(credentialResponse(1)));
  const credentials = await instance.completeLogin(
    "https://app.example/callback?handoff=ticket&state=application-state",
    restoredPending,
  );
  const credentialRecord = credentials.exportRecord();
  assert.equal(credentialRecord.accessToken, "access-token-1");
  assert.equal(JSON.stringify(credentials).includes(credentialRecord.accessToken), false);
  const restoredCredentials = instance.restoreCredentialPair(structuredClone(credentialRecord));
  assert.equal(restoredCredentials.refreshGeneration, 1);

  for (const invalid of [
    { ...pendingRecord, runtimeOrigin: "https://other.example" },
    { ...pendingRecord, unexpected: true },
  ]) {
    assert.throws(() => instance.restorePendingLogin(invalid), OwlAuthError);
  }
  for (const invalid of [
    { ...credentialRecord, runtimeBasePath: "/other/" },
    { ...credentialRecord, accessToken: "bad\r\nheader" },
    { ...credentialRecord, refreshToken: "bad token" },
    { ...credentialRecord, unexpected: true },
  ]) {
    assert.throws(() => instance.restoreCredentialPair(invalid), OwlAuthError);
  }
});

test("refresh transport ambiguity is quarantined and never replayed", async () => {
  const calls = [];
  const instance = client(queuedFetch([new Error("lost response")], calls));
  const credentials = createCredentialPair({
    runtimeOrigin: "https://identity.example",
    runtimeBasePath: "/runtime/",
    projectId: PROJECT,
    applicationId: APPLICATION,
    userId: "usr_public",
    sessionId: "session",
    refreshGeneration: 1,
    accessToken: "access",
    refreshToken: "refresh",
    expiresIn: 60,
    projection: {
      userId: "usr_public",
      userRevision: 1,
      projectionSchema: "owlauth.user.v1",
      projectionRevision: 1,
      displayName: null,
      pictureUrl: null,
      locale: null,
      verifiedEmail: null,
      status: "active",
      createdAt: "2026-07-30T00:00:00Z",
      updatedAt: "2026-07-30T00:00:00Z",
    },
    projectionRevision: 1,
    sessionExpiresAt: "2026-08-30T00:00:00Z",
  });
  await assert.rejects(instance.refresh(credentials), (error) => {
    assert.equal(error.category, "Indeterminate");
    assert.equal(error.action, "quarantine_credentials");
    return true;
  });
  assert.equal(calls.length, 1);
});

test("pre-dispatch cancellation performs no request", async () => {
  const calls = [];
  const controller = new AbortController();
  controller.abort();
  const instance = client(queuedFetch([], calls));
  await assert.rejects(
    instance.currentUser(boundCredential().accessToken, { signal: controller.signal }),
    (error) => error.category === "Cancelled" && error.code === "cancelled_before_dispatch",
  );
  assert.equal(calls.length, 0);
});


test("user projection requires the exact schema and explicit nullable fields", async () => {
  const fixture = JSON.parse(
    await readFile(
      path.resolve(
        path.dirname(fileURLToPath(import.meta.url)),
        "../../spec/fixtures/user-projection-invalid-values.json",
      ),
      "utf8",
    ),
  );
  const currentResponse = (wireProjection) =>
    jsonResponse({
      project_id: PROJECT,
      application_id: APPLICATION,
      user_id: "usr_public",
      projection: wireProjection,
      projection_revision: 1,
      authenticated_at: "2026-07-31T00:00:00Z",
      session_expires_at: "2026-08-30T00:00:00Z",
    });

  const nullable = projection(1);
  nullable.locale = null;
  nullable.verified_email = null;
  const accepted = await client(queuedFetch([currentResponse(nullable)])).currentUser(
    boundCredential().accessToken,
  );
  assert.equal(accepted.projection.locale, null);
  assert.equal(accepted.projection.verifiedEmail, null);

  const fixtureInvalid = fixture.invalidPatches.map(({ field, value }) => ({
    ...fixture.projection,
    [field]: value,
  }));
  for (const invalid of [
    { ...projection(1), projection_schema: "owlauth.project_user.v1" },
    Object.fromEntries(Object.entries(projection(1)).filter(([key]) => key !== "locale")),
    { ...projection(1), unexpected: true },
    ...fixtureInvalid,
  ]) {
    await assert.rejects(
      client(queuedFetch([currentResponse(invalid)])).currentUser(boundCredential().accessToken),
      OwlAuthError,
    );
  }
});
