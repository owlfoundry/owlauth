import assert from "node:assert/strict";
import test from "node:test";

import {
  AccessToken,
  Client,
  CredentialPair,
  OwlAuthError,
} from "../dist/index.js";

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
      login_available: true,
      future: "ignored",
    }),
    jsonResponse({
      keys: [{ kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig", kid: "kid", x: "abc" }],
      revision: 1,
      signing_epoch: 2,
    }),
  ];
  const instance = client(queuedFetch(responses));
  const config = await instance.getPublicConfiguration();
  assert.equal(config.providers[0].displayName, "OIDC");
  const jwks = await instance.getProjectJwks();
  assert.equal(jwks.signingEpoch, 2);
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
        assert.equal(error.category, "Protocol");
        assert.equal(error.code, fixture.code);
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
      const credentials = new CredentialPair({
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
          status: "active",
          createdAt: "2026-07-30T00:00:00Z",
          updatedAt: "2026-07-30T00:00:00Z",
        },
        projectionRevision: 1,
        sessionExpiresAt: "2026-08-30T00:00:00Z",
      });

      await assert.rejects(instance.refresh(credentials), (error) => {
        assert.ok(error instanceof OwlAuthError);
        assert.equal(error.category, "Protocol");
        assert.equal(error.code, fixture.code);
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
        future: true,
      },
      409,
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

test("credential context mismatch is a protocol error before refresh dispatch", async () => {
  const calls = [];
  const instance = client(queuedFetch([], calls));
  const foreign = new CredentialPair({
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

test("refresh transport ambiguity is quarantined and never replayed", async () => {
  const calls = [];
  const instance = client(queuedFetch([new Error("lost response")], calls));
  const credentials = new CredentialPair({
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
    instance.currentUser(new AccessToken("sentinel-access"), { signal: controller.signal }),
    (error) => error.category === "Cancelled" && error.code === "cancelled_before_dispatch",
  );
  assert.equal(calls.length, 0);
});
