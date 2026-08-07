import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const packageSpecifier = process.env.OWLAUTH_TYPESCRIPT_PACKAGE ?? "../dist/index.js";
const { Client, OwlAuthError } = await import(packageSpecifier);

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const specRoot = path.resolve(packageRoot, "../spec");
const fixturesRoot = path.join(specRoot, "fixtures") + path.sep;
const corpusPath = path.join(specRoot, "conformance/cases.json");
const BASE_URL = "https://runtime.conformance.example/";
const REDIRECT = "https://application.example/callback";
const NOW = Date.parse("2099-01-01T00:00:00Z");
const OPERATIONS = new Set([
  "get_public_application_config",
  "get_project_jwks",
  "start_login",
  "exchange_handoff",
  "refresh_session",
  "get_current_user",
  "logout_application_session",
  "prepare_browser_logout",
]);

async function loadJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

function exactObject(value, required, optional = [], label = "object") {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert.deepEqual(
    Object.keys(value).sort(),
    [...required, ...optional.filter((key) => Object.hasOwn(value, key))].sort(),
    `${label} fields`,
  );
}

function boundedString(value, maximum) {
  assert.equal(typeof value, "string");
  assert.ok(value.length >= 1 && value.length <= maximum);
}

function validateExpected(expected) {
  const common = ["outcome", "pendingDisposition", "credentialDisposition"];
  if (expected.outcome === "success") {
    exactObject(expected, common, ["values"], "expected success");
    if (expected.values !== undefined) exactObject(expected.values, Object.keys(expected.values), [], "values");
  } else {
    assert.equal(expected.outcome, "error");
    exactObject(
      expected,
      [...common, "category", "code", "retry", "action"],
      ["retryAfterSeconds"],
      "expected error",
    );
    for (const key of ["category", "code", "retry", "action"]) boundedString(expected[key], 64);
    if (expected.retryAfterSeconds !== undefined) {
      assert.ok(Number.isInteger(expected.retryAfterSeconds));
      assert.ok(expected.retryAfterSeconds >= 0 && expected.retryAfterSeconds <= 86_400);
    }
  }
  assert.ok(
    new Set(["not_applicable", "preserved", "discard_required", "quarantined", "consumed"]).has(
      expected.pendingDisposition,
    ),
  );
  assert.ok(
    new Set([
      "not_applicable",
      "preserved",
      "replaced",
      "cleared",
      "invalidated",
      "quarantined",
      "reauthentication_required",
    ]).has(expected.credentialDisposition),
  );
  if (expected.outcome === "error") {
    const pendingActions = new Map([
      ["discard_required", "discard_pending"],
      ["quarantined", "quarantine_pending"],
    ]);
    const credentialActions = new Map([
      ["invalidated", "invalidate_credentials"],
      ["quarantined", "quarantine_credentials"],
      ["reauthentication_required", "reauthenticate"],
    ]);
    const required = pendingActions.get(expected.pendingDisposition) ?? credentialActions.get(expected.credentialDisposition);
    if (required !== undefined) assert.equal(expected.action, required);
    if (expected.credentialDisposition === "preserved") assert.equal(expected.action, "none");
  }
}

function validateFixture(fixture) {
  exactObject(fixture, ["schemaVersion", "synthetic", "exchange"], ["redactionSentinels"], "fixture");
  assert.equal(fixture.schemaVersion, 3);
  assert.equal(fixture.synthetic, true);
  const exchange = fixture.exchange;
  if (exchange.kind === "http") {
    exactObject(exchange, ["kind", "status", "headers", "body"], ["request"], "http exchange");
    assert.ok(Number.isInteger(exchange.status) && exchange.status >= 100 && exchange.status <= 599);
    exactObject(exchange.headers, Object.keys(exchange.headers), [], "headers");
    for (const [name, value] of Object.entries(exchange.headers)) {
      boundedString(name, 128);
      assert.equal(typeof value, "string");
      assert.ok(value.length <= 512);
    }
    const bodyFields = {
      json: ["encoding", "value"],
      text: ["encoding", "value"],
      empty: ["encoding"],
      base64: ["encoding", "value"],
      repeat: ["encoding", "value", "count"],
    }[exchange.body?.encoding];
    assert.ok(bodyFields, "unsupported body encoding");
    exactObject(exchange.body, bodyFields, [], "body");
    if (exchange.body.encoding === "text") {
      boundedString(exchange.body.value, 65_536);
      assert.ok(new TextEncoder().encode(exchange.body.value).length <= 65_536);
    } else if (exchange.body.encoding === "base64") {
      boundedString(exchange.body.value, 87_384);
      const decoded = Buffer.from(exchange.body.value, "base64");
      assert.equal(decoded.toString("base64"), exchange.body.value);
      assert.ok(decoded.byteLength <= 65_536);
    } else if (exchange.body.encoding === "repeat") {
      assert.equal(typeof exchange.body.value, "string");
      assert.equal(new TextEncoder().encode(exchange.body.value).length, 1);
      assert.ok(Number.isInteger(exchange.body.count));
      assert.ok(exchange.body.count >= 0 && exchange.body.count <= 65_537);
    }
    if (exchange.request !== undefined) {
      exactObject(exchange.request, ["method", "body"], [], "request assertion");
      assert.ok(["GET", "POST"].includes(exchange.request.method));
      assert.ok(["absent", "json"].includes(exchange.request.body));
    }
  } else if (exchange.kind === "callback") {
    exactObject(exchange, ["kind", "attempts", "clockOffsetSeconds"], [], "callback exchange");
    assert.ok(
      Array.isArray(exchange.attempts) &&
        exchange.attempts.length > 0 &&
        exchange.attempts.every((value) => ["success", "error", "ambiguous", "state_mismatch"].includes(value)),
    );
    assert.ok(Number.isInteger(exchange.clockOffsetSeconds));
    assert.ok(exchange.clockOffsetSeconds >= 0 && exchange.clockOffsetSeconds <= 86_400);
  } else if (exchange.kind === "transportFailure") {
    exactObject(exchange, ["kind", "failureKind", "requestPhase"], [], "transport exchange");
    assert.ok(["transport", "timeout", "cancelled"].includes(exchange.failureKind));
    assert.ok(["before_dispatch", "possibly_dispatched"].includes(exchange.requestPhase));
  } else {
    assert.fail(`unsupported fixture kind: ${exchange.kind}`);
  }
  assert.ok(
    Array.isArray(fixture.redactionSentinels ?? []) &&
      (fixture.redactionSentinels ?? []).every(
        (value) => typeof value === "string" && value.length > 0 && value.length <= 256,
      ),
  );
}

async function validateCorpus(document) {
  exactObject(document, ["schemaVersion", "requiredCaseNames", "cases"], [], "corpus");
  assert.equal(document.schemaVersion, 3, "unsupported corpus schema version");
  assert.ok(Array.isArray(document.requiredCaseNames) && document.requiredCaseNames.length > 0);
  for (const name of document.requiredCaseNames) boundedString(name, 128);
  assert.equal(new Set(document.requiredCaseNames).size, document.requiredCaseNames.length);
  assert.ok(Array.isArray(document.cases) && document.cases.length > 0);
  const names = new Set();
  for (const entry of document.cases) {
    exactObject(
      entry,
      [
        "name",
        "required",
        "capability",
        "operationId",
        "fixture",
        "precondition",
        "requestPhase",
        "responseReceived",
        "evidenceLevel",
        "configuredContext",
        "expected",
      ],
      ["platformCapability"],
      "case",
    );
    boundedString(entry.name, 128);
    assert.equal(names.has(entry.name), false, `duplicate case: ${entry.name}`);
    names.add(entry.name);
    assert.equal(entry.required, true);
    boundedString(entry.capability, 64);
    assert.ok(OPERATIONS.has(entry.operationId), `unsupported required capability: ${entry.operationId}`);
    boundedString(entry.fixture, 256);
    assert.ok(["none", "pending_login", "credential_pair"].includes(entry.precondition));
    assert.ok(["before_dispatch", "possibly_dispatched", "response_received"].includes(entry.requestPhase));
    assert.equal(entry.responseReceived, entry.requestPhase === "response_received");
    assert.equal(entry.evidenceLevel, "deterministic");
    if (entry.platformCapability !== undefined) boundedString(entry.platformCapability, 64);
    exactObject(entry.configuredContext, ["projectId", "applicationId", "publishableKey"], [], "context");
    for (const value of Object.values(entry.configuredContext)) boundedString(value, 128);
    validateExpected(entry.expected);
    const fixturePath = path.resolve(path.dirname(corpusPath), entry.fixture);
    assert.ok(fixturePath.startsWith(fixturesRoot), `fixture escapes corpus root: ${entry.name}`);
    entry.loadedFixture = await loadJson(fixturePath);
    validateFixture(entry.loadedFixture);
    const kind = entry.loadedFixture.exchange.kind;
    assert.equal(kind === "http", entry.responseReceived);
    if (kind === "transportFailure") assert.equal(entry.loadedFixture.exchange.requestPhase, entry.requestPhase);
  }
  assert.equal(names.size, document.requiredCaseNames.length);
  assert.deepEqual([...names].sort(), [...document.requiredCaseNames].sort());
  return document.cases;
}

function responseFor(fixture) {
  const { status, headers, body } = fixture.exchange;
  let encoded;
  if (body.encoding === "json") encoded = JSON.stringify(body.value);
  else if (body.encoding === "text") encoded = body.value;
  else if (body.encoding === "empty") encoded = "";
  else if (body.encoding === "base64") encoded = Uint8Array.from(Buffer.from(body.value, "base64"));
  else encoded = body.value.repeat(body.count);
  return new Response(encoded, { status, headers });
}

function failureFor(fixture) {
  const kind = fixture.exchange.failureKind;
  if (kind === "timeout") return new DOMException("synthetic timeout", "TimeoutError");
  if (kind === "cancelled") return new DOMException("synthetic cancellation", "AbortError");
  return new Error("synthetic transport failure");
}

function context(entry) {
  return entry.configuredContext;
}

function makeClient(entry, outcomes, calls, now = () => NOW) {
  const configured = context(entry);
  return new Client({
    baseUrl: BASE_URL,
    projectId: configured.projectId,
    applicationId: configured.applicationId,
    publishableKey: configured.publishableKey,
    now,
    timeoutMs: 20,
    fetch: async (_input, init) => {
      calls.push(init);
      const outcome = outcomes.shift();
      if (outcome instanceof Error) throw outcome;
      return outcome;
    },
  });
}

function callbackUrl(kind, state) {
  if (kind === "success") return `${REDIRECT}?handoff=synthetic-handoff&state=${state}`;
  if (kind === "error") return `${REDIRECT}?error=provider_rejected&state=${state}`;
  if (kind === "ambiguous") {
    return `${REDIRECT}?handoff=synthetic-handoff&error=provider_rejected&state=${state}`;
  }
  return `${REDIRECT}?handoff=synthetic-handoff&state=wrong`;
}

async function setupCredential(client) {
  const started = await client.beginLogin({ redirectUri: REDIRECT });
  return client.completeLogin(callbackUrl("success", started.pending.state), started.pending);
}

async function invokeHttp(entry, setup) {
  const calls = [];
  const outcomes = [];
  if (entry.precondition === "pending_login") outcomes.push(responseFor(setup.login));
  if (entry.precondition === "credential_pair") {
    outcomes.push(responseFor(setup.login), responseFor(setup.credential));
  }
  outcomes.push(responseFor(entry.loadedFixture));
  const client = makeClient(entry, outcomes, calls);
  let pending;
  let result;
  switch (entry.operationId) {
    case "get_public_application_config":
      result = await client.getPublicConfiguration();
      break;
    case "get_project_jwks":
      result = await client.getProjectJwks();
      break;
    case "start_login":
      result = await client.beginLogin({ redirectUri: REDIRECT });
      pending = result.pending;
      break;
    case "exchange_handoff": {
      const started = await client.beginLogin({ redirectUri: REDIRECT });
      pending = started.pending;
      result = await client.completeLogin(callbackUrl("success", pending.state), pending);
      break;
    }
    case "refresh_session":
      result = await client.refresh(await setupCredential(client));
      break;
    case "get_current_user": {
      const credentials = await setupCredential(client);
      result = await client.currentUser(credentials.accessToken);
      break;
    }
    case "logout_application_session": {
      const credentials = await setupCredential(client);
      result = await client.logoutApplication(credentials.accessToken);
      break;
    }
    case "prepare_browser_logout": {
      const credentials = await setupCredential(client);
      result = await client.prepareBrowserLogout(credentials.accessToken);
      break;
    }
    default:
      assert.fail(entry.operationId);
  }
  return { result, calls, pending };
}

async function invokeCallback(entry, setup) {
  const calls = [];
  let offset = 0;
  const client = makeClient(entry, [responseFor(setup.login)], calls, () => NOW + offset * 1000);
  const started = await client.beginLogin({ redirectUri: REDIRECT });
  offset = entry.loadedFixture.exchange.clockOffsetSeconds;
  let result;
  for (const attempt of entry.loadedFixture.exchange.attempts) {
    try {
      result = client.validateCallback(callbackUrl(attempt, started.pending.state), started.pending);
    } catch (error) {
      if (attempt !== entry.loadedFixture.exchange.attempts.at(-1)) continue;
      throw error;
    }
  }
  return { result, calls, pending: started.pending };
}

async function invokeTransport(entry, setup) {
  const calls = [];
  const outcomes = [];
  if (entry.precondition === "pending_login") outcomes.push(responseFor(setup.login));
  if (entry.precondition === "credential_pair") {
    outcomes.push(responseFor(setup.login), responseFor(setup.credential));
  }
  outcomes.push(failureFor(entry.loadedFixture));
  const client = makeClient(entry, outcomes, calls);
  const controller = new AbortController();
  if (entry.requestPhase === "before_dispatch") {
    const reason =
      entry.loadedFixture.exchange.failureKind === "timeout"
        ? new DOMException("synthetic timeout", "TimeoutError")
        : new DOMException("synthetic cancellation", "AbortError");
    controller.abort(reason);
  }
  const options = entry.requestPhase === "before_dispatch" ? { signal: controller.signal } : {};
  let pending;
  let result;
  if (entry.operationId === "get_public_application_config") {
    result = await client.getPublicConfiguration(options);
  } else if (entry.operationId === "exchange_handoff") {
    const started = await client.beginLogin({ redirectUri: REDIRECT });
    pending = started.pending;
    result = await client.completeLogin(callbackUrl("success", pending.state), pending, options);
  } else if (entry.operationId === "refresh_session") {
    result = await client.refresh(await setupCredential(client));
  } else {
    assert.fail(entry.operationId);
  }
  return { result, calls, pending };
}

async function invoke(entry, setup) {
  const kind = entry.loadedFixture.exchange.kind;
  if (kind === "callback") return invokeCallback(entry, setup);
  if (kind === "transportFailure") return invokeTransport(entry, setup);
  return invokeHttp(entry, setup);
}

function normalizedCategory(value) {
  return value.replace(/([a-z])([A-Z])/gu, "$1_$2").toLowerCase();
}

function assertNoSentinels(value, fixture) {
  const formatted = [String(value), JSON.stringify(value), String(value?.cause)].join("\n");
  for (const sentinel of fixture.redactionSentinels ?? []) {
    assert.equal(formatted.includes(sentinel), false, `redaction sentinel leaked: ${sentinel}`);
  }
}

function assertSuccess(entry, result) {
  const values = entry.expected.values ?? {};
  if (entry.operationId === "get_public_application_config") {
    assert.equal(result.projectId, values.projectId);
    assert.equal(result.applicationId, values.applicationId);
    assert.deepEqual(result.providers.map((provider) => provider.key), values.providerKeys);
    assert.equal(result.loginAvailable, values.loginAvailable);
  } else if (entry.operationId === "get_project_jwks") {
    assert.deepEqual(result.keys.map((key) => key.kid), values.keyIds);
    assert.equal(result.revision, values.revision);
    assert.equal(result.signingEpoch, values.signingEpoch);
  } else if (entry.operationId === "start_login") {
    assert.ok(result.pending);
  } else if (entry.operationId === "get_current_user") {
    assert.equal(result.projectId, values.projectId);
    assert.equal(result.applicationId, values.applicationId);
    assert.equal(result.userId, values.userId);
    assert.equal(result.projectionRevision, values.projectionRevision);
  } else if (entry.operationId === "prepare_browser_logout") {
    assert.ok(result.hostedUrl.startsWith(BASE_URL));
  }
}

test("every required schema v3 case executes through the public SDK", async (t) => {
  const entries = await validateCorpus(await loadJson(corpusPath));
  const setup = {
    login: await loadJson(path.join(specRoot, "fixtures/login-start.json")),
    credential: await loadJson(path.join(specRoot, "fixtures/credential-pair.json")),
  };
  for (const entry of entries) {
    await t.test(entry.name, async () => {
      try {
        const { result, calls, pending } = await invoke(entry, setup);
        assert.equal(entry.expected.outcome, "success");
        assertSuccess(entry, result);
        const request = entry.loadedFixture.exchange.request;
        if (request !== undefined) {
          const init = calls.at(-1);
          assert.equal(init.method, request.method);
          assert.equal(init.body === undefined, request.body === "absent");
        }
        if (entry.expected.pendingDisposition === "preserved" && pending !== undefined) {
          assert.equal(pending.consumed, false);
        }
        assertNoSentinels(result, entry.loadedFixture);
      } catch (error) {
        assert.equal(entry.expected.outcome, "error", entry.name);
        assert.ok(error instanceof OwlAuthError, entry.name);
        assert.equal(normalizedCategory(error.category), entry.expected.category, entry.name);
        assert.equal(error.code, entry.expected.code, entry.name);
        assert.equal(error.operation, entry.operationId, entry.name);
        assert.equal(error.retry, entry.expected.retry, entry.name);
        assert.equal(error.action, entry.expected.action, entry.name);
        assert.equal(error.retryAfterSeconds, entry.expected.retryAfterSeconds, entry.name);
        assertNoSentinels(error, entry.loadedFixture);
      }
    });
  }
});

test("schema v3 pending dispositions enforce guard and replay behavior", async () => {
  const entries = await validateCorpus(await loadJson(corpusPath));
  const setup = { login: await loadJson(path.join(specRoot, "fixtures/login-start.json")) };
  for (const entry of entries) {
    if (entry.operationId === "start_login") {
      const calls = [];
      const client = makeClient(entry, [responseFor(entry.loadedFixture)], calls);
      const started = await client.beginLogin({ redirectUri: REDIRECT });
      assert.equal(started.pending.consumed, false, entry.name);
      assert.equal(calls.length, 1, entry.name);
      continue;
    }
    if (entry.precondition !== "pending_login") continue;

    const kind = entry.loadedFixture.exchange.kind;
    const calls = [];
    const outcomes = [responseFor(setup.login)];
    if (kind === "http") outcomes.push(responseFor(entry.loadedFixture));
    else if (kind === "transportFailure") outcomes.push(failureFor(entry.loadedFixture));
    let clockOffset = 0;
    const client = makeClient(entry, outcomes, calls, () => NOW + clockOffset * 1000);
    const started = await client.beginLogin({ redirectUri: REDIRECT });
    if (kind === "callback") {
      clockOffset = entry.loadedFixture.exchange.clockOffsetSeconds;
      for (const attempt of entry.loadedFixture.exchange.attempts) {
        try {
          client.validateCallback(callbackUrl(attempt, started.pending.state), started.pending);
        } catch {
          // The case's semantic assertion is executed by the main runner.
        }
      }
      assert.ok(["preserved", "discard_required"].includes(entry.expected.pendingDisposition));
      assert.equal(started.pending.consumed, false, entry.name);
      assert.equal(calls.length, 1, entry.name);
      continue;
    }

    if (entry.expected.pendingDisposition === "preserved") {
      const controller = new AbortController();
      controller.abort();
      await assert.rejects(
        client.completeLogin(callbackUrl("success", started.pending.state), started.pending, {
          signal: controller.signal,
        }),
      );
      assert.equal(started.pending.consumed, false, entry.name);
      assert.equal(calls.length, 1, entry.name);
      continue;
    }

    assert.ok(["discard_required", "quarantined"].includes(entry.expected.pendingDisposition));
    const first = client.validateCallback(callbackUrl("success", started.pending.state), started.pending);
    const replay = client.validateCallback(callbackUrl("success", started.pending.state), started.pending);
    await assert.rejects(client.exchangeHandoff(first));
    assert.equal(started.pending.consumed, true, entry.name);
    const requestCount = calls.length;
    await assert.rejects(client.exchangeHandoff(replay), (error) => error.code === "handoff_already_attempted");
    assert.equal(calls.length, requestCount, entry.name);
    assert.equal(requestCount, 2, entry.name);
  }
});

test("schema v3 validation fails closed", async () => {
  const original = await loadJson(corpusPath);
  for (const mutation of [
    (value) => {
      value.schemaVersion = 99;
    },
    (value) => {
      value.cases[0].unknownRequiredField = true;
    },
    (value) => {
      delete value.cases[0].operationId;
    },
    (value) => {
      value.cases.push(structuredClone(value.cases[0]));
    },
    (value) => {
      value.cases[0].operationId = "future_operation";
    },
    (value) => {
      value.cases.pop();
    },
    (value) => {
      value.cases[0].fixture = "../fixtures/missing.json";
    },
  ]) {
    const document = structuredClone(original);
    mutation(document);
    await assert.rejects(validateCorpus(document));
  }

  const fixture = await loadJson(path.join(specRoot, "fixtures/login-start.json"));
  for (const mutation of [
    (value) => {
      value.exchange.clockOffsetSeconds = -1;
      value.exchange.kind = "callback";
      value.exchange.attempts = ["success"];
      delete value.exchange.status;
      delete value.exchange.headers;
      delete value.exchange.body;
    },
    (value) => {
      value.redactionSentinels = ["x".repeat(257)];
    },
    (value) => {
      value.exchange.headers["content-type"] = 1;
    },
    (value) => {
      value.exchange.body = { encoding: "repeat", value: "xx", count: 1 };
    },
  ]) {
    const value = structuredClone(fixture);
    mutation(value);
    assert.throws(() => validateFixture(value));
  }
});
