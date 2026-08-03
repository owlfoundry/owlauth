import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  AccessToken,
  Client,
  CredentialPair,
  OwlAuthError,
  PkceVerifier,
  ValidatedCallback,
} from "../dist/index.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const specRoot = path.resolve(packageRoot, "../spec");
const fixturesRoot = path.join(specRoot, "fixtures") + path.sep;
const SUPPORTED_CORPUS_SCHEMA = 2;

async function loadJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

function exactKeys(value, allowed, label) {
  assert.equal(typeof value, "object", `${label} must be an object`);
  const names = allowed.map((entry) => (entry.startsWith("!") ? entry.slice(1) : entry));
  for (const key of Object.keys(value)) {
    assert.ok(names.includes(key), `${label} has unknown required field: ${key}`);
  }
  for (const key of allowed.filter((entry) => entry.startsWith("!"))) {
    assert.ok(Object.hasOwn(value, key.slice(1)), `${label} is missing ${key.slice(1)}`);
  }
}

function response(fixture) {
  return new Response(JSON.stringify(fixture.response), {
    status: fixture.responseStatus,
    headers: { "content-type": "application/json" },
  });
}

function context(entry) {
  return (
    entry.configuredContext ?? {
      projectId: "prj_conformance",
      applicationId: "app_conformance",
      publishableKey: "owl_app_conformance",
    }
  );
}

function clientFor(entry, fixture) {
  const configured = context(entry);
  let requests = 0;
  const client = new Client({
    baseUrl: "https://runtime.conformance.example/",
    projectId: configured.projectId,
    applicationId: configured.applicationId,
    publishableKey: configured.publishableKey,
    fetch: async () => {
      requests += 1;
      return response(fixture);
    },
  });
  return { client, requests: () => requests };
}

function syntheticCredentials(configured) {
  return new CredentialPair({
    projectId: configured.projectId,
    applicationId: configured.applicationId,
    userId: "usr_conformance",
    sessionId: "00000000-0000-4000-8000-000000000001",
    refreshGeneration: 1,
    accessToken: "SYNTHETIC_INPUT_ACCESS",
    refreshToken: "SYNTHETIC_INPUT_REFRESH",
    expiresIn: 300,
    projection: {
      userId: "usr_conformance",
      userRevision: 1,
      projectionSchema: "owlauth.user.v1",
      projectionRevision: 1,
      displayName: null,
      pictureUrl: null,
      locale: null,
      verifiedEmail: null,
      status: "active",
      createdAt: "2099-01-01T00:00:00Z",
      updatedAt: "2099-01-01T00:00:00Z",
    },
    projectionRevision: 1,
    sessionExpiresAt: "2099-01-02T00:00:00Z",
  });
}

async function execute(entry, fixture) {
  const harness = clientFor(entry, fixture);
  const configured = context(entry);
  let outcome;
  switch (entry.operation) {
    case "public_configuration":
      outcome = await harness.client.getPublicConfiguration();
      break;
    case "handoff":
    case "credential_response":
      outcome = await harness.client.exchangeHandoff(
        new ValidatedCallback("SYNTHETIC_HANDOFF", new PkceVerifier("a".repeat(43))),
      );
      break;
    case "refresh":
      outcome = await harness.client.refresh(syntheticCredentials(configured));
      break;
    case "current_user":
    case "current_user_response":
      outcome = await harness.client.currentUser(new AccessToken("SYNTHETIC_INPUT_ACCESS"));
      break;
    default:
      throw new Error(`unsupported required operation: ${entry.operation}`);
  }
  assert.equal(harness.requests(), 1);
  return outcome;
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

function assertSuccess(entry, result, fixture) {
  const expected = entry.expected;
  switch (entry.operation) {
    case "public_configuration":
      assert.equal(result.projectId, expected.projectId);
      assert.equal(result.applicationId, expected.applicationId);
      assert.deepEqual(
        result.providers.map((provider) => provider.key),
        expected.providerKeys,
      );
      assert.equal(result.loginAvailable, expected.loginAvailable);
      break;
    case "credential_response":
      assert.equal(result.projectId, expected.projectId);
      assert.equal(result.applicationId, expected.applicationId);
      assert.equal(result.userId, expected.userId);
      assert.equal(result.refreshGeneration, expected.refreshGeneration);
      assert.equal(result.projectionRevision, expected.projectionRevision);
      assertNoSentinels(result, fixture);
      break;
    case "current_user_response":
      assert.equal(result.projectId, expected.projectId);
      assert.equal(result.applicationId, expected.applicationId);
      assert.equal(result.userId, expected.userId);
      assert.equal(result.projectionRevision, expected.projectionRevision);
      break;
    default:
      throw new Error(`unsupported success operation: ${entry.operation}`);
  }
}

async function assertCase(entry, fixture) {
  if (entry.expected.outcome === "success") {
    assertSuccess(entry, await execute(entry, fixture), fixture);
    return;
  }
  await assert.rejects(execute(entry, fixture), (error) => {
    assert.ok(error instanceof OwlAuthError);
    assert.equal(normalizedCategory(error.category), entry.expected.category);
    assert.equal(error.code, entry.expected.code);
    assert.equal(error.retry, entry.expected.retry);
    assert.equal(error.action, entry.expected.action);
    assertNoSentinels(error, fixture);
    return true;
  });
}

test("every required shared conformance case executes through the SDK", async (t) => {
  const casesPath = path.join(specRoot, "conformance/cases.json");
  const corpus = await loadJson(casesPath);
  exactKeys(corpus, ["!schemaVersion", "!cases"], "corpus");
  assert.equal(corpus.schemaVersion, SUPPORTED_CORPUS_SCHEMA, "unsupported corpus schema version");
  assert.ok(Array.isArray(corpus.cases) && corpus.cases.length > 0);

  const names = new Set();
  for (const entry of corpus.cases) {
    exactKeys(
      entry,
      [
        "!name",
        "!fixture",
        "!required",
        "!capability",
        "!operation",
        "!minimumCorpusSchema",
        "configuredContext",
        "!expected",
      ],
      "case",
    );
    assert.equal(typeof entry.name, "string");
    assert.ok(entry.name.length > 0 && !names.has(entry.name), `duplicate case: ${entry.name}`);
    names.add(entry.name);
    assert.equal(entry.minimumCorpusSchema <= SUPPORTED_CORPUS_SCHEMA, true);
    assert.equal(entry.required, true, `optional capability must be reported explicitly: ${entry.name}`);
    assert.equal(typeof entry.capability, "string");
    assert.equal(typeof entry.operation, "string");
    assert.equal(typeof entry.fixture, "string");
    if (entry.configuredContext !== undefined) {
      exactKeys(
        entry.configuredContext,
        ["!projectId", "!applicationId", "!publishableKey"],
        `configured context ${entry.name}`,
      );
    }
    if (entry.expected?.outcome === "error") {
      exactKeys(
        entry.expected,
        ["!outcome", "!category", "!code", "!retry", "!action"],
        `expected error ${entry.name}`,
      );
    } else if (entry.expected?.outcome === "success") {
      const successFields = {
        public_configuration: ["!outcome", "!projectId", "!applicationId", "!providerKeys", "!loginAvailable"],
        credential_response: [
          "!outcome",
          "!projectId",
          "!applicationId",
          "!userId",
          "!refreshGeneration",
          "!projectionRevision",
          "!redacted",
        ],
        current_user_response: ["!outcome", "!projectId", "!applicationId", "!userId", "!projectionRevision"],
      }[entry.operation];
      assert.ok(successFields, `unsupported success operation: ${entry.operation}`);
      exactKeys(entry.expected, successFields, `expected success ${entry.name}`);
    } else {
      assert.fail(`invalid expected outcome: ${entry.name}`);
    }
    const fixturePath = path.resolve(path.dirname(casesPath), entry.fixture);
    assert.ok(fixturePath.startsWith(fixturesRoot), `fixture escapes corpus root: ${entry.name}`);
    const fixture = await loadJson(fixturePath);
    exactKeys(
      fixture,
      ["!schemaVersion", "!synthetic", "!responseStatus", "!response", "redactionSentinels"],
      `fixture ${entry.name}`,
    );
    assert.equal(fixture.schemaVersion, SUPPORTED_CORPUS_SCHEMA);
    assert.equal(fixture.synthetic, true);
    assert.ok(Number.isSafeInteger(fixture.responseStatus));
    assert.equal(typeof fixture.response, "object");
    if (fixture.redactionSentinels !== undefined) {
      assert.ok(
        Array.isArray(fixture.redactionSentinels) &&
          fixture.redactionSentinels.every((value) => typeof value === "string" && value.length > 0),
      );
    }
    await t.test(entry.name, async () => assertCase(entry, fixture));
  }
});
