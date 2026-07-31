import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("published runtime closure uses only Web-standard platform APIs", async () => {
  const files = ["index.js", "client.js", "errors.js", "types.js"];
  const combined = (
    await Promise.all(files.map((file) => readFile(path.join(packageRoot, "dist", file), "utf8")))
  ).join("\n");
  for (const forbidden of [
    'from "node:',
    "require(",
    "process.",
    "Buffer.",
    "window.",
    "document.",
    "localStorage",
    "sessionStorage",
  ]) {
    assert.equal(combined.includes(forbidden), false, `portable artifact contains ${forbidden}`);
  }
  const metadata = JSON.parse(await readFile(path.join(packageRoot, "package.json"), "utf8"));
  assert.deepEqual(Object.keys(metadata.exports), ["."]);
  assert.equal(metadata.exports["./browser"], undefined);
});
