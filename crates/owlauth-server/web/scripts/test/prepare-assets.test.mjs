import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { preparePlane } from "../prepare-assets.mjs";

async function fixture({
  manifestFile = "assets/runtime-abcdefgh.js",
  source = "export const ready=true;",
  extra,
} = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), "owlauth-web-assets-"));
  await mkdir(path.join(root, ".vite"), { recursive: true });
  await mkdir(path.join(root, "assets"), { recursive: true });
  const manifest = {
    "src/runtime/main.tsx": {
      file: manifestFile,
      name: "main",
      src: "src/runtime/main.tsx",
      isEntry: true,
    },
  };
  await writeFile(path.join(root, ".vite", "manifest.json"), JSON.stringify(manifest));
  if (!manifestFile.includes("..") && !manifestFile.includes("\\") && !manifestFile.includes("%")) {
    await writeFile(path.join(root, manifestFile), source);
  }
  if (extra !== undefined)
    await writeFile(path.join(root, "assets", "runtime-extra1234.js"), extra);
  return root;
}

test("normalizes a closed plane manifest and creates deterministic representations", async () => {
  const first = await fixture();
  const second = await fixture();
  try {
    const firstManifest = await preparePlane("runtime", first);
    const secondManifest = await preparePlane("runtime", second);
    assert.deepEqual(firstManifest, secondManifest);
    for (const suffix of ["", ".gz", ".br"]) {
      assert.deepEqual(
        await readFile(path.join(first, `assets/runtime-abcdefgh.js${suffix}`)),
        await readFile(path.join(second, `assets/runtime-abcdefgh.js${suffix}`)),
      );
    }
    assert.equal(firstManifest.schemaVersion, 1);
    assert.equal(firstManifest.files[0].mime, "text/javascript; charset=utf-8");
  } finally {
    await Promise.all([
      rm(first, { recursive: true, force: true }),
      rm(second, { recursive: true, force: true }),
    ]);
  }
});

test("rejects traversal and encoded path forms", async (context) => {
  for (const manifestFile of [
    "../runtime-abcdefgh.js",
    "assets\\runtime-abcdefgh.js",
    "assets/runtime-%2fabcdefgh.js",
  ]) {
    await context.test(manifestFile, async () => {
      const root = await fixture({ manifestFile });
      try {
        await assert.rejects(
          preparePlane("runtime", root),
          /(?:canonical|backslash|encoded|absolute)/u,
        );
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
});

test("rejects output that is not in the manifest closure", async () => {
  const root = await fixture({ extra: "export const unlisted=true;" });
  try {
    await assert.rejects(preparePlane("runtime", root), /missing or unlisted file/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects worker and evaluated-code output", async (context) => {
  for (const source of [
    "navigator.serviceWorker.register('/sw.js')",
    "const run=eval('1')",
    "new Worker('/worker.js')",
  ]) {
    await context.test(source, async () => {
      const root = await fixture({ source });
      try {
        await assert.rejects(
          preparePlane("runtime", root),
          /forbidden (?:worker API|string-to-code API)/u,
        );
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
});

test("rejects cross-plane emitted names", async () => {
  const root = await fixture({ manifestFile: "assets/control-abcdefgh.js" });
  try {
    await assert.rejects(preparePlane("runtime", root), /cross-plane or unowned/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
