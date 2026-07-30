import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = path.join(packageRoot, "src");

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map((entry) => {
      const target = path.join(directory, entry.name);
      return entry.isDirectory() ? walk(target) : [target];
    }),
  );
  return nested.flat();
}

const sourceFiles = (await walk(sourceRoot)).filter(
  (file) => /\.[cm]?[jt]sx?$/u.test(file) && !/\.test\.[jt]sx?$/u.test(file),
);
const failures = [];
const importPattern = /(?:import|export)\s+(?:type\s+)?(?:[^"']*?\s+from\s+)?["']([^"']+)["']/gu;
const forbiddenSource = [
  ["raw HTML sink", /\b(?:dangerouslySetInnerHTML|innerHTML|outerHTML|insertAdjacentHTML)\b/u],
  ["string-to-code API", /\b(?:eval|Function)\s*\(/u],
  ["worker API", /\b(?:SharedWorker|Worker)\s*\(|serviceWorker\b/u],
  ["browser persistence", /\b(?:localStorage|sessionStorage|indexedDB|caches)\b/u],
  ["inline style", /\bstyle\s*=\s*\{\{/u],
  ["dynamic import", /\bimport\s*\(/u],
  ["remote URL", /["'](?:https?:)?\/\//u],
];

for (const file of sourceFiles) {
  const relative = path.relative(sourceRoot, file).split(path.sep).join("/");
  const source = await readFile(file, "utf8");
  const owner = relative.split("/", 1)[0];

  for (const match of source.matchAll(importPattern)) {
    const specifier = match[1] ?? "";
    if (owner === "runtime" && /(?:^|\/)(?:control|control-openapi)(?:\/|$|\.)/u.test(specifier)) {
      failures.push(`${relative}: Runtime imports Control (${specifier})`);
    }
    if (owner === "control" && /(?:^|\/)(?:runtime|runtime-openapi)(?:\/|$|\.)/u.test(specifier)) {
      failures.push(`${relative}: Control imports Runtime (${specifier})`);
    }
    if (owner === "shared" && /(?:^|\/)(?:runtime|control|generated)(?:\/|$|\.)/u.test(specifier)) {
      failures.push(`${relative}: shared source imports plane-owned code (${specifier})`);
    }
    if (owner === "generated") {
      failures.push(`${relative}: generated contract must be type-only and import-free`);
    }
  }

  if (owner !== "generated") {
    for (const [description, pattern] of forbiddenSource) {
      if (pattern.test(source)) {
        failures.push(`${relative}: forbidden ${description}`);
      }
    }
  }
}

if (failures.length > 0) {
  throw new Error(`Hosted-web source boundary validation failed:\n- ${failures.join("\n- ")}`);
}

console.log(`Validated ${sourceFiles.length} hosted-web source files and plane import boundaries.`);
