import { readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import openapiTS, { astToString } from "openapi-typescript";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(packageRoot, "../../..");
const defaults = {
  runtime:
    process.env.OWLAUTH_RUNTIME_OPENAPI ?? path.join(repositoryRoot, "target/openapi/runtime.json"),
  control:
    process.env.OWLAUTH_CONTROL_OPENAPI ?? path.join(repositoryRoot, "target/openapi/control.json"),
};
const outputs = {
  runtime: path.join(packageRoot, "src/generated/runtime-openapi.ts"),
  control: path.join(packageRoot, "src/generated/control-openapi.ts"),
};

function parseArguments(arguments_) {
  const mode = arguments_.includes("--write")
    ? "write"
    : arguments_.includes("--check")
      ? "check"
      : null;
  if (mode === null || (arguments_.includes("--write") && arguments_.includes("--check"))) {
    throw new Error(
      "Usage: generate-contracts.mjs (--write | --check) [--runtime FILE] [--control FILE]",
    );
  }
  const inputs = { ...defaults };
  for (const plane of ["runtime", "control"]) {
    const index = arguments_.indexOf(`--${plane}`);
    if (index >= 0) {
      const value = arguments_[index + 1];
      if (value === undefined) throw new Error(`--${plane} requires a file path`);
      inputs[plane] = path.resolve(value);
    }
  }
  return { mode, inputs };
}

function validateDocument(document, plane, input) {
  if (
    typeof document !== "object" ||
    document === null ||
    typeof document.openapi !== "string" ||
    !document.openapi.startsWith("3.1.") ||
    typeof document.info !== "object" ||
    document.info === null ||
    typeof document.paths !== "object" ||
    document.paths === null
  ) {
    throw new Error(`${input} is not a complete OpenAPI 3.1 document`);
  }

  const otherPlane = plane === "runtime" ? "control" : "runtime";
  const explicitPlane = document["x-owlauth-plane"];
  if (explicitPlane !== undefined && explicitPlane !== plane) {
    throw new Error(`${input} declares plane ${String(explicitPlane)}, expected ${plane}`);
  }

  for (const [route, item] of Object.entries(document.paths)) {
    const lowerRoute = route.toLowerCase();
    if (lowerRoute.includes(`/${otherPlane}/`)) {
      throw new Error(`${input} contains a cross-plane route: ${route}`);
    }
    if (plane === "runtime" && (route === "/v1/system" || lowerRoute.includes("/console"))) {
      throw new Error(`${input} contains a Control-only route: ${route}`);
    }
    if (
      plane === "control" &&
      (lowerRoute.includes("/auth/interactions") || lowerRoute.includes("/auth/callback"))
    ) {
      throw new Error(`${input} contains a Runtime-only route: ${route}`);
    }
    if (typeof item === "object" && item !== null) {
      for (const operation of Object.values(item)) {
        if (typeof operation !== "object" || operation === null || !Array.isArray(operation.tags))
          continue;
        if (operation.tags.some((tag) => String(tag).toLowerCase() === otherPlane)) {
          throw new Error(`${input} contains a ${otherPlane} operation under ${route}`);
        }
      }
    }
  }
}

async function generate(plane, input) {
  let raw;
  try {
    raw = await readFile(input, "utf8");
  } catch (error) {
    throw new Error(
      `Missing deterministic ${plane} OpenAPI input at ${input}. Run the owlauth-types plane exporters first.`,
      { cause: error },
    );
  }
  const document = JSON.parse(raw);
  validateDocument(document, plane, input);
  const ast = await openapiTS(pathToFileURL(input), { alphabetize: true });
  const body = astToString(ast).replaceAll("\r\n", "\n");
  return `/**\n * Generated from target/openapi/${plane}.json by openapi-typescript.\n * Do not edit by hand.\n */\n\n${body.trimStart()}`;
}

const { mode, inputs } = parseArguments(process.argv.slice(2));
const changed = [];
for (const plane of ["runtime", "control"]) {
  const generated = await generate(plane, inputs[plane]);
  const output = outputs[plane];
  const current = await readFile(output, "utf8").catch(() => "");
  if (current === generated) continue;
  changed.push(path.relative(repositoryRoot, output));
  if (mode === "write") {
    const temporary = `${output}.tmp`;
    await writeFile(temporary, generated, "utf8");
    await rename(temporary, output);
    await rm(temporary, { force: true });
  }
}

if (mode === "check" && changed.length > 0) {
  throw new Error(
    `Generated contract drift detected:\n- ${changed.join("\n- ")}\nRun pnpm --filter @owlauth/server-web contracts:generate.`,
  );
}
console.log(
  changed.length === 0
    ? "Generated hosted-web contracts are current."
    : `Updated ${changed.join(", ")}.`,
);
