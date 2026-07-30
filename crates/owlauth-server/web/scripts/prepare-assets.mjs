import { constants as bufferConstants } from "node:buffer";
import { createHash } from "node:crypto";
import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { brotliCompressSync, constants as zlibConstants, gzipSync } from "node:zlib";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PLANES = ["runtime", "control"];
const MIME = new Map([
  [".css", "text/css; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json"],
  [".svg", "image/svg+xml"],
  [".png", "image/png"],
  [".webp", "image/webp"],
  [".woff2", "font/woff2"],
]);
const TEXT_EXTENSIONS = new Set([".css", ".js", ".json", ".svg"]);
const FORBIDDEN_JAVASCRIPT = [
  ["source map", /(?:sourceMappingURL|sourceURL)\s*=/u],
  ["inline data program", /(?:text|application)\/javascript\s*;\s*base64/iu],
  ["string-to-code API", /\b(?:eval|Function)\s*\(/u],
  ["worker API", /\b(?:SharedWorker|Worker)\s*\(|serviceWorker\s*\.\s*register/u],
  ["remote module import", /\bimport\s*\(\s*["'](?:https?:)?\/\//iu],
  ["remote executable element", /<(?:script|link)\b[^>]*(?:src|href)\s*=\s*["'](?:https?:)?\/\//iu],
  ["inline event handler", /\bon[a-z]+\s*=\s*["']/iu],
];

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function canonicalRelativeFile(value, description) {
  invariant(
    typeof value === "string" && value.length > 0,
    `${description} must be a non-empty string`,
  );
  invariant(!value.includes("\\"), `${description} contains a backslash: ${value}`);
  invariant(!value.includes("%"), `${description} contains encoded or ambiguous bytes: ${value}`);
  invariant(!/[?#]/u.test(value), `${description} contains a query or fragment: ${value}`);
  invariant(!/^(?:[a-z][a-z\d+.-]*:|\/|\\)/iu.test(value), `${description} is absolute: ${value}`);
  invariant(!value.includes("//"), `${description} has an empty segment: ${value}`);
  const segments = value.split("/");
  invariant(
    segments.every((segment) => segment !== "" && segment !== "." && segment !== ".."),
    `${description} is not canonical: ${value}`,
  );
  invariant(path.posix.normalize(value) === value, `${description} is not normalized: ${value}`);
  return value;
}

async function listFiles(directory, prefix = "") {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name, "en"))) {
    const relative = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isSymbolicLink())
      throw new Error(`Asset output contains a symbolic link: ${relative}`);
    if (entry.isDirectory())
      files.push(...(await listFiles(path.join(directory, entry.name), relative)));
    else if (entry.isFile()) files.push(relative);
    else throw new Error(`Asset output contains an unsupported filesystem entry: ${relative}`);
  }
  return files;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function compressionVariants(bytes) {
  const gzip = gzipSync(bytes, { level: 9 });
  const brotli = brotliCompressSync(bytes, {
    params: {
      [zlibConstants.BROTLI_PARAM_MODE]: zlibConstants.BROTLI_MODE_TEXT,
      [zlibConstants.BROTLI_PARAM_QUALITY]: 11,
      [zlibConstants.BROTLI_PARAM_SIZE_HINT]: Math.min(bytes.length, bufferConstants.MAX_LENGTH),
    },
  });
  invariant(gzip.equals(gzipSync(bytes, { level: 9 })), "gzip output is not deterministic");
  invariant(
    brotli.equals(
      brotliCompressSync(bytes, {
        params: {
          [zlibConstants.BROTLI_PARAM_MODE]: zlibConstants.BROTLI_MODE_TEXT,
          [zlibConstants.BROTLI_PARAM_QUALITY]: 11,
          [zlibConstants.BROTLI_PARAM_SIZE_HINT]: Math.min(
            bytes.length,
            bufferConstants.MAX_LENGTH,
          ),
        },
      }),
    ),
    "Brotli output is not deterministic",
  );
  return { gzip, brotli };
}

function collectClosure(manifest, plane) {
  invariant(
    typeof manifest === "object" && manifest !== null && !Array.isArray(manifest),
    `${plane} Vite manifest must be an object`,
  );
  const records = Object.entries(manifest);
  const entries = records.filter(([, record]) => record?.isEntry === true);
  invariant(
    entries.length === 1,
    `${plane} Vite manifest must contain exactly one entry; found ${entries.length}`,
  );

  const [entryKey, entryRecord] = entries[0];
  invariant(
    entryKey === `src/${plane}/main.tsx`,
    `${plane} manifest entry key is unexpected: ${entryKey}`,
  );
  const visited = new Set();
  const files = new Set();
  const scripts = [];
  const stylesheets = [];

  function visit(key) {
    invariant(!visited.has(key), `${plane} manifest contains a repeated or cyclic import: ${key}`);
    const record = manifest[key];
    invariant(
      typeof record === "object" && record !== null && !Array.isArray(record),
      `${plane} manifest references a missing record: ${key}`,
    );
    visited.add(key);
    invariant(
      !Array.isArray(record.dynamicImports) || record.dynamicImports.length === 0,
      `${plane} dynamic imports are not admitted`,
    );

    const file = canonicalRelativeFile(record.file, `${plane} emitted file`);
    invariant(
      file.startsWith(`assets/${plane}-`),
      `${plane} manifest names a cross-plane or unowned file: ${file}`,
    );
    invariant(!files.has(file), `${plane} manifest contains duplicate output file: ${file}`);
    files.add(file);
    scripts.push(file);

    for (const css of record.css ?? []) {
      const cssFile = canonicalRelativeFile(css, `${plane} CSS file`);
      invariant(
        cssFile.startsWith(`assets/${plane}-`),
        `${plane} manifest names a cross-plane CSS file: ${cssFile}`,
      );
      invariant(
        !files.has(cssFile),
        `${plane} manifest contains duplicate output file: ${cssFile}`,
      );
      files.add(cssFile);
      stylesheets.push(cssFile);
    }
    for (const asset of record.assets ?? []) {
      const assetFile = canonicalRelativeFile(asset, `${plane} asset file`);
      invariant(
        assetFile.startsWith(`assets/${plane}-`),
        `${plane} manifest names a cross-plane asset: ${assetFile}`,
      );
      invariant(
        !files.has(assetFile),
        `${plane} manifest contains duplicate output file: ${assetFile}`,
      );
      files.add(assetFile);
    }
    for (const imported of record.imports ?? []) visit(imported);
  }

  visit(entryKey);
  invariant(visited.size === records.length, `${plane} manifest contains unreachable records`);
  return { entry: entryRecord.file, files: [...files].sort(), scripts, stylesheets };
}

function validateFileContent(relative, bytes) {
  const extension = path.posix.extname(relative);
  const mime = MIME.get(extension);
  invariant(mime !== undefined, `No reviewed MIME mapping for ${relative}`);
  invariant(!relative.endsWith(".map"), `Source map is forbidden: ${relative}`);
  invariant(
    /-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+$/u.test(relative),
    `Asset is not fingerprinted: ${relative}`,
  );
  if (TEXT_EXTENSIONS.has(extension)) {
    const text = bytes.toString("utf8");
    invariant(
      Buffer.from(text, "utf8").equals(bytes),
      `Text asset is not valid UTF-8: ${relative}`,
    );
    invariant(!text.includes("\u0000"), `Text asset contains NUL: ${relative}`);
    if (extension === ".js") {
      for (const [description, pattern] of FORBIDDEN_JAVASCRIPT) {
        invariant(!pattern.test(text), `${relative} contains forbidden ${description}`);
      }
    }
    if (extension === ".svg") {
      invariant(
        !/<(?:script|foreignObject)\b/iu.test(text),
        `${relative} contains executable SVG markup`,
      );
      invariant(
        !/(?:href|src)\s*=\s*["'](?:https?:)?\/\//iu.test(text),
        `${relative} contains a remote SVG reference`,
      );
    }
  }
  return mime;
}

export async function preparePlane(plane, root = path.join(packageRoot, "dist", plane)) {
  invariant(PLANES.includes(plane), `Unknown plane: ${plane}`);
  const rootInfo = await stat(root).catch(() => null);
  invariant(rootInfo?.isDirectory() === true, `Missing ${plane} Vite output at ${root}`);
  const viteManifestPath = path.join(root, ".vite", "manifest.json");
  const manifest = JSON.parse(await readFile(viteManifestPath, "utf8"));
  const closure = collectClosure(manifest, plane);

  const before = await listFiles(root);
  const authored = before.filter(
    (file) =>
      file !== ".vite/manifest.json" &&
      file !== "server-manifest.json" &&
      !file.endsWith(".gz") &&
      !file.endsWith(".br"),
  );
  invariant(new Set(authored).size === authored.length, `${plane} output contains duplicate paths`);
  invariant(
    authored.length === closure.files.length &&
      authored.every((file) => closure.files.includes(file)),
    `${plane} output contains a missing or unlisted file (manifest: ${closure.files.join(", ")}; output: ${authored.join(", ")})`,
  );

  const normalizedFiles = [];
  for (const relative of closure.files) {
    const absolute = path.join(root, ...relative.split("/"));
    const bytes = await readFile(absolute);
    const mime = validateFileContent(relative, bytes);
    const identity = { path: relative, bytes: bytes.length, sha256: sha256(bytes) };
    const representations = { identity };
    if (TEXT_EXTENSIONS.has(path.posix.extname(relative))) {
      const { gzip, brotli } = compressionVariants(bytes);
      await writeFile(`${absolute}.gz`, gzip);
      await writeFile(`${absolute}.br`, brotli);
      representations.gzip = { path: `${relative}.gz`, bytes: gzip.length, sha256: sha256(gzip) };
      representations.brotli = {
        path: `${relative}.br`,
        bytes: brotli.length,
        sha256: sha256(brotli),
      };
    }
    normalizedFiles.push({
      path: relative,
      mime,
      bytes: bytes.length,
      sha256: identity.sha256,
      representations,
    });
  }

  const digest = createHash("sha256");
  for (const file of normalizedFiles) digest.update(`${file.path}\0${file.sha256}\n`, "utf8");
  const normalized = {
    schemaVersion: 1,
    plane,
    entry: canonicalRelativeFile(closure.entry, `${plane} entry`),
    scripts: closure.scripts,
    stylesheets: closure.stylesheets,
    assetSetSha256: digest.digest("hex"),
    files: normalizedFiles,
  };
  await writeFile(
    path.join(root, "server-manifest.json"),
    `${JSON.stringify(normalized, null, 2)}\n`,
    "utf8",
  );

  const expected = new Set([".vite/manifest.json", "server-manifest.json"]);
  for (const file of normalizedFiles) {
    expected.add(file.path);
    for (const representation of Object.values(file.representations))
      expected.add(representation.path);
  }
  const after = await listFiles(root);
  invariant(
    after.length === expected.size && after.every((file) => expected.has(file)),
    `${plane} prepared output contains an unexpected file`,
  );
  return normalized;
}

async function main() {
  const manifests = [];
  for (const plane of PLANES) manifests.push(await preparePlane(plane));
  const outputPaths = new Set(
    manifests.flatMap((manifest) => manifest.files.map((file) => file.path)),
  );
  const outputCount = manifests.reduce((total, manifest) => total + manifest.files.length, 0);
  invariant(outputPaths.size === outputCount, "Runtime and Control emitted paths overlap");
  console.log(
    manifests
      .map(
        (manifest) =>
          `${manifest.plane}: ${manifest.files.length} files (${manifest.assetSetSha256})`,
      )
      .join("\n"),
  );
}

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await main();
}
