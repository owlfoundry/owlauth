import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";

interface CandidateCoordinate {
  readonly component: "python" | "rust" | "typescript";
  readonly sourceCommit: string;
  readonly version: string;
  readonly workflowRunAttempt: string;
  readonly workflowRunId: string;
}

interface CandidateDescriptor {
  readonly archive: { readonly sha256: string };
  readonly coordinate: CandidateCoordinate;
}

interface PreparedCandidate {
  readonly archive: string;
  readonly archiveSha256: string;
  readonly descriptor: string;
  readonly descriptorSha256: string;
  readonly version: string;
}

export interface PreparedSdkCandidates {
  readonly python: PreparedCandidate & { readonly executable: string; readonly runner: string };
  readonly rust: PreparedCandidate & { readonly manifest: string };
  readonly typescript: PreparedCandidate & { readonly runner: string; readonly sdkRoot: string };
}

export async function prepareSdkCandidates(
  repository: string,
  temporaryRoot: string,
): Promise<PreparedSdkCandidates> {
  const python = process.env["OWLAUTH_E2E_ARTIFACT_PYTHON"] ?? "python3";
  const script = resolve(repository, "scripts/sdk_artifact.py");
  const sourceCommit = command("git", ["rev-parse", "HEAD"], repository).trim();
  const sharedVerification = [
    "--source-commit",
    sourceCommit,
    ...(process.env["GITHUB_RUN_ID"] === undefined
      ? []
      : ["--workflow-run-id", process.env["GITHUB_RUN_ID"]]),
    ...(process.env["GITHUB_RUN_ATTEMPT"] === undefined
      ? []
      : ["--workflow-run-attempt", process.env["GITHUB_RUN_ATTEMPT"]]),
  ];

  const typescript = await candidate("typescript");
  verify([
    "verify",
    "--component",
    "typescript",
    "--archive",
    typescript.archive,
    "--descriptor",
    typescript.descriptor,
    ...sharedVerification,
  ]);
  const typescriptRoot = resolve(temporaryRoot, "sdk-consumers/typescript");
  await mkdir(typescriptRoot, { recursive: true });
  await writeFile(
    resolve(typescriptRoot, "package.json"),
    '{"name":"owlauth-e2e-typescript-consumer","private":true,"type":"module"}\n',
  );
  command("npm", ["install", "--ignore-scripts", "--no-save", typescript.archive], typescriptRoot);
  const typescriptRunner = resolve(typescriptRoot, "e2e-real-server.mjs");
  await copyFile(resolve(repository, "sdks/typescript/test/e2e-real-server.mjs"), typescriptRunner);
  const typescriptSdkRoot = resolve(typescriptRoot, "node_modules/@owlauth/client/dist");

  const pythonCandidate = await candidate("python");
  verify([
    "verify",
    "--component",
    "python",
    "--archive",
    pythonCandidate.archive,
    "--descriptor",
    pythonCandidate.descriptor,
    "--distribution-directory",
    dirname(pythonCandidate.archive),
    ...sharedVerification,
  ]);
  const pythonRoot = resolve(temporaryRoot, "sdk-consumers/python");
  const virtualEnvironment = resolve(pythonRoot, "venv");
  await mkdir(pythonRoot, { recursive: true });
  command(process.env["OWLAUTH_E2E_PYTHON"] ?? "python", ["-m", "venv", virtualEnvironment]);
  const pythonExecutable = resolve(virtualEnvironment, "bin/python");
  command(pythonExecutable, [
    "-m",
    "pip",
    "install",
    "--disable-pip-version-check",
    "--no-deps",
    pythonCandidate.archive,
  ]);
  const pythonRunner = resolve(pythonRoot, "runtime_e2e.py");
  await copyFile(resolve(repository, "sdks/python/tests/runtime_e2e.py"), pythonRunner);

  const rust = await candidate("rust");
  const rustUploadMetadata = requiredAbsolutePath("OWLAUTH_E2E_RUST_UPLOAD_METADATA");
  verify([
    "verify",
    "--component",
    "rust",
    "--archive",
    rust.archive,
    "--descriptor",
    rust.descriptor,
    "--upload-metadata",
    rustUploadMetadata,
    ...sharedVerification,
  ]);
  const rustRoot = resolve(temporaryRoot, "sdk-consumers/rust");
  await mkdir(rustRoot, { recursive: true });
  command("tar", ["-xzf", rust.archive, "-C", rustRoot]);
  const extracted = resolve(rustRoot, `owlauth-client-${rust.version}`);
  const rustConsumer = resolve(rustRoot, "consumer");
  await mkdir(resolve(rustConsumer, "tests"), { recursive: true });
  await copyFile(
    resolve(repository, "sdks/rust/tests/server_e2e.rs"),
    resolve(rustConsumer, "tests/server_e2e.rs"),
  );
  const rustManifest = resolve(rustConsumer, "Cargo.toml");
  await writeFile(
    rustManifest,
    `[package]\nname = "owlauth-e2e-rust-consumer"\nversion = "0.0.0"\nedition = "2024"\npublish = false\n\n[dependencies]\nowlauth-client = { path = ${JSON.stringify(extracted)} }\nreqwest = { version = "0.13.4", default-features = false, features = ["json", "rustls"] }\nserde = { version = "1.0.229", features = ["derive"] }\nserde_json = "1.0.151"\ntokio = { version = "1.53.1", features = ["macros", "rt-multi-thread"] }\nurl = "2.5.8"\n`,
  );

  return {
    python: {
      ...pythonCandidate,
      executable: pythonExecutable,
      runner: pythonRunner,
    },
    rust: { ...rust, manifest: rustManifest },
    typescript: {
      ...typescript,
      runner: typescriptRunner,
      sdkRoot: typescriptSdkRoot,
    },
  };

  function verify(arguments_: string[]): void {
    command(python, [script, ...arguments_], repository);
  }

  async function candidate(
    component: CandidateCoordinate["component"],
  ): Promise<PreparedCandidate> {
    const prefix = `OWLAUTH_E2E_${component.toUpperCase()}`;
    const archive = requiredAbsolutePath(`${prefix}_ARCHIVE`);
    const descriptorPath = requiredAbsolutePath(`${prefix}_DESCRIPTOR`);
    const expectedArchiveSha256 = requiredDigest(`${prefix}_ARCHIVE_SHA256`);
    const expectedDescriptorSha256 = requiredDigest(`${prefix}_DESCRIPTOR_SHA256`);
    const descriptorBytes = await readFile(descriptorPath);
    const descriptorSha256 = sha256(descriptorBytes);
    if (descriptorSha256 !== expectedDescriptorSha256) {
      throw new Error(`${component} candidate descriptor digest differs from CI output`);
    }
    const descriptor = JSON.parse(descriptorBytes.toString("utf8")) as CandidateDescriptor;
    if (
      descriptor.coordinate.component !== component ||
      descriptor.coordinate.sourceCommit !== sourceCommit ||
      descriptor.archive.sha256 !== expectedArchiveSha256
    ) {
      throw new Error(`${component} candidate coordinate differs from the same-server run`);
    }
    const archiveSha256 = sha256(await readFile(archive));
    if (archiveSha256 !== expectedArchiveSha256) {
      throw new Error(`${component} candidate archive digest differs from CI output`);
    }
    return {
      archive,
      archiveSha256,
      descriptor: descriptorPath,
      descriptorSha256,
      version: descriptor.coordinate.version,
    };
  }
}

function requiredAbsolutePath(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "" || !isAbsolute(value)) {
    throw new Error(`${name} must be an absolute path`);
  }
  return value;
}

function requiredDigest(name: string): string {
  const value = process.env[name];
  if (value === undefined || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${name} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function command(executable: string, arguments_: string[], cwd?: string): string {
  const result = spawnSync(executable, arguments_, { cwd, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(
      `${executable} ${arguments_[0] ?? ""} failed: ${(result.stderr || result.stdout).trim()}`,
    );
  }
  return result.stdout;
}
