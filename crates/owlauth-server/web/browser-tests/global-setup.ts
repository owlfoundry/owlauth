import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const operatorKey = `owl_ctrl_v1_${"A".repeat(43)}`;

export default async function globalSetup() {
  const repository = resolve(import.meta.dirname, "../../../..");
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "owlauth-browser-e2e-"));
  const runtimePort = await freePort();
  const controlPort = await freePort();
  const container = command("docker", [
    "run",
    "-d",
    "--rm",
    "-e",
    "POSTGRES_PASSWORD=owlauth_browser",
    "-p",
    "127.0.0.1::5432",
    "--health-cmd",
    "pg_isready -U postgres",
    "--health-interval",
    "1s",
    "--health-retries",
    "30",
    "postgres:17-bookworm",
  ]).trim();

  let runtimeServer: ReturnType<typeof spawn> | undefined;
  let controlServer: ReturnType<typeof spawn> | undefined;
  try {
    await waitForHealthyContainer(container);
    const mapping = command("docker", ["port", container, "5432/tcp"]).trim();
    const postgresPort = mapping.slice(mapping.lastIndexOf(":") + 1);
    const postgresUrl = `postgresql://postgres:owlauth_browser@127.0.0.1:${postgresPort}/postgres`;
    const runtimeBase = `http://127.0.0.1:${String(runtimePort)}/`;
    const controlBase = `http://127.0.0.1:${String(controlPort)}/`;

    const commonEnvironment = {
      ...process.env,
      OWLAUTH_INSTANCE_ID: "browser-e2e",
      OWLAUTH_POSTGRES_URL: postgresUrl,
      OWLAUTH_SIGNER_STORE_ROOT: resolve(temporaryRoot, "signers"),
      OWLAUTH_SIGNER_STORE_KEY: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT: resolve(temporaryRoot, "secrets"),
      OWLAUTH_CONFIGURATION_SECRET_STORE_KEY: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
      OWLAUTH_RUNTIME_PROCESS_ID: "browser-runtime",
      OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS: "browser-runtime",
      OWLAUTH_RUNTIME_BASE_URL: runtimeBase,
      OWLAUTH_KEY_PROPAGATION_DELAY_MS: "100",
      OWLAUTH_PUBLICATION_LEASE_TTL_MS: "5000",
    };
    runtimeServer = spawn("cargo", ["run", "--quiet", "--locked", "-p", "owlauth-server"], {
      cwd: repository,
      env: {
        ...commonEnvironment,
        OWLAUTH_MODE: "runtime",
        OWLAUTH_RUNTIME_ADDR: `127.0.0.1:${String(runtimePort)}`,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    controlServer = spawn("cargo", ["run", "--quiet", "--locked", "-p", "owlauth-server"], {
      cwd: repository,
      env: {
        ...commonEnvironment,
        OWLAUTH_MODE: "control",
        OWLAUTH_CONTROL_ADDR: `127.0.0.1:${String(controlPort)}`,
        OWLAUTH_CONTROL_BASE_URL: controlBase,
        OWLAUTH_CONTROL_API_KEY: operatorKey,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    await waitForUrl(`${runtimeBase}health`, runtimeServer);
    await waitForUrl(`${controlBase}health`, controlServer);
    process.env["OWLAUTH_E2E_RUNTIME_BASE"] = runtimeBase;
    process.env["OWLAUTH_E2E_CONTROL_BASE"] = controlBase;
    process.env["OWLAUTH_E2E_OPERATOR_KEY"] = operatorKey;
  } catch (error) {
    runtimeServer?.kill("SIGTERM");
    controlServer?.kill("SIGTERM");
    spawnSync("docker", ["rm", "-f", container], { stdio: "ignore" });
    await rm(temporaryRoot, { recursive: true, force: true });
    throw error;
  }

  return async () => {
    runtimeServer.kill("SIGTERM");
    controlServer.kill("SIGTERM");
    await Promise.all([waitForExit(runtimeServer), waitForExit(controlServer)]);
    spawnSync("docker", ["rm", "-f", container], { stdio: "ignore" });
    await rm(temporaryRoot, { recursive: true, force: true });
  };
}

function command(executable: string, arguments_: string[]): string {
  const result = spawnSync(executable, arguments_, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`${executable} failed: ${result.stderr.trim()}`);
  }
  return result.stdout;
}

async function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (typeof address === "string" || address === null) {
        server.close();
        reject(new Error("Could not allocate a loopback port"));
        return;
      }
      server.close((error) => {
        if (error === undefined) resolvePort(address.port);
        else reject(error);
      });
    });
  });
}

async function waitForHealthyContainer(container: string): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const result = spawnSync(
      "docker",
      ["inspect", "--format={{.State.Health.Status}}", container],
      { encoding: "utf8" },
    );
    if (result.stdout.trim() === "healthy") return;
    await delay(500);
  }
  throw new Error("PostgreSQL browser-test container did not become healthy");
}

async function waitForExit(process: ReturnType<typeof spawn>): Promise<void> {
  await new Promise((resolveExit) => {
    if (process.exitCode !== null) resolveExit(undefined);
    else process.once("exit", resolveExit);
  });
}

async function waitForUrl(url: string, process: ReturnType<typeof spawn>): Promise<void> {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (process.exitCode !== null) throw new Error("OwlAuth browser-test server exited early");
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Startup is still in progress.
    }
    await delay(250);
  }
  throw new Error(`OwlAuth browser-test server did not become ready at ${url}`);
}

async function delay(milliseconds: number): Promise<void> {
  await new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}
