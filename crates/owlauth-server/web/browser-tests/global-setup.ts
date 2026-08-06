import { spawn, spawnSync } from "node:child_process";
import { closeSync, openSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

import { prepareSdkCandidates } from "./sdk-candidates";
import { startControlledServices, type ControlledServices } from "./test-services";

const operatorKey = `owl_ctrl_v1_${"A".repeat(43)}`;

export default async function globalSetup() {
  const repository = resolve(import.meta.dirname, "../../../..");
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "owlauth-browser-e2e-"));
  const runtimePort = await freePort();
  const clientPort = await freePort();
  const controlPort = await freePort();
  const providerPort = await freePort();
  const faultProxyPort = await freePort();
  const applicationPort = await freePort();
  const smtpPort = await freePort();
  const webhookPort = await freePort();
  const smtpKeyFile = resolve(temporaryRoot, "smtp-key.pem");
  const smtpRequestFile = resolve(temporaryRoot, "smtp.csr");
  const smtpCertificateFile = resolve(temporaryRoot, "smtp-cert.pem");
  const smtpRootKeyFile = resolve(temporaryRoot, "smtp-root-key.pem");
  const smtpRootCertificateFile = resolve(temporaryRoot, "smtp-root.pem");
  const smtpRootCertificateDerFile = resolve(temporaryRoot, "smtp-root.der");
  const smtpExtensionsFile = resolve(temporaryRoot, "smtp-extensions.cnf");
  const runtimeLogFile = resolve(temporaryRoot, "runtime.log");
  const clientLogFile = resolve(temporaryRoot, "client.log");
  const controlLogFile = resolve(temporaryRoot, "control.log");
  const runtimeLog = openSync(runtimeLogFile, "a");
  const clientLog = openSync(clientLogFile, "a");
  const controlLog = openSync(controlLogFile, "a");
  command("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    smtpRootKeyFile,
    "-out",
    smtpRootCertificateFile,
    "-days",
    "1",
    "-subj",
    "/CN=OwlAuth browser SMTP root",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign,cRLSign",
  ]);
  command("openssl", [
    "req",
    "-new",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    smtpKeyFile,
    "-out",
    smtpRequestFile,
    "-subj",
    "/CN=localhost",
  ]);
  await writeFile(
    smtpExtensionsFile,
    "subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
  );
  command("openssl", [
    "x509",
    "-req",
    "-in",
    smtpRequestFile,
    "-CA",
    smtpRootCertificateFile,
    "-CAkey",
    smtpRootKeyFile,
    "-CAcreateserial",
    "-out",
    smtpCertificateFile,
    "-days",
    "1",
    "-extfile",
    smtpExtensionsFile,
  ]);
  command("openssl", [
    "x509",
    "-in",
    smtpRootCertificateFile,
    "-outform",
    "DER",
    "-out",
    smtpRootCertificateDerFile,
  ]);
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
  let clientServer: ReturnType<typeof spawn> | undefined;
  let controlServer: ReturnType<typeof spawn> | undefined;
  let services: ControlledServices | undefined;
  try {
    // The release-grade project-auth runner supplies reviewed SDK candidates. UI-only local
    // journeys can start the same real servers without manufacturing SDK provenance they do not
    // consume; the Application fixture then points at the local built TypeScript tree.
    const sdkCandidates =
      process.env["OWLAUTH_E2E_TYPESCRIPT_ARCHIVE"] === undefined
        ? null
        : await prepareSdkCandidates(repository, temporaryRoot);
    services = await startControlledServices(
      sdkCandidates?.typescript.sdkRoot ?? resolve(repository, "sdks/typescript/dist"),
      providerPort,
      applicationPort,
      runtimePort,
      faultProxyPort,
      smtpPort,
      webhookPort,
      smtpCertificateFile,
      smtpKeyFile,
    );
    await waitForHealthyContainer(container);
    const mapping = command("docker", ["port", container, "5432/tcp"]).trim();
    const postgresPort = mapping.slice(mapping.lastIndexOf(":") + 1);
    const postgresUrl = `postgresql://postgres:owlauth_browser@127.0.0.1:${postgresPort}/postgres`;
    const runtimeUpstreamBase = `http://127.0.0.1:${String(runtimePort)}/`;
    const runtimeBase = services.faultProxyBase;
    const clientBase = `http://127.0.0.1:${String(clientPort)}/`;
    const controlBase = `http://127.0.0.1:${String(controlPort)}/`;

    const inheritedEnvironment = Object.fromEntries(
      Object.entries(process.env).filter(([name]) => !name.startsWith("OWLAUTH_")),
    );
    const commonEnvironment = {
      ...inheritedEnvironment,
      OWLAUTH_INSTANCE_ID: "browser-e2e",
      OWLAUTH_POSTGRES_URL: postgresUrl,
      OWLAUTH_SOFTWARE_CUSTODY_KEY: "Hh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4",
      OWLAUTH_SIGNER_STORE_ROOT: resolve(temporaryRoot, "signers"),
      OWLAUTH_SIGNER_STORE_KEY: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT: resolve(temporaryRoot, "secrets"),
      OWLAUTH_CONFIGURATION_SECRET_STORE_KEY: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
      OWLAUTH_RUNTIME_PROCESS_ID: "browser-runtime",
      OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS: "browser-runtime",
      OWLAUTH_RUNTIME_KEY_VERSION: "1",
      OWLAUTH_RUNTIME_DIGEST_KEY: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
      OWLAUTH_RUNTIME_PROTECTION_KEY: "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
      OWLAUTH_CLIENT_PROCESS_ID: "browser-client",
      OWLAUTH_REQUIRED_CLIENT_PROCESS_IDS: "browser-client",
      OWLAUTH_CLIENT_KEY_DIGEST_KEY_VERSION: "1",
      OWLAUTH_CLIENT_KEY_DIGEST_KEY: "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
      OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION: "1",
      OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY: "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo",
      OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY: "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws",
      OWLAUTH_PROJECTION_EMAIL_KEY_VERSION: "1",
      OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY: "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
      OWLAUTH_IDENTITY_MUTATION_EVIDENCE_KEY_VERSION: "1",
      OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY: "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk",
      OWLAUTH_IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY:
        "DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw",
      OWLAUTH_ADMISSION_DIGEST_KEY: "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU",
      OWLAUTH_PROVIDER_ALLOWED_ORIGINS: services.providerOrigin,
      OWLAUTH_PROVIDER_ALLOW_HTTP_LOOPBACK: "true",
      OWLAUTH_WEBHOOK_ALLOWED_PRIVATE_IPS: "127.0.0.1",
      OWLAUTH_WEBHOOK_EXTRA_ROOT_CERT_DER_FILE: smtpRootCertificateDerFile,
      OWLAUTH_RUNTIME_BASE_URL: runtimeBase,
      OWLAUTH_KEY_PROPAGATION_DELAY_MS: "100",
      OWLAUTH_PUBLICATION_LEASE_TTL_MS: "5000",
    };
    const deploymentMetadataEnvironment = {
      OWLAUTH_DEPLOYMENT_SMTP_GENERATION: "1",
      OWLAUTH_DEPLOYMENT_SMTP_STATUS: "reconciled",
      OWLAUTH_DEPLOYMENT_SMTP_HOST: "localhost",
      OWLAUTH_DEPLOYMENT_SMTP_PORT: String(smtpPort),
      OWLAUTH_DEPLOYMENT_SMTP_TLS_MODE: "implicit_tls",
      OWLAUTH_DEPLOYMENT_SMTP_SENDER_ADDRESS: "login@owlauth.test",
      OWLAUTH_DEPLOYMENT_SMTP_ALLOWED_PRIVATE_IPS: "127.0.0.1,::1",
    };
    const runtimeEmailIdentityEnvironment = {
      OWLAUTH_EMAIL_IDENTITY_KEY_VERSION: "1",
      OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY: "PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0",
      OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY: "Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4",
    };
    controlServer = spawn("cargo", ["run", "--quiet", "--locked", "-p", "owlauth-server"], {
      cwd: repository,
      env: {
        ...commonEnvironment,
        ...deploymentMetadataEnvironment,
        OWLAUTH_MODE: "control",
        OWLAUTH_CONTROL_ADDR: `127.0.0.1:${String(controlPort)}`,
        OWLAUTH_CONTROL_BASE_URL: controlBase,
        OWLAUTH_CONTROL_API_KEY: operatorKey,
      },
      stdio: ["ignore", controlLog, controlLog],
    });
    await waitForUrl(`${controlBase}health`, controlServer);
    const deployment = await bootstrapDeploymentSmtp(controlBase);
    controlServer.kill("SIGTERM");
    await waitForExit(controlServer);
    const deploymentEnvironment = {
      ...deploymentMetadataEnvironment,
      OWLAUTH_DEPLOYMENT_SMTP_STATUS: "active",
      OWLAUTH_DEPLOYMENT_SMTP_SAFE_FINGERPRINT: deployment.safeFingerprint,
    };
    runtimeServer = spawn("cargo", ["run", "--quiet", "--locked", "-p", "owlauth-server"], {
      cwd: repository,
      env: {
        ...commonEnvironment,
        ...runtimeEmailIdentityEnvironment,
        ...deploymentEnvironment,
        OWLAUTH_SMTP_EXTRA_ROOT_CERT_DER_FILE: smtpRootCertificateDerFile,
        OWLAUTH_MODE: "runtime",
        OWLAUTH_RUNTIME_ADDR: `127.0.0.1:${String(runtimePort)}`,
        OWLAUTH_MANAGED_CREDENTIAL_KEY_VERSION: "1",
        OWLAUTH_MANAGED_CREDENTIAL_KEY: "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY",
      },
      stdio: ["ignore", runtimeLog, runtimeLog],
    });
    clientServer = spawn("cargo", ["run", "--quiet", "--locked", "-p", "owlauth-server"], {
      cwd: repository,
      env: {
        ...commonEnvironment,
        OWLAUTH_MODE: "client",
        OWLAUTH_CLIENT_ADDR: `127.0.0.1:${String(clientPort)}`,
        OWLAUTH_CLIENT_BASE_URL: clientBase,
      },
      stdio: ["ignore", clientLog, clientLog],
    });
    controlServer = spawn("cargo", ["run", "--quiet", "--locked", "-p", "owlauth-server"], {
      cwd: repository,
      env: {
        ...commonEnvironment,
        ...deploymentEnvironment,
        OWLAUTH_MODE: "control",
        OWLAUTH_CONTROL_ADDR: `127.0.0.1:${String(controlPort)}`,
        OWLAUTH_CONTROL_BASE_URL: controlBase,
        OWLAUTH_CONTROL_API_KEY: operatorKey,
        OWLAUTH_CONTROL_MCP_ENABLED: "true",
      },
      stdio: ["ignore", controlLog, controlLog],
    });
    await waitForUrl(`${runtimeUpstreamBase}health`, runtimeServer);
    await waitForUrl(`${clientBase}ready`, clientServer);
    await waitForUrl(`${controlBase}health`, controlServer);
    process.env["OWLAUTH_E2E_RUNTIME_BASE"] = runtimeBase;
    process.env["OWLAUTH_E2E_CLIENT_BASE"] = clientBase;
    process.env["OWLAUTH_E2E_CONTROL_BASE"] = controlBase;
    process.env["OWLAUTH_E2E_OPERATOR_KEY"] = operatorKey;
    process.env["OWLAUTH_E2E_PROVIDER_ORIGIN"] = services.providerOrigin;
    process.env["OWLAUTH_E2E_PROVIDER_CLIENT_ID"] = services.providerClientId;
    process.env["OWLAUTH_E2E_PROVIDER_CLIENT_SECRET"] = services.providerClientSecret;
    process.env["OWLAUTH_E2E_APPLICATION_ORIGIN"] = services.applicationOrigin;
    process.env["OWLAUTH_E2E_FAULT_PROXY_BASE"] = services.faultProxyBase;
    process.env["OWLAUTH_E2E_FAULT_PROXY_TOKEN"] = services.faultProxyToken;
    process.env["OWLAUTH_E2E_BROWSER_DRIVER_URL"] = services.browserDriverUrl;
    process.env["OWLAUTH_E2E_BROWSER_DRIVER_TOKEN"] = services.browserDriverToken;
    process.env["OWLAUTH_E2E_REPOSITORY"] = repository;
    process.env["OWLAUTH_E2E_SOURCE_COMMIT"] = command("git", ["rev-parse", "HEAD"]).trim();
    if (sdkCandidates !== null) {
      process.env["OWLAUTH_E2E_TYPESCRIPT_ARCHIVE"] = sdkCandidates.typescript.archive;
      process.env["OWLAUTH_E2E_TYPESCRIPT_SDK_DIGEST"] = sdkCandidates.typescript.archiveSha256;
      process.env["OWLAUTH_E2E_TYPESCRIPT_VERSION"] = sdkCandidates.typescript.version;
      process.env["OWLAUTH_E2E_TYPESCRIPT_RUNNER"] = sdkCandidates.typescript.runner;
      process.env["OWLAUTH_E2E_PYTHON_ARCHIVE"] = sdkCandidates.python.archive;
      process.env["OWLAUTH_E2E_PYTHON_SDK_DIGEST"] = sdkCandidates.python.archiveSha256;
      process.env["OWLAUTH_E2E_PYTHON_VERSION"] = sdkCandidates.python.version;
      process.env["OWLAUTH_E2E_PYTHON_EXECUTABLE"] = sdkCandidates.python.executable;
      process.env["OWLAUTH_E2E_PYTHON_RUNNER"] = sdkCandidates.python.runner;
      process.env["OWLAUTH_E2E_RUST_ARCHIVE"] = sdkCandidates.rust.archive;
      process.env["OWLAUTH_E2E_RUST_SDK_DIGEST"] = sdkCandidates.rust.archiveSha256;
      process.env["OWLAUTH_E2E_RUST_VERSION"] = sdkCandidates.rust.version;
      process.env["OWLAUTH_E2E_RUST_MANIFEST"] = sdkCandidates.rust.manifest;
    }
    process.env["OWLAUTH_E2E_MAIL_CAPTURE_URL"] = services.mailCaptureUrl;
    process.env["OWLAUTH_E2E_WEBHOOK_CAPTURE_URL"] = services.webhookCaptureUrl;
    process.env["OWLAUTH_E2E_WEBHOOK_ENDPOINT_URL"] = services.webhookEndpointUrl;
    process.env["OWLAUTH_E2E_SMTP_PORT"] = String(smtpPort);
    process.env["OWLAUTH_E2E_POSTGRES_CONTAINER"] = container;
    process.env["OWLAUTH_E2E_RUNTIME_LOG"] = runtimeLogFile;
    process.env["OWLAUTH_E2E_CONTROL_LOG"] = controlLogFile;
  } catch (error) {
    runtimeServer?.kill("SIGTERM");
    clientServer?.kill("SIGTERM");
    controlServer?.kill("SIGTERM");
    await services?.close();
    spawnSync("docker", ["rm", "-f", container], { stdio: "ignore" });
    closeSync(runtimeLog);
    closeSync(clientLog);
    closeSync(controlLog);
    const diagnostics = await Promise.all([
      boundedLogTail(runtimeLogFile),
      boundedLogTail(clientLogFile),
      boundedLogTail(controlLogFile),
    ]);
    await rm(temporaryRoot, { recursive: true, force: true });
    throw new Error(
      `${error instanceof Error ? error.message : String(error)}\nRuntime log tail:\n${diagnostics[0]}\nClient log tail:\n${diagnostics[1]}\nControl log tail:\n${diagnostics[2]}`,
      { cause: error },
    );
  }

  return async () => {
    runtimeServer.kill("SIGTERM");
    clientServer.kill("SIGTERM");
    controlServer.kill("SIGTERM");
    await Promise.all([
      waitForExit(runtimeServer),
      waitForExit(clientServer),
      waitForExit(controlServer),
      services.close(),
    ]);
    spawnSync("docker", ["rm", "-f", container], { stdio: "ignore" });
    closeSync(runtimeLog);
    closeSync(clientLog);
    closeSync(controlLog);
    await rm(temporaryRoot, { recursive: true, force: true });
  };
}

async function bootstrapDeploymentSmtp(controlBase: string): Promise<{ safeFingerprint: string }> {
  const operationKey = "browser-smtp-bootstrap-credential";
  const smtpResponse = await fetch(`${controlBase}v1/system/smtp-default-generations`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${operatorKey}`,
      "content-type": "application/json",
      "idempotency-key": operationKey,
    },
    body: JSON.stringify({
      credential: JSON.stringify({ username: "capture-user", password: "capture-password" }),
    }),
  });
  if (!smtpResponse.ok) throw new Error(`SMTP bootstrap credential: ${await smtpResponse.text()}`);
  const smtp = (await smtpResponse.json()) as { safe_fingerprint: string };
  return {
    safeFingerprint: Buffer.from(smtp.safe_fingerprint, "base64url").toString("hex"),
  };
}

function command(executable: string, arguments_: string[]): string {
  const result = spawnSync(executable, arguments_, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`${executable} failed: ${result.stderr.trim()}`);
  }
  return result.stdout;
}

async function boundedLogTail(path: string): Promise<string> {
  try {
    const value = await readFile(path, "utf8");
    return value.slice(-4096);
  } catch (error) {
    return `unavailable: ${error instanceof Error ? error.message : String(error)}`;
  }
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
  for (let attempt = 0; attempt < 480; attempt += 1) {
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
