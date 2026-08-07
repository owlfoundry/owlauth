import { expect, test, type Page } from "@playwright/test";

const controlBase = requiredEnvironment("OWLAUTH_E2E_CONTROL_BASE");
const operatorKey = requiredEnvironment("OWLAUTH_E2E_OPERATOR_KEY");
const rejectedKey = `owl_ctrl_v1_${"B".repeat(43)}`;

test("operator credentials are discarded on lock, reload, denial, and page close", async ({
  page,
  context,
}) => {
  const consoleMessages: string[] = [];
  page.on("console", (message) => consoleMessages.push(message.text()));

  await page.goto(`${controlBase}console/`);
  await unlock(page, operatorKey);
  await expect(page.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();
  await assertCredentialFreeBrowserState(page, [operatorKey, rejectedKey]);

  await page.getByRole("button", { name: "Exit console" }).click();
  await expect(page.getByRole("button", { name: "Unlock console" })).toBeVisible();
  await assertCredentialFreeBrowserState(page, [operatorKey, rejectedKey]);

  await unlock(page, operatorKey);
  await expect(page.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("button", { name: "Unlock console" })).toBeVisible();
  await expect(page.getByLabel("Operator API key")).toHaveValue("");
  await assertCredentialFreeBrowserState(page, [operatorKey, rejectedKey]);

  await unlock(page, rejectedKey);
  await expect(page.getByRole("alert")).toContainText("The API key could not be verified.");
  await expect(page.getByLabel("Operator API key")).toHaveValue("");
  await assertCredentialFreeBrowserState(page, [operatorKey, rejectedKey]);

  await unlock(page, operatorKey);
  await expect(page.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();
  await page.evaluate(() => {
    const lifecycle = window as Window & {
      __owlauthRestoreEvidence?: { body: string; persisted: boolean }[];
    };
    const evidence: { body: string; persisted: boolean }[] = [];
    lifecycle.__owlauthRestoreEvidence = evidence;
    window.addEventListener(
      "pageshow",
      (event) => {
        evidence.push({
          body: document.body.textContent,
          persisted: event.persisted,
        });
      },
      { capture: true },
    );
  });
  await page.goto("about:blank");
  await page.goBack();
  await expect(page.getByRole("button", { name: "Unlock console" })).toBeVisible();
  const restoreEvidence = await page.evaluate(
    () =>
      (
        window as Window & {
          __owlauthRestoreEvidence?: { body: string; persisted: boolean }[];
        }
      ).__owlauthRestoreEvidence ?? [],
  );
  for (const restored of restoreEvidence.filter(({ persisted }) => persisted)) {
    expect(restored.body).not.toContain("Projects");
  }
  await assertCredentialFreeBrowserState(page, [operatorKey, rejectedKey]);

  await unlock(page, operatorKey);
  await expect(page.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();
  await page.close();

  const reopened = await context.newPage();
  await reopened.goto(`${controlBase}console/`);
  await expect(reopened.getByRole("button", { name: "Unlock console" })).toBeVisible();
  await expect(reopened.getByLabel("Operator API key")).toHaveValue("");
  await assertCredentialFreeBrowserState(reopened, [operatorKey, rejectedKey]);
  expect(consoleMessages.join("\n")).not.toContain(operatorKey);
  expect(consoleMessages.join("\n")).not.toContain(rejectedKey);
});

test("server-key reveal is one-time, non-dismissible, and revisioned in a real browser", async ({
  page,
  browserName,
}) => {
  const suffix = `${browserName}-${Date.now().toString(36)}`;
  const projectName = `Server key Project ${suffix}`;
  const keyLabel = `backend <img> ${suffix}`;

  await page.goto(`${controlBase}console/`);
  await unlock(page, operatorKey);
  await expect(page.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Create Project" }).first().click();
  await page.getByLabel("Display name").fill(projectName);
  await page.getByRole("dialog").getByRole("button", { name: "Create Project" }).click();
  await expect(page.getByRole("heading", { name: projectName })).toBeVisible();

  await page.getByRole("link", { name: "Project secret keys" }).click();
  await expect(
    page.getByRole("heading", { name: "Project secret keys", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Create secret key" }).first().click();
  const create = page.getByRole("dialog", { name: "Create Project secret key" });
  await create.getByLabel("Key label").fill(keyLabel);
  await create.getByRole("button", { name: "Create secret key" }).click();

  const reveal = page.getByRole("dialog", { name: "Store this Project secret key now" });
  await expect(reveal).toBeVisible();
  await expect(reveal.getByRole("button", { name: "Close dialog" })).toHaveCount(0);
  const credential = await reveal.getByTestId("one-time-server-credential").innerText();
  expect(credential).toMatch(/^owl_server_v1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/u);
  await page.keyboard.press("Escape");
  await expect(reveal).toBeVisible();
  await reveal.getByLabel(/I stored this credential/u).check();
  await reveal.getByRole("button", { name: "I saved this key" }).click();
  await expect(reveal).toBeHidden();
  await expect(page.getByText(credential, { exact: true })).toHaveCount(0);
  await expect(page.locator("img")).toHaveCount(0);
  const acknowledgedRow = page.getByRole("row", { name: new RegExp(keyLabel, "u") });
  await expect(acknowledgedRow).toContainText("Storage confirmed");

  // Lose a second original reveal through reload. The safe server inventory, not browser storage,
  // must reconstruct the gate and permit revocation while preventing another create.
  const unresolvedLabel = `reload unresolved ${suffix}`;
  await page.getByRole("button", { name: "Create secret key" }).first().click();
  const unresolvedCreate = page.getByRole("dialog", { name: "Create Project secret key" });
  await unresolvedCreate.getByLabel("Key label").fill(unresolvedLabel);
  await unresolvedCreate.getByRole("button", { name: "Create secret key" }).click();
  const unresolvedReveal = page.getByRole("dialog", { name: "Store this Project secret key now" });
  const lostCredential = await unresolvedReveal
    .getByTestId("one-time-server-credential")
    .innerText();
  await page.reload();
  await unlock(page, operatorKey);
  await expect(
    page.getByRole("heading", { name: "Project secret keys", exact: true }),
  ).toBeVisible();
  const unresolvedRow = page.getByRole("row", { name: new RegExp(unresolvedLabel, "u") });
  await expect(unresolvedRow).toContainText("Storage unconfirmed — creation blocked");
  await expect(page.getByRole("button", { name: "Create secret key" }).first()).toBeDisabled();
  await unresolvedRow.getByRole("button", { name: "Revoke" }).click();
  const unresolvedRevoke = page.getByRole("dialog", { name: "Revoke Project secret key" });
  await unresolvedRevoke.getByRole("button", { name: "Revoke Project secret key" }).click();
  await expect(unresolvedRow).toContainText("Status: revoked");

  await acknowledgedRow.getByRole("button", { name: "Revoke" }).click();
  const revoke = page.getByRole("dialog", { name: "Revoke Project secret key" });
  await expect(revoke).toContainText(keyLabel);
  await revoke.getByRole("button", { name: "Revoke Project secret key" }).click();
  await expect(page.getByRole("row", { name: new RegExp(keyLabel, "u") })).toContainText(
    "Status: revoked",
  );
  await expect(page.getByText(credential, { exact: true })).toHaveCount(0);
  await assertCredentialFreeBrowserState(page, [
    operatorKey,
    rejectedKey,
    credential,
    lostCredential,
  ]);
});

async function unlock(page: Page, key: string): Promise<void> {
  await page.getByLabel("Operator API key").fill(key);
  await page.getByRole("button", { name: "Unlock console" }).click();
}

async function assertCredentialFreeBrowserState(page: Page, secrets: string[]): Promise<void> {
  const state = await page.evaluate(async () => ({
    body: document.body.textContent,
    html: document.documentElement.outerHTML,
    url: location.href,
    historyState: JSON.stringify(history.state),
    local: Object.values(localStorage),
    session: Object.values(sessionStorage),
    caches: await caches.keys(),
    databases:
      typeof indexedDB.databases === "function"
        ? (await indexedDB.databases()).map((database) => database.name)
        : [],
  }));
  expect(state.local).toEqual([]);
  expect(state.session).toEqual([]);
  expect(state.caches).toEqual([]);
  expect(state.databases).toEqual([]);
  for (const secret of secrets) {
    expect(state.body).not.toContain(secret);
    expect(state.html).not.toContain(secret);
    expect(state.url).not.toContain(secret);
    expect(state.historyState).not.toContain(secret);
  }
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}
