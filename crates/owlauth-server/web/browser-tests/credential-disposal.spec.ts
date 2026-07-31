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
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
  await assertCredentialFreeBrowserState(page, [operatorKey, rejectedKey]);

  await page.getByRole("button", { name: "Lock console" }).click();
  await expect(page.getByRole("button", { name: "Unlock console" })).toBeVisible();
  await assertCredentialFreeBrowserState(page, [operatorKey, rejectedKey]);

  await unlock(page, operatorKey);
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("button", { name: "Unlock console" })).toBeVisible();
  await expect(page.getByLabel("Operator API key")).toHaveValue("");
  await assertCredentialFreeBrowserState(page, [operatorKey, rejectedKey]);

  await unlock(page, rejectedKey);
  await expect(page.getByRole("alert")).toHaveText("Authentication failed.");
  await expect(page.getByLabel("Operator API key")).toHaveValue("");
  await assertCredentialFreeBrowserState(page, [operatorKey, rejectedKey]);

  await unlock(page, operatorKey);
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
  await page.close();

  const reopened = await context.newPage();
  await reopened.goto(`${controlBase}console/`);
  await expect(reopened.getByRole("button", { name: "Unlock console" })).toBeVisible();
  await expect(reopened.getByLabel("Operator API key")).toHaveValue("");
  await assertCredentialFreeBrowserState(reopened, [operatorKey, rejectedKey]);
  expect(consoleMessages.join("\n")).not.toContain(operatorKey);
  expect(consoleMessages.join("\n")).not.toContain(rejectedKey);
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
