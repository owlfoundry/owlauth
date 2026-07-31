import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const controlBase = requiredEnvironment("OWLAUTH_E2E_CONTROL_BASE");
const runtimeBase = requiredEnvironment("OWLAUTH_E2E_RUNTIME_BASE");
const operatorKey = requiredEnvironment("OWLAUTH_E2E_OPERATOR_KEY");
const providerOrigin = requiredEnvironment("OWLAUTH_E2E_PROVIDER_ORIGIN");

test("fresh-database operator journey reaches exact Runtime readiness", async ({
  page,
  browserName,
}) => {
  const suffix = `${browserName}-${Date.now().toString(36)}`;
  const projectName = `E2E Project ${suffix}`;
  const applicationName = `E2E Application ${suffix}`;
  const providerName = `E2E Provider ${suffix}`;
  const providerSecret = `secret-${suffix}`;

  await page.goto(`${controlBase}console/`);
  await page.getByLabel("Operator API key").fill(operatorKey);
  await page.getByRole("button", { name: "Unlock console" }).click();
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();

  await page.locator("#project-name").fill(projectName);
  await page.getByRole("button", { name: "Create Project" }).click();
  await expect(page.getByRole("heading", { name: projectName })).toBeVisible();
  const projectPublicId = await page
    .locator('section[aria-labelledby="project-detail-heading"] code')
    .first()
    .innerText();

  await page.getByLabel("Belongs to").fill(`deployment-${suffix}`);
  await page.getByRole("button", { name: "Update Project", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("metadata updated");
  await page.getByLabel("Access token lifetime (seconds)").fill("1200");
  await page.getByLabel("Allow explicit browser session reuse confirmation").check();
  await page.getByRole("button", { name: "Update Project policy" }).click();
  await expect(page.getByText(/Claims revision 2; session revision 2/u)).toBeVisible();

  await page.locator("#application-name").fill(applicationName);
  await page.getByRole("button", { name: "Create Application" }).click();
  await expect(page.getByRole("heading", { name: applicationName })).toBeVisible();
  const applicationPublicId = await page.locator("article code").first().innerText();

  await page.getByLabel("Redirect URIs, one per line").fill("https://app.example/callback");
  await page.getByLabel("Allowed origins, one per line").fill("https://app.example");
  await page.getByRole("button", { name: "Replace configuration" }).click();
  await expect(page.getByRole("status")).toContainText("configuration replaced");

  await page.getByRole("button", { name: "Provision signing key" }).click();
  await expect(page.getByRole("button", { name: "Activate" })).toBeVisible();
  const firstJwks = await page.request.get(
    `${runtimeBase}projects/${encodeURIComponent(projectPublicId)}/.well-known/jwks.json`,
  );
  expect(firstJwks.ok()).toBe(true);
  expect((await firstJwks.json()) as { keys: unknown[] }).toMatchObject({ keys: [{}] });
  await page.waitForTimeout(150);
  await page.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByText(/active, ring revision/u)).toBeVisible();

  await page.getByLabel("Provider key").fill(`provider-${suffix}`);
  await page.locator("#provider-name").fill(providerName);
  await page.getByLabel("Canonical HTTPS issuer").fill(providerOrigin);
  await page.getByLabel("Client ID").fill(`client-${suffix}`);
  await page.getByLabel("Client secret (write-only)").fill(providerSecret);
  await page.getByRole("button", { name: "Configure provider" }).click();
  await expect(page.getByText(/write-only/u)).toBeVisible();
  await expect(page.locator("body")).not.toContainText(providerSecret);

  await page.getByLabel("Assign to Application").selectOption({ label: applicationName });
  await page.getByRole("button", { name: "Assign", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("assigned");

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
  const storage = await page.evaluate(async () => ({
    local: localStorage.length,
    session: sessionStorage.length,
    caches: (await caches.keys()).length,
    databases: typeof indexedDB.databases === "function" ? (await indexedDB.databases()).length : 0,
    url: location.href,
  }));
  expect(storage).toMatchObject({ local: 0, session: 0, caches: 0, databases: 0 });
  expect(storage.url).not.toContain(operatorKey);

  const publicConfiguration = await page.request.get(
    `${runtimeBase}v1/projects/${encodeURIComponent(projectPublicId)}/auth/config?application_id=${encodeURIComponent(applicationPublicId)}`,
  );
  expect(publicConfiguration.ok()).toBe(true);
  await expect(publicConfiguration.json()).resolves.toMatchObject({
    application_display_name: applicationName,
    application_public_id: applicationPublicId,
    login_available: true,
    project_display_name: projectName,
    project_public_id: projectPublicId,
    providers: [{ display_name: providerName }],
  });

  const runtimePage = await page.context().newPage();
  const runtimeAuthorizations: string[] = [];
  runtimePage.on("request", (request) => {
    if (request.url().startsWith(runtimeBase)) {
      const authorization = request.headers()["authorization"];
      if (authorization !== undefined) runtimeAuthorizations.push(authorization);
    }
  });
  await runtimePage.goto(`${runtimeBase}auth/`);
  await expect(runtimePage.getByRole("heading", { name: "Hosted authentication" })).toBeVisible();
  await expect(runtimePage.getByText(/No authentication interaction is active/u)).toBeVisible();
  await expect(runtimePage.getByRole("button")).toHaveCount(0);
  expect(runtimeAuthorizations).toEqual([]);
  const runtimeAccessibility = await new AxeBuilder({ page: runtimePage }).analyze();
  expect(runtimeAccessibility.violations).toEqual([]);
});

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}
