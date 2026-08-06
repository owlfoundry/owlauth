import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const controlBase = requiredEnvironment("OWLAUTH_E2E_CONTROL_BASE");
const runtimeBase = requiredEnvironment("OWLAUTH_E2E_RUNTIME_BASE");
const operatorKey = requiredEnvironment("OWLAUTH_E2E_OPERATOR_KEY");
const providerOrigin = requiredEnvironment("OWLAUTH_E2E_PROVIDER_ORIGIN");

test("fresh-database operator journey reaches exact Runtime readiness", async ({
  page,
  browserName,
}, testInfo) => {
  const suffix = `${browserName}-${Date.now().toString(36)}`;
  const injectionMarker = `<img src=x onerror=alert('${suffix}')>`;
  const projectName = `E2E Project ${injectionMarker}`;
  const applicationName = `E2E Application ${injectionMarker}`;
  const providerName = `E2E Provider ${injectionMarker}`;
  const providerSecret = `secret-${suffix}`;

  await page.goto(`${controlBase}console/`);
  await page.getByLabel("Operator API key").fill(operatorKey);
  await page.getByRole("button", { name: "Unlock console" }).click();
  await expect(page.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Create Project" }).first().click();
  await page.getByLabel("Display name").fill(projectName);
  await page.getByRole("dialog").getByRole("button", { name: "Create Project" }).click();
  await expect(page.getByRole("heading", { name: projectName })).toBeVisible();
  const projectPublicId = await page
    .locator("dt", { hasText: /^Public ID$/u })
    .locator("+ dd")
    .innerText();

  await page.getByRole("link", { name: "Settings" }).click();
  await page.getByRole("button", { name: "Edit metadata" }).click();
  await page.getByLabel("External owner metadata").fill(`deployment-${suffix}`);
  await page.getByRole("button", { name: "Save metadata" }).click();
  await expect(page.getByRole("status").filter({ hasText: "metadata updated" })).toBeVisible();
  await page.getByRole("button", { name: "Edit policy" }).click();
  await page.getByLabel("Access token lifetime in seconds").fill("1200");
  await page.getByLabel("Allow explicit browser-session reuse confirmation").check();
  await page.getByRole("button", { name: "Save policy" }).click();
  await expect(page.getByRole("status").filter({ hasText: "policy updated" })).toBeVisible();
  await expect(page.locator("dt", { hasText: /^Claims revision$/u }).locator("+ dd")).toHaveText(
    "2",
  );
  await expect(page.locator("dt", { hasText: /^Session revision$/u }).locator("+ dd")).toHaveText(
    "2",
  );

  await page.getByRole("link", { name: "Applications", exact: true }).click();
  await page.getByRole("button", { name: "Create Application" }).first().click();
  await page.getByLabel("Display name").fill(applicationName);
  await page.getByRole("dialog").getByRole("button", { name: "Create Application" }).click();
  await expect(page.getByRole("heading", { name: applicationName })).toBeVisible();
  const applicationPublicId = await page
    .locator("dt", { hasText: /^Public ID$/u })
    .locator("+ dd")
    .innerText();

  await page.getByRole("button", { name: "Edit configuration" }).click();
  await page.getByLabel("Redirect URIs").fill("https://app.example/callback");
  await page.getByLabel("Allowed origins").fill("https://app.example");
  await page.getByRole("button", { name: "Replace configuration" }).click();
  await expect(
    page.getByRole("status").filter({ hasText: "configuration replaced" }),
  ).toBeVisible();

  await page.getByRole("link", { name: "Signing keys" }).click();
  await expect(page.getByText(/active, ring revision/u)).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("button", { name: "Rotate signing key" })).toBeEnabled();
  const firstJwks = await page.request.get(
    `${runtimeBase}projects/${encodeURIComponent(projectPublicId)}/.well-known/jwks.json`,
  );
  expect(firstJwks.ok()).toBe(true);
  expect((await firstJwks.json()) as { keys: unknown[] }).toMatchObject({ keys: [{}] });

  await page.getByRole("link", { name: "Providers" }).click();
  await page.getByRole("button", { name: "Add Custom OIDC" }).click();
  const providerDialog = page.getByRole("dialog", { name: "Add Custom OIDC" });
  await providerDialog.getByLabel("Canonical HTTPS issuer").fill(providerOrigin);
  await providerDialog.getByRole("button", { name: "Run preflight" }).click();
  await expect(providerDialog.getByRole("heading", { name: "Preflight result" })).toBeVisible();
  await providerDialog.getByLabel("Provider key").fill(`provider-${suffix}`);
  await providerDialog.getByLabel("Display name").fill(providerName);
  await providerDialog.getByLabel("Client ID").fill(`client-${suffix}`);
  await providerDialog.getByLabel("Client secret").fill(providerSecret);
  await providerDialog.getByRole("button", { name: "Add provider" }).click();
  await expect(page.getByRole("status").filter({ hasText: "secret was discarded" })).toBeVisible();
  await expect(page.locator("body")).not.toContainText(providerSecret);

  await page.getByLabel("Assign to Application").selectOption({ label: applicationName });
  await page.getByRole("button", { name: "Assign provider" }).click();
  await expect(page.getByRole("status").filter({ hasText: "assigned" })).toBeVisible();

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
  await expect(page.locator("img[src='x']")).toHaveCount(0);
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
  await expect(runtimePage.getByRole("heading", { name: "No sign-in is active" })).toBeVisible();
  await expect(runtimePage.getByRole("button")).toHaveCount(0);
  expect(runtimeAuthorizations).toEqual([]);
  const runtimeAccessibility = await new AxeBuilder({ page: runtimePage }).analyze();
  expect(runtimeAccessibility.violations).toEqual([]);

  for (const width of [1440, 1024, 768, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await page.evaluate(() => {
      window.scrollTo(0, 0);
      if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    });
    await assertNoDocumentOverflow(page);
    await page.screenshot({
      path: testInfo.outputPath(`control-${browserName}-${String(width)}.png`),
      fullPage: true,
    });
    await runtimePage.setViewportSize({ width, height: 900 });
    await runtimePage.evaluate(() => {
      window.scrollTo(0, 0);
    });
    await assertNoDocumentOverflow(runtimePage);
    await runtimePage.screenshot({
      path: testInfo.outputPath(`runtime-${browserName}-${String(width)}.png`),
      fullPage: true,
    });
  }

  await page.getByRole("button", { name: "Open navigation" }).click();
  const navigationSheet = page.getByRole("dialog", { name: "Console navigation" });
  await expect(navigationSheet).toBeVisible();
  const projectSwitcher = navigationSheet.getByLabel("Project context");
  await navigationSheet.getByText("Project context", { exact: true }).click();
  await expect(projectSwitcher).toBeFocused();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await navigationSheet.getByRole("button", { name: "Close navigation" }).click();

  // A 1440px desktop at 200% browser zoom exposes roughly a 720 CSS-pixel layout viewport.
  for (const candidate of [page, runtimePage]) {
    await candidate.setViewportSize({ width: 720, height: 450 });
    await assertNoDocumentOverflow(candidate);
    await candidate.emulateMedia({ reducedMotion: "reduce" });
    await expect(candidate.locator("body")).toHaveCSS("scroll-behavior", "auto");
    await candidate.emulateMedia({ forcedColors: "active", reducedMotion: "reduce" });
    await expect
      .poll(() => candidate.evaluate(() => window.matchMedia("(forced-colors: active)").matches))
      .toBe(true);
    expect(
      await candidate.evaluate(() =>
        getComputedStyle(document.documentElement).getPropertyValue("--owl-text").trim(),
      ),
    ).toBe("CanvasText");
    // Forced-colors paint-time substitutions are intentionally absent from computed RGB values,
    // so axe cannot calculate meaningful contrast in this emulation. Keep every structural rule
    // enabled while directly asserting the system-color token above.
    expect(
      (await new AxeBuilder({ page: candidate }).disableRules(["color-contrast"]).analyze())
        .violations,
    ).toEqual([]);
  }
});

async function assertNoDocumentOverflow(page: import("@playwright/test").Page): Promise<void> {
  await expect
    .poll(() =>
      page.evaluate(() => ({
        clientWidth: document.documentElement.clientWidth,
        scrollWidth: document.documentElement.scrollWidth,
      })),
    )
    .toMatchObject({ clientWidth: expect.any(Number), scrollWidth: expect.any(Number) });
  const dimensions = await page.evaluate(() => {
    const clientWidth = document.documentElement.clientWidth;
    const overflowing = Array.from(document.querySelectorAll<HTMLElement>("body *"))
      .filter((element) => {
        const bounds = element.getBoundingClientRect();
        return bounds.right > clientWidth + 0.5 || bounds.left < -0.5;
      })
      .slice(0, 12)
      .map((element) => ({
        className: element.className,
        left: element.getBoundingClientRect().left,
        right: element.getBoundingClientRect().right,
        tagName: element.tagName,
      }));
    return {
      clientWidth,
      overflowing,
      scrollWidth: document.documentElement.scrollWidth,
    };
  });
  expect(
    dimensions.scrollWidth,
    `document overflow: ${JSON.stringify(dimensions.overflowing)}`,
  ).toBeLessThanOrEqual(dimensions.clientWidth);
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}
