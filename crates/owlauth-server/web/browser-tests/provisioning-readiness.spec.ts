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
  const longProjectName = `${suffix.replaceAll("-", "")}p`.padEnd(128, "p").slice(0, 128);
  const updatedProjectName = `${projectName} updated`;
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
  const projectId = new URL(page.url()).pathname.split("/").at(-1);
  if (projectId === undefined || projectId === "") throw new Error("Project route ID is absent");
  await expect(page.getByRole("list", { name: "Sign-in setup" }).getByRole("listitem")).toHaveCount(
    4,
  );
  await expect(page.getByRole("link", { name: "Switch project" })).toBeVisible();
  for (const width of [1440, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await assertNoDocumentOverflow(page);
    await assertOverviewLayout(page, width);
    await page.screenshot({
      path: testInfo.outputPath(`project-overview-${browserName}-${String(width)}.png`),
      fullPage: true,
    });
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page
    .getByRole("navigation", { name: "Breadcrumb" })
    .getByRole("link", { name: "Projects" })
    .click();
  await expect(page.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();
  const projectDirectoryLink = page.getByRole("link", { name: projectName, exact: true });
  await expect(projectDirectoryLink).toBeVisible();
  for (const width of [1440, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await assertNoDocumentOverflow(page);
    await page.screenshot({
      path: testInfo.outputPath(`project-directory-${browserName}-${String(width)}.png`),
      fullPage: true,
    });
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await projectDirectoryLink.click();
  await expect(page.getByRole("heading", { name: projectName })).toBeVisible();
  const projectPublicId = await page
    .getByRole("button", { name: "Copy Project public ID" })
    .locator("..")
    .locator("code")
    .innerText();

  await page.getByRole("link", { name: "Settings" }).click();
  await page.getByRole("button", { name: "Edit metadata" }).click();
  await page
    .getByRole("dialog", { name: "Edit Project name" })
    .getByLabel("Display name")
    .fill(updatedProjectName);
  await page.getByRole("button", { name: "Save Project name" }).click();
  await expect(page.getByRole("status").filter({ hasText: "metadata updated" })).toBeVisible();
  await page.getByRole("button", { name: "Edit policy" }).click();
  await page.getByLabel("Access token lifetime in seconds").fill("1200");
  await page.getByLabel("Allow users to explicitly confirm reuse of their browser session").check();
  await page.getByRole("button", { name: "Save policy" }).click();
  await expect(page.getByRole("status").filter({ hasText: "policy updated" })).toBeVisible();
  await expect(
    page.locator("dt", { hasText: /^Access token lifetime$/u }).locator("+ dd"),
  ).toHaveText("20 minutes");
  await expect(page.locator("dt", { hasText: /^Session reuse$/u }).locator("+ dd")).toHaveText(
    "Explicit confirmation allowed",
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

  await page.getByRole("button", { name: "Edit name" }).click();
  const nameEditor = page.getByRole("dialog", { name: "Edit Application name" });
  await nameEditor.getByLabel("Display name").fill(`${applicationName} draft`);
  await page.goBack({ waitUntil: "commit", timeout: 2_000 }).catch(() => null);
  await expect(page.getByRole("dialog", { name: "Discard unsaved changes?" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog", { name: "Discard unsaved changes?" })).toHaveCount(0);
  await expect(nameEditor).toBeVisible();
  await expect(nameEditor.getByLabel("Display name")).toHaveValue(`${applicationName} draft`);
  await nameEditor.getByRole("button", { name: "Cancel" }).click();

  await page.getByRole("link", { name: "Login URLs" }).click();
  await page.getByRole("button", { name: "Edit login URLs" }).click();
  const urlEditor = page.getByRole("dialog", { name: "Edit login URLs" });
  await urlEditor
    .getByLabel("Redirect URL 1", { exact: true })
    .fill("https://app.example/callback");
  await urlEditor.getByLabel("Allowed origin 1", { exact: true }).fill("https://app.example");
  await urlEditor.getByRole("button", { name: "Save login URLs" }).click();
  await expect(
    page.getByRole("status").filter({ hasText: "configuration replaced" }),
  ).toBeVisible();

  await page.getByRole("link", { name: "Signing keys" }).click();
  await expect(page.getByText("Status: active", { exact: true }).first()).toBeVisible({
    timeout: 30_000,
  });
  await expect(page.getByRole("button", { name: "Rotate signing key" })).toBeEnabled();
  const firstJwks = await page.request.get(
    `${runtimeBase}projects/${encodeURIComponent(projectPublicId)}/.well-known/jwks.json`,
  );
  expect(firstJwks.ok()).toBe(true);
  expect((await firstJwks.json()) as { keys: unknown[] }).toMatchObject({ keys: [{}] });

  await page.getByRole("link", { name: "Providers" }).click();

  await page.getByRole("button", { name: "Add provider" }).click();
  let providerChooser = page.getByRole("dialog", { name: "Choose a provider" });
  await providerChooser.getByRole("button", { name: /Google/u }).click();
  const googleDialog = page.getByRole("dialog", { name: "Add Google" });
  const googleProviderKey = `google-${suffix}`;
  await expect(googleDialog.getByLabel("Client ID")).toBeDisabled();
  await googleDialog.getByLabel("Provider key").fill(googleProviderKey);
  await googleDialog.getByRole("button", { name: "Review registration settings" }).click();
  await expect(googleDialog.getByRole("heading", { name: "Registration settings" })).toBeVisible();
  await expect(
    googleDialog.getByText("https://accounts.google.com", { exact: true }),
  ).toBeVisible();
  await expect(googleDialog.getByText("openid profile", { exact: true })).toBeVisible();
  await expect(
    googleDialog.getByText(
      `${runtimeBase}projects/${projectPublicId}/auth/callback/${googleProviderKey}`,
      { exact: true },
    ),
  ).toBeVisible();
  await expect(googleDialog.getByLabel("Client ID")).toBeEnabled();
  await googleDialog.getByRole("button", { name: "Close provider setup" }).click();

  await page.getByRole("button", { name: "Add provider" }).click();
  providerChooser = page.getByRole("dialog", { name: "Choose a provider" });
  await providerChooser.getByRole("button", { name: /GitHub/u }).click();
  const githubDialog = page.getByRole("dialog", { name: "Add GitHub" });
  const githubProviderKey = `github-${suffix}`;
  await githubDialog.getByLabel("Provider key").fill(githubProviderKey);
  await githubDialog.getByRole("button", { name: "Review registration settings" }).click();
  await expect(githubDialog.getByRole("heading", { name: "Registration settings" })).toBeVisible();
  await expect(githubDialog.getByText("https://github.com", { exact: true })).toBeVisible();
  await expect(githubDialog.getByText("read:user", { exact: true })).toBeVisible();
  await expect(githubDialog.getByText(/fixed login-only profile/u)).toBeVisible();
  await expect(
    githubDialog.getByText(
      `${runtimeBase}projects/${projectPublicId}/auth/callback/${githubProviderKey}`,
      { exact: true },
    ),
  ).toBeVisible();
  await githubDialog.getByRole("button", { name: "Close provider setup" }).click();

  await page.getByRole("button", { name: "Add provider" }).click();
  providerChooser = page.getByRole("dialog", { name: "Choose a provider" });
  await providerChooser.getByRole("button", { name: /Custom OIDC/u }).click();
  const providerDialog = page.getByRole("dialog", { name: "Add Custom OIDC" });
  const customProviderKey = `provider-${suffix}`;
  await expect(providerDialog.getByLabel("Client ID")).toBeDisabled();
  await providerDialog.getByLabel("Provider key").fill(customProviderKey);
  await providerDialog.getByLabel("Canonical HTTPS issuer").fill(providerOrigin);
  await providerDialog.getByRole("button", { name: "Review registration settings" }).click();
  await expect(providerDialog.getByRole("heading", { name: "Preflight result" })).toBeVisible();
  await expect(
    providerDialog.getByText(
      `${runtimeBase}projects/${projectPublicId}/auth/callback/${customProviderKey}`,
      { exact: true },
    ),
  ).toBeVisible();
  await expect(providerDialog.getByLabel("Client ID")).toBeEnabled();
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
    project_display_name: updatedProjectName,
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
  const switchProjectLink = navigationSheet.getByRole("link", { name: "Switch project" });
  await switchProjectLink.focus();
  await expect(switchProjectLink).toBeFocused();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  const mobileApplicationsLink = navigationSheet.getByRole("link", {
    name: "Applications",
    exact: true,
  });
  await mobileApplicationsLink.focus();
  await expect(mobileApplicationsLink).toBeFocused();
  await mobileApplicationsLink.press("Enter");
  await expect(navigationSheet).toHaveCount(0);
  await expect(page).toHaveURL(new RegExp(`/console/projects/${projectId}/applications$`, "u"));
  const mobileDestinationHeading = page.getByRole("heading", { name: "Applications", exact: true });
  await expect(mobileDestinationHeading).toBeVisible();
  await expect(mobileDestinationHeading).toBeFocused();

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

  await page.emulateMedia({ forcedColors: "none", reducedMotion: "no-preference" });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page
    .getByRole("navigation", { name: "Resources" })
    .getByRole("link", { name: "Projects", exact: true })
    .click();
  await expect(page.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Create Project" }).first().click();
  await page.getByLabel("Display name").fill(longProjectName);
  await page.getByRole("dialog").getByRole("button", { name: "Create Project" }).click();
  await expect(page.getByRole("heading", { name: longProjectName, exact: true })).toBeVisible();
  await page.setViewportSize({ width: 320, height: 900 });
  await assertNoDocumentOverflow(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page
    .getByRole("navigation", { name: "Breadcrumb" })
    .getByRole("link", { name: "Projects" })
    .click();
  await expect(page.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();
  await page.setViewportSize({ width: 320, height: 900 });
  await expect(page.getByRole("link", { name: longProjectName, exact: true })).toBeVisible();
  await assertNoDocumentOverflow(page);
});

async function assertOverviewLayout(
  page: import("@playwright/test").Page,
  width: number,
): Promise<void> {
  const layout = await page
    .getByRole("list", { name: "Sign-in setup" })
    .getByRole("listitem")
    .evaluateAll((steps) =>
      steps.map((step) => {
        const content = step.querySelector<HTMLElement>(":scope > div");
        const heading = step.querySelector<HTMLElement>("h3");
        const badge = heading?.nextElementSibling;
        const action = step.querySelector<HTMLElement>(":scope > a");
        if (
          content === null ||
          heading === null ||
          !(badge instanceof HTMLElement) ||
          action === null
        ) {
          throw new Error("Setup step layout elements are missing");
        }
        const contentBounds = content.getBoundingClientRect();
        const badgeBounds = badge.getBoundingClientRect();
        const actionBounds = action.getBoundingClientRect();
        const stepBounds = step.getBoundingClientRect();
        return {
          action: {
            bottom: actionBounds.bottom,
            left: actionBounds.left,
            right: actionBounds.right,
            top: actionBounds.top,
          },
          badgeWidth: badgeBounds.width,
          content: {
            bottom: contentBounds.bottom,
            left: contentBounds.left,
            right: contentBounds.right,
            top: contentBounds.top,
          },
          step: { left: stepBounds.left, right: stepBounds.right },
        };
      }),
    );

  expect(layout).toHaveLength(4);
  for (const step of layout) {
    expect(step.badgeWidth).toBeLessThan(180);
    expect(step.step.left).toBeGreaterThanOrEqual(0);
    expect(step.step.right).toBeLessThanOrEqual(width + 0.5);
  }
  if (width > 768) {
    const actionRights = layout.map((step) => step.action.right);
    expect(Math.max(...actionRights) - Math.min(...actionRights)).toBeLessThanOrEqual(1);
    for (const step of layout) {
      expect(step.action.left - step.content.right).toBeGreaterThanOrEqual(8);
    }
  } else {
    for (const step of layout) {
      expect(Math.abs(step.action.left - step.content.left)).toBeLessThanOrEqual(1);
      expect(step.action.top - step.content.bottom).toBeGreaterThanOrEqual(8);
    }
  }
}

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
