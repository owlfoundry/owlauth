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

  await installCspViolationRecorder(page);
  await page.goto(`${controlBase}console/`);
  const controlFavicon = await page.locator('link[rel="icon"]').getAttribute("href");
  expect(controlFavicon).toMatch(/\/console\/assets\/owlauth-favicon\.svg$/u);
  if (controlFavicon === null) throw new Error("Control favicon URL is absent");
  const controlFaviconSvg = await assertSameOriginSvgLoads(page, controlFavicon);
  expect(await cspViolations(page)).toEqual([]);
  for (const viewport of [
    { width: 1920, height: 1080 },
    { width: 390, height: 844 },
    { width: 320, height: 900 },
  ]) {
    await page.setViewportSize(viewport);
    await assertNoDocumentOverflow(page);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    await page.screenshot({
      path: testInfo.outputPath(
        `control-locked-${browserName}-${String(viewport.width)}x${String(viewport.height)}.png`,
      ),
      fullPage: true,
    });
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByLabel("Operator API key").fill(operatorKey);
  await page.getByRole("button", { name: "Unlock console" }).click();
  await expect(page.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Create Project" }).first().click();
  await page.getByLabel("Display name").fill(projectName);
  await page.getByRole("dialog").getByRole("button", { name: "Create Project" }).click();
  await expect(page.getByRole("heading", { name: projectName })).toBeVisible();
  const projectId = new URL(page.url()).pathname.split("/").at(-1);
  if (projectId === undefined || projectId === "") throw new Error("Project route ID is absent");
  const projectContext = page.getByRole("group", { name: "Current project" });
  await expect(projectContext.getByText(projectName, { exact: true })).toBeVisible();
  await expect(projectContext.getByRole("button", { name: "Copy Project ID" })).toBeVisible();
  await expect(projectContext.getByRole("button", { name: "Copy Project ID" })).toHaveAttribute(
    "title",
    "Copy Project ID",
  );
  await expect(
    page.getByRole("list", { name: "Project resource summary" }).getByRole("listitem"),
  ).toHaveCount(4);
  await expect(page.getByRole("link", { name: "Back to projects" })).toBeVisible();
  for (const viewport of [
    { width: 1920, height: 1080 },
    { width: 390, height: 844 },
    { width: 320, height: 900 },
  ]) {
    await page.setViewportSize(viewport);
    await assertNoDocumentOverflow(page);
    await assertOverviewLayout(page, viewport.width);
    await page.screenshot({
      path: testInfo.outputPath(
        `project-overview-${browserName}-${String(viewport.width)}x${String(viewport.height)}.png`,
      ),
      fullPage: true,
    });
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Open navigation" }).click();
  const mobileNavigationSheet = page.getByRole("dialog", { name: "Console navigation" });
  const mobileProjectContext = mobileNavigationSheet.getByRole("group", {
    name: "Current project",
  });
  await expect(mobileProjectContext.getByText(projectName, { exact: true })).toBeVisible();
  await expect(mobileProjectContext.getByRole("button", { name: "Copy Project ID" })).toBeVisible();
  await assertNoDocumentOverflow(page);
  await page.screenshot({
    path: testInfo.outputPath(`project-navigation-${browserName}-390x844.png`),
    fullPage: true,
  });
  await mobileNavigationSheet.getByRole("button", { name: "Close panel" }).click();

  await page.setViewportSize({ width: 1440, height: 900 });
  await page
    .getByRole("navigation", { name: "Breadcrumb" })
    .getByRole("link", { name: "Projects" })
    .click();
  await expect(page.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();
  const projectDirectoryLink = page.getByRole("link", { name: projectName, exact: true });
  await expect(projectDirectoryLink).toBeVisible();
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await assertNoDocumentOverflow(page);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
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
  await expect(page.locator("dt", { hasText: /^Session reuse$/u }).locator("+ dd")).toHaveText(
    "Explicit confirmation allowed",
  );
  await page.getByRole("button", { name: "Edit metadata" }).click();
  await page
    .getByRole("dialog", { name: "Edit Project name" })
    .getByLabel("Display name")
    .fill(updatedProjectName);
  await page.getByRole("button", { name: "Save Project name" }).click();
  await expect(page.getByRole("status").filter({ hasText: "metadata updated" })).toBeVisible();
  await page.getByRole("button", { name: "Edit policy" }).click();
  await page.getByLabel("Access token lifetime in seconds").fill("1200");
  await expect(
    page.getByLabel("Allow users to explicitly confirm reuse of their browser session"),
  ).toBeChecked();
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

  await auditControlRoute(page, testInfo, browserName, "providers");

  await navigateControl(page, "Passwordless email", "Passwordless email");
  await expect(page.getByRole("heading", { name: "Passwordless policy" })).toBeVisible();
  await auditControlRoute(page, testInfo, browserName, "passwordless-email");

  await navigateControl(page, "Users", "Users");
  await expect(page.getByRole("heading", { name: "No users yet" })).toBeVisible();
  const userFilters = page.getByRole("form", { name: "Filter Project users" });
  await expect(userFilters.getByLabel("Search")).toHaveAttribute(
    "placeholder",
    "Name, user ID, or exact email",
  );
  await expect(userFilters.getByLabel("Status")).toHaveValue("all");
  await expect(userFilters.getByLabel("Identity")).toHaveValue("all");
  await expect(
    userFilters.getByLabel("Identity").getByRole("option", { name: providerName }),
  ).toHaveCount(1);
  await expect(userFilters.getByLabel("Sort")).toHaveValue("created_newest");

  const providerResponse = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return (
      url.pathname.endsWith(`/v1/projects/${projectId}/users`) &&
      url.searchParams.get("identity_kind") === "provider" &&
      url.searchParams.get("provider_key") === customProviderKey
    );
  });
  await userFilters.getByLabel("Identity").selectOption(`provider:${customProviderKey}`);
  expect((await providerResponse).ok()).toBe(true);

  const sortResponse = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return (
      url.pathname.endsWith(`/v1/projects/${projectId}/users`) &&
      url.searchParams.get("sort") === "created_oldest"
    );
  });
  await userFilters.getByLabel("Sort").selectOption("created_oldest");
  expect((await sortResponse).ok()).toBe(true);

  await userFilters.getByLabel("Search").fill("Client");
  const searchResponse = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return (
      url.pathname.endsWith(`/v1/projects/${projectId}/users`) &&
      url.searchParams.get("search") === "Client"
    );
  });
  await userFilters.getByRole("button", { name: "Search", exact: true }).click();
  expect((await searchResponse).ok()).toBe(true);
  await expect(page.getByRole("heading", { name: "No matching users" })).toBeVisible();

  await userFilters.getByRole("button", { name: "Clear filters" }).click();
  await expect(page.getByRole("heading", { name: "No users yet" })).toBeVisible();
  await userFilters.getByLabel("Search").fill("User@EXAMPLE.COM");
  const emailResponse = page.waitForResponse((response) =>
    new URL(response.url()).pathname.endsWith(`/v1/projects/${projectId}/users/lookup`),
  );
  await userFilters.getByRole("button", { name: "Search", exact: true }).click();
  const exactLookup = await emailResponse;
  expect(exactLookup.request().method()).toBe("POST");
  expect(exactLookup.request().postDataJSON()).toEqual({ email: "User@EXAMPLE.COM" });
  expect(exactLookup.ok()).toBe(true);
  await expect(page.getByRole("heading", { name: "No matching users" })).toBeVisible();
  await userFilters.getByRole("button", { name: "Clear filters" }).click();
  await expect(page.getByRole("heading", { name: "No users yet" })).toBeVisible();
  const newestResponse = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return (
      url.pathname.endsWith(`/v1/projects/${projectId}/users`) &&
      url.searchParams.get("sort") === "created_newest"
    );
  });
  await userFilters.getByLabel("Sort").selectOption("created_newest");
  expect((await newestResponse).ok()).toBe(true);
  for (const width of [2560, 1920, 1440, 1024, 720, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await assertUserInventoryAlignment(page, width);
  }
  await auditControlRoute(page, testInfo, browserName, "users-empty");

  const missingUserPath = new URL(
    `console/projects/${projectId}/users/00000000-0000-0000-0000-000000000000`,
    controlBase,
  ).pathname;
  await navigateInPlace(page, missingUserPath);
  await expect(page.getByRole("heading", { name: "User detail", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "User not found", exact: true })).toBeVisible();
  await auditControlRoute(page, testInfo, browserName, "user-detail-missing");
  await page.getByRole("link", { name: "Back to users", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Users", exact: true })).toBeVisible();

  await navigateControl(page, "Signing keys", "Signing keys");
  await expect(page.getByText("Status: active", { exact: true }).first()).toBeVisible();
  await auditControlRoute(page, testInfo, browserName, "signing-keys");

  await navigateControl(page, "Project secret keys", "Project secret keys");
  await expect(page.getByRole("heading", { name: "No Project secret keys" })).toBeVisible();
  await auditControlRoute(page, testInfo, browserName, "server-keys-empty");

  await navigateControl(page, "Settings", "Project settings");
  await expect(page.locator("dt", { hasText: /^Session reuse$/u })).toBeVisible();
  await auditControlRoute(page, testInfo, browserName, "project-settings");

  await navigateControl(page, "Applications", "Applications");
  await expect(page.getByRole("link", { name: applicationName, exact: true })).toBeVisible();
  await auditControlRoute(page, testInfo, browserName, "applications");
  await page.getByRole("link", { name: applicationName, exact: true }).click();
  await expect(page.getByRole("heading", { name: applicationName, exact: true })).toBeVisible();
  await auditControlRoute(page, testInfo, browserName, "application-detail");
  await page.getByRole("link", { name: "Webhooks", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Webhook endpoints", exact: true })).toBeVisible();
  await auditControlRoute(page, testInfo, browserName, "application-webhooks");

  await navigateControl(page, "Overview", updatedProjectName);
  await expect(page.getByRole("list", { name: "Project resource summary" })).toBeVisible();
  await auditControlRoute(page, testInfo, browserName, "project-overview-final");

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
  await installCspViolationRecorder(runtimePage);
  const runtimeAuthorizations: string[] = [];
  runtimePage.on("request", (request) => {
    if (request.url().startsWith(runtimeBase)) {
      const authorization = request.headers()["authorization"];
      if (authorization !== undefined) runtimeAuthorizations.push(authorization);
    }
  });
  await runtimePage.goto(`${runtimeBase}auth/`);
  const runtimeFavicon = await runtimePage.locator('link[rel="icon"]').getAttribute("href");
  expect(runtimeFavicon).toMatch(/\/auth\/assets\/owlauth-favicon\.svg$/u);
  if (runtimeFavicon === null) throw new Error("Runtime favicon URL is absent");
  await expect(assertSameOriginSvgLoads(runtimePage, runtimeFavicon)).resolves.toBe(
    controlFaviconSvg,
  );
  expect(await cspViolations(runtimePage)).toEqual([]);
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
  const allProjectsLink = navigationSheet.getByRole("link", { name: "Back to projects" });
  await allProjectsLink.focus();
  await expect(allProjectsLink).toBeFocused();
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
    .getByRole("link", { name: "Back to projects", exact: true })
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

  await navigateInPlace(page, new URL("console/not-a-route", controlBase).pathname);
  await expect(page.getByRole("heading", { name: "Page not found", exact: true })).toBeVisible();
  await auditControlRoute(page, testInfo, browserName, "not-found");
});

async function navigateInPlace(
  page: import("@playwright/test").Page,
  pathname: string,
): Promise<void> {
  await page.evaluate((nextPathname) => {
    window.history.pushState(null, "", nextPathname);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, pathname);
}

async function navigateControl(
  page: import("@playwright/test").Page,
  linkName: string,
  headingName: string,
): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page
    .getByRole("navigation", { name: "Resources" })
    .getByRole("link", { name: linkName, exact: true })
    .click();
  await expect(page.getByRole("heading", { name: headingName, exact: true }).first()).toBeVisible();
}

async function auditControlRoute(
  page: import("@playwright/test").Page,
  testInfo: import("@playwright/test").TestInfo,
  browserName: string,
  routeName: string,
): Promise<void> {
  for (const viewport of [
    { width: 1920, height: 1080 },
    { width: 1440, height: 900 },
    { width: 390, height: 844 },
  ]) {
    await page.setViewportSize(viewport);
    await page.evaluate(() => {
      window.scrollTo(0, 0);
      if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    });
    await assertNoDocumentOverflow(page);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    await page.screenshot({
      path: testInfo.outputPath(
        `${routeName}-${browserName}-${String(viewport.width)}x${String(viewport.height)}.png`,
      ),
      fullPage: true,
    });
  }
  await page.setViewportSize({ width: 1440, height: 900 });
}

async function assertUserInventoryAlignment(
  page: import("@playwright/test").Page,
  viewportWidth: number,
): Promise<void> {
  const toolbar = page.getByRole("form", { name: "Filter Project users" });
  const empty = page.getByRole("heading", { name: "No users yet" }).locator("..");
  const [toolbarBounds, emptyBounds, mainBounds] = await Promise.all([
    measure(toolbar, "Users toolbar"),
    measure(empty, "Users empty state"),
    measure(page.locator("#console-main"), "Console canvas"),
  ]);
  expect(Math.abs(toolbarBounds.x - emptyBounds.x)).toBeLessThanOrEqual(1);
  expect(Math.abs(toolbarBounds.width - emptyBounds.width)).toBeLessThanOrEqual(1);
  expect(toolbarBounds.width).toBeGreaterThanOrEqual(mainBounds.width - 65);

  if (viewportWidth === 1920) {
    expect(mainBounds.width).toBeGreaterThanOrEqual(viewportWidth * 0.8);
    expect(Math.abs(mainBounds.x + mainBounds.width - viewportWidth)).toBeLessThanOrEqual(1);
  }
  if (viewportWidth === 2560) {
    const sidebarBounds = await measure(
      page.locator("aside[aria-label='Console navigation']"),
      "Console sidebar",
    );
    expect(Math.abs(mainBounds.width - 104 * 16)).toBeLessThanOrEqual(1);
    const leftGap = mainBounds.x - (sidebarBounds.x + sidebarBounds.width);
    const rightGap = viewportWidth - (mainBounds.x + mainBounds.width);
    expect(Math.abs(leftGap - rightGap)).toBeLessThanOrEqual(1);
  }

  const [search, status, identity, sort, submit, refresh] = await Promise.all([
    measure(toolbar.getByLabel("Search"), "Search field"),
    measure(toolbar.getByLabel("Status"), "Status filter"),
    measure(toolbar.getByLabel("Identity"), "Identity filter"),
    measure(toolbar.getByLabel("Sort"), "Sort filter"),
    measure(toolbar.getByRole("button", { name: "Search", exact: true }), "Search action"),
    measure(toolbar.getByRole("button", { name: "Refresh", exact: true }), "Refresh action"),
  ]);
  const sameRow = (...bounds: { readonly y: number; readonly height: number }[]) => {
    const bottoms = bounds.map((box) => box.y + box.height);
    expect(Math.max(...bottoms) - Math.min(...bottoms)).toBeLessThanOrEqual(1);
  };
  const precedes = (
    first: { readonly y: number; readonly height: number },
    second: { readonly y: number },
  ) => {
    expect(second.y - (first.y + first.height)).toBeGreaterThanOrEqual(8);
  };

  if (viewportWidth > 1152) {
    sameRow(search, status, identity, sort, submit, refresh);
  } else if (viewportWidth > 768) {
    precedes(search, status);
    sameRow(status, identity, sort);
    precedes(sort, submit);
    sameRow(submit, refresh);
  } else if (viewportWidth > 480) {
    precedes(search, status);
    sameRow(status, identity);
    precedes(identity, sort);
    precedes(sort, submit);
    sameRow(submit, refresh);
  } else {
    precedes(search, status);
    precedes(status, identity);
    precedes(identity, sort);
    precedes(sort, submit);
    precedes(submit, refresh);
  }
}

async function measure(
  locator: import("@playwright/test").Locator,
  label: string,
): Promise<{ x: number; y: number; width: number; height: number }> {
  const bounds = await locator.boundingBox();
  if (bounds === null) throw new Error(`${label} is not measurable`);
  return bounds;
}

async function assertOverviewLayout(
  page: import("@playwright/test").Page,
  width: number,
): Promise<void> {
  const layout = await page
    .getByRole("list", { name: "Project resource summary" })
    .getByRole("listitem")
    .evaluateAll((items) =>
      items.map((item) => {
        const card = item.querySelector<HTMLElement>(":scope > a");
        const heading = card?.querySelector<HTMLElement>("h3");
        const value = card?.querySelector<HTMLElement>("strong");
        if (
          card === null ||
          heading === null ||
          heading === undefined ||
          value === null ||
          value === undefined
        ) {
          throw new Error("Dashboard card layout elements are missing");
        }
        const bounds = card.getBoundingClientRect();
        return {
          bottom: bounds.bottom,
          heading: heading.textContent,
          left: bounds.left,
          right: bounds.right,
          top: bounds.top,
          value: value.textContent,
        };
      }),
    );

  expect(layout).toHaveLength(4);
  for (const card of layout) {
    expect(card.heading).not.toBe("");
    expect(card.value).toMatch(/^\d+$/u);
    expect(card.left).toBeGreaterThanOrEqual(0);
    expect(card.right).toBeLessThanOrEqual(width + 0.5);
  }
  if (width > 768) {
    const tops = layout.map((card) => card.top);
    expect(Math.max(...tops) - Math.min(...tops)).toBeLessThanOrEqual(1);
  } else {
    const lefts = layout.map((card) => card.left);
    expect(Math.max(...lefts) - Math.min(...lefts)).toBeLessThanOrEqual(1);
    for (let index = 1; index < layout.length; index += 1) {
      const previous = layout[index - 1];
      const current = layout[index];
      if (previous === undefined || current === undefined)
        throw new Error("Dashboard card missing");
      expect(current.top - previous.bottom).toBeGreaterThanOrEqual(8);
    }
  }
}

async function installCspViolationRecorder(page: import("@playwright/test").Page): Promise<void> {
  await page.addInitScript(() => {
    const violations: string[] = [];
    const testWindow = window as Window & { __owlauthE2ECspViolations?: unknown };
    testWindow.__owlauthE2ECspViolations = violations;
    document.addEventListener("securitypolicyviolation", (event) => {
      violations.push(`${event.violatedDirective}:${event.blockedURI}`);
    });
  });
}

async function cspViolations(page: import("@playwright/test").Page): Promise<string[]> {
  return page.evaluate(() => {
    const testWindow = window as Window & { __owlauthE2ECspViolations?: unknown };
    const violations = testWindow.__owlauthE2ECspViolations;
    return Array.isArray(violations)
      ? violations.filter((value): value is string => typeof value === "string")
      : ["CSP violation recorder was not installed"];
  });
}

async function assertSameOriginSvgLoads(
  page: import("@playwright/test").Page,
  href: string,
): Promise<string> {
  const result = await page.evaluate(async (faviconHref) => {
    const url = new URL(faviconHref, location.href);
    if (url.origin !== location.origin) throw new Error("Favicon is not same-origin");
    await new Promise<void>((resolve, reject) => {
      const image = new Image();
      image.addEventListener(
        "load",
        () => {
          resolve();
        },
        { once: true },
      );
      image.addEventListener(
        "error",
        () => {
          reject(new Error("Favicon image failed to load"));
        },
        { once: true },
      );
      image.src = url.href;
    });
    const response = await fetch(url.href, { credentials: "omit" });
    return {
      body: await response.text(),
      contentType: response.headers.get("content-type"),
      ok: response.ok,
    };
  }, href);
  expect(result.ok).toBe(true);
  expect(result.contentType).toMatch(/^image\/svg\+xml(?:;|$)/u);
  expect(result.body).toContain("<svg");
  return result.body;
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
