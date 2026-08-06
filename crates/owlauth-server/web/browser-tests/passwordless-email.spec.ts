import {
  expect,
  request as playwrightRequest,
  test,
  type APIRequestContext,
  type Page,
} from "@playwright/test";

const controlBase = required("OWLAUTH_E2E_CONTROL_BASE");
const runtimeBase = required("OWLAUTH_E2E_RUNTIME_BASE");
const operatorKey = required("OWLAUTH_E2E_OPERATOR_KEY");
const applicationOrigin = required("OWLAUTH_E2E_APPLICATION_ORIGIN");
const mailCaptureUrl = required("OWLAUTH_E2E_MAIL_CAPTURE_URL");
const smtpPort = Number(required("OWLAUTH_E2E_SMTP_PORT"));

interface Project {
  id: string;
  public_id: string;
  metadata_revision: number;
  security_revision: number;
}
interface Application {
  id: string;
  public_id: string;
  security_revision: number;
  configuration: { publishable_keys: string[]; redirect_uris: string[] };
}
interface Policy {
  policy_revision: number;
  security_revision: number;
}
interface SmtpConfiguration {
  id: string;
  revision: number;
  status: string;
}
interface SmtpTestOperation {
  id: string;
  status: string;
  outcome: string | null;
}
interface EmailChallengeAccepted {
  accepted: boolean;
  revision: number;
  challenge_id: string;
  generation: number;
  proof_modes: ("otp" | "magic_link")[];
  expires_at: string;
}
interface ChallengeAttempt {
  hostedUrl: string;
  challengeUrl: string;
  request: { csrf: string; email: string; expected_revision: number };
  response: EmailChallengeAccepted;
}

// This is intentionally a browser product journey. PostgreSQL, the split Control/Runtime
// processes, the Runtime mail worker, TLS SMTP transport, hosted UI, and fragment-only magic
// proof all participate; no test substitutes an API-only completion for either proof.
test("passwordless OTP and fragment magic link are newest-only and one-use", async ({
  page,
  browserName,
}) => {
  // This real journey intentionally crosses two 30-second resend fences and several independent
  // bounded worker leases. Keep each operation bounded below while allowing both SMTP paths to run.
  test.setTimeout(900_000);
  expect(["chromium", "firefox"]).toContain(browserName);
  await page.request.delete(mailCaptureUrl);
  const suffix = `${browserName}-${Date.now().toString(36)}`;
  const { project, application } = await provisionEmail(page.request, suffix);
  const email = `person-${suffix}@example.test`;

  // The product journey starts only after the public contract proves this providerless
  // Application truthfully advertises the currently ready email capability.
  const publicConfiguration = await page.request.get(
    `${runtimeBase}v1/projects/${encodeURIComponent(project.public_id)}/auth/config?application_id=${encodeURIComponent(application.public_id)}`,
  );
  expect(publicConfiguration.ok()).toBe(true);
  await expect(publicConfiguration.json()).resolves.toMatchObject({
    providers: [],
    email_available: true,
    email_otp_enabled: true,
    email_magic_link_enabled: true,
    login_available: true,
  });

  const firstHosted = await startLogin(page.request, project, application, `otp-${suffix}`);
  await page.goto(firstHosted);
  await page.getByRole("button", { name: "Continue with email" }).click();
  await page.getByRole("textbox", { name: "Email address", exact: true }).fill(email);
  await page.getByRole("button", { name: "Send sign-in email" }).click();
  const first = await waitForMail(page.request, 1);
  const firstOtp = otp(first.at(-1) ?? "");

  // Generate a newer sibling. The active page alone owns the opaque challenge handle: a fresh
  // GET must not reconstruct it from the URL or cookie.
  await page.waitForTimeout(31_000);
  await page.getByRole("textbox", { name: "Email address", exact: true }).fill(email);
  await page.getByRole("button", { name: "Send a new message" }).click();
  const second = await waitForMail(page.request, 2);
  const secondOtp = otp(second.at(-1) ?? "");
  expect(secondOtp).not.toBe(firstOtp);
  const reloaded = await page.context().newPage();
  await reloaded.goto(firstHosted);
  await expect(reloaded.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await expect(reloaded.getByRole("button", { name: "Verify code" })).toHaveCount(0);
  await reloaded.close();

  await page.getByLabel("One-time code").fill(firstOtp);
  await page.getByRole("button", { name: "Verify code" }).click();
  await expect(page.getByRole("alert")).toContainText("Code invalid or expired.");
  await page.getByLabel("One-time code").fill(secondOtp);
  await page.getByRole("button", { name: "Verify code" }).click();
  await page.waitForURL((url) => url.origin === applicationOrigin, { timeout: 30_000 });
  await page.goto(firstHosted);
  await expect(page.getByRole("heading", { name: "Sign-in completed" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Verify code" })).toHaveCount(0);
  await expect(page.getByLabel("One-time code")).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText(firstOtp);
  await expect(page.locator("body")).not.toContainText(secondOtp);

  // OTP above used the deployment-default generation. Activate a tested Project generation on
  // the same real implicit-TLS capture before magic so both selection and worker paths are proven.
  await activateProjectSmtp(page.request, project, suffix, email);
  await page.request.delete(mailCaptureUrl);
  const magicHosted = await startLogin(page.request, project, application, `magic-${suffix}`);
  await page.goto(magicHosted);
  await page.getByRole("button", { name: "Continue with email" }).click();
  await page.getByRole("textbox", { name: "Email address", exact: true }).fill(email);
  await page.getByRole("button", { name: "Send sign-in email" }).click();
  const firstMagicMessage = (await waitForMail(page.request, 1)).at(-1) ?? "";
  const firstLink = magicLink(firstMagicMessage);
  await page.waitForTimeout(31_000);
  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible({
    timeout: 10_000,
  });
  await expect(page.getByRole("button", { name: "Send a new message" })).toBeVisible({
    timeout: 10_000,
  });
  await page.getByRole("textbox", { name: "Email address", exact: true }).fill(email);
  await page.getByRole("button", { name: "Send a new message" }).click({ timeout: 10_000 });
  const secondMagicMessage = (await waitForMail(page.request, 2)).at(-1) ?? "";
  const secondLink = magicLink(secondMagicMessage);
  const firstMagicProof = magicProof(firstLink);
  const secondMagicProof = magicProof(secondLink);
  expect(secondLink).not.toBe(firstLink);

  // Scanner-like GETs must use a cookie jar isolated from the browser. Each request is
  // fragmentless and can establish only an inert Gate-0 context in that isolated jar; proving the
  // newest link below still completes proves these prefetches did not consume either proof.
  const scanner = await playwrightRequest.newContext();
  try {
    for (const link of [firstLink, secondLink]) {
      const fragmentless = link.split("#", 1)[0] ?? link;
      const response = await scanner.get(fragmentless);
      expect(response.ok()).toBe(true);
      expect(response.url()).toBe(fragmentless);
      const body = await response.text();
      expect(body).not.toContain(firstMagicProof);
      expect(body).not.toContain(secondMagicProof);
    }
  } finally {
    await scanner.dispose();
  }

  // Gate 0 admits transfer context only for the canonical newest proof. A superseded link and a
  // fresh navigation after completion disclose only the same generic return-to-origin state.
  await page.goto(firstLink);
  await expect(page).not.toHaveURL(/proof=/u, { timeout: 10_000 });
  await expect(page.locator("body")).not.toContainText(firstMagicProof, { timeout: 10_000 });
  await expect(page.getByRole("heading", { name: "This link cannot be used" })).toBeVisible({
    timeout: 10_000,
  });
  await expect(page.getByRole("alert")).toContainText(
    "Return to the browser where sign-in started.",
  );
  await expect(page.getByRole("button", { name: "Continue sign-in", exact: true })).toHaveCount(0, {
    timeout: 10_000,
  });

  await page.goto(secondLink);
  await expect(page).not.toHaveURL(/proof=/u, { timeout: 10_000 });
  await expect(page.locator("body")).not.toContainText(secondMagicProof, { timeout: 10_000 });
  await expect(page.getByRole("heading", { name: "Continue email sign-in" })).toBeVisible({
    timeout: 10_000,
  });
  await page
    .getByRole("button", { name: "Continue sign-in", exact: true })
    .click({ timeout: 10_000 });
  await page.waitForURL((url) => url.origin === applicationOrigin, { timeout: 10_000 });

  await page.goto(secondLink);
  await expect(page.getByRole("heading", { name: "This link cannot be used" })).toBeVisible({
    timeout: 10_000,
  });
  await expect(page.getByRole("alert")).toContainText(
    "Return to the browser where sign-in started.",
  );
});

test("OTP-only and magic-only policies expose and accept only admitted proofs", async ({
  page,
  browserName,
}) => {
  test.skip(browserName !== "chromium", "one browser proves the proof-mode contract matrix");
  test.setTimeout(240_000);
  await page.request.delete(mailCaptureUrl);
  const suffix = `proof-modes-${Date.now().toString(36)}`;

  const otpAuthority = await provisionEmail(page.request, `${suffix}-otp`, {
    otp: true,
    magicLink: false,
  });
  const otpHosted = await startLogin(
    page.request,
    otpAuthority.project,
    otpAuthority.application,
    `otp-only-${suffix}`,
  );
  await page.goto(otpHosted);
  await page.getByRole("button", { name: "Continue with email" }).click();
  await page
    .getByRole("textbox", { name: "Email address", exact: true })
    .fill(`otp-${suffix}@example.test`);
  const otpPending = page.waitForResponse((response) =>
    response.url().endsWith("/email/challenges"),
  );
  await page.getByRole("button", { name: "Send sign-in email" }).click();
  const otpAccepted = (await (await otpPending).json()) as EmailChallengeAccepted;
  expect(otpAccepted.proof_modes).toEqual(["otp"]);
  await expect(page.getByRole("button", { name: "Verify code" })).toBeVisible();
  await expect(page.getByRole("status")).not.toContainText("sign-in link");
  const otpMessage = (await waitForMail(page.request, 1))[0] ?? "";
  expect(otpMessage).toContain("One-time code:");
  expect(otpMessage).not.toContain("Sign-in link:");

  const magicAuthority = await provisionEmail(page.request, `${suffix}-magic`, {
    otp: false,
    magicLink: true,
  });
  const magicHosted = await startLogin(
    page.request,
    magicAuthority.project,
    magicAuthority.application,
    `magic-only-${suffix}`,
  );
  await page.goto(magicHosted);
  await page.getByRole("button", { name: "Continue with email" }).click();
  await page
    .getByRole("textbox", { name: "Email address", exact: true })
    .fill(`magic-${suffix}@example.test`);
  const magicPending = page.waitForResponse((response) =>
    response.url().endsWith("/email/challenges"),
  );
  await page.getByRole("button", { name: "Send sign-in email" }).click();
  const magicResponse = await magicPending;
  const magicRequest = magicResponse.request().postDataJSON() as ChallengeAttempt["request"];
  const magicAccepted = (await magicResponse.json()) as EmailChallengeAccepted;
  expect(magicAccepted.proof_modes).toEqual(["magic_link"]);
  await expect(page.getByRole("button", { name: "Verify code" })).toHaveCount(0);
  await expect(page.getByLabel("One-time code")).toHaveCount(0);
  await expect(page.getByRole("status")).toContainText("Open the newest sign-in link");
  const magicMessage = (await waitForMail(page.request, 2))[1] ?? "";
  expect(magicMessage).toContain("Sign-in link:");
  expect(magicMessage).not.toContain("One-time code:");

  const unsupportedOtp = await sameOriginJsonPost(
    page,
    magicResponse.url().replace(/email\/challenges$/u, "email/otp/verify"),
    {
      csrf: magicRequest.csrf,
      expected_revision: magicAccepted.revision,
      challenge_id: magicAccepted.challenge_id,
      generation: magicAccepted.generation,
      otp: "000000",
    },
  );
  expect(unsupportedOtp.status, unsupportedOtp.body).toBe(200);
  expect(JSON.parse(unsupportedOtp.body)).toEqual({
    completed: false,
    redirect_url: null,
    application_type: null,
  });
  await page.request.delete(mailCaptureUrl);
});

test("native magic-only completion returns trusted custom-scheme navigation once", async ({
  page,
  browser,
  browserName,
}) => {
  test.skip(browserName !== "chromium", "one browser proves native custom-scheme handoff");
  test.setTimeout(240_000);
  await page.request.delete(mailCaptureUrl);
  const suffix = `native-magic-${Date.now().toString(36)}`;
  const authority = await provisionEmail(
    page.request,
    suffix,
    { otp: false, magicLink: true },
    "native",
  );
  const hosted = await startLogin(
    page.request,
    authority.project,
    authority.application,
    `native-${suffix}`,
  );
  await page.goto(hosted);
  await page.getByRole("button", { name: "Continue with email" }).click();
  await page
    .getByRole("textbox", { name: "Email address", exact: true })
    .fill(`native-${suffix}@example.test`);
  const challengePending = page.waitForResponse((response) =>
    response.url().endsWith("/email/challenges"),
  );
  await page.getByRole("button", { name: "Send sign-in email" }).click();
  const accepted = (await (await challengePending).json()) as EmailChallengeAccepted;
  expect(accepted.proof_modes).toEqual(["magic_link"]);
  const message = (await waitForMail(page.request, 1))[0] ?? "";
  const link = magicLink(message);

  // Establish an independent transfer confirmation while the proof is pending. It will race the
  // original bound browser only when the operator explicitly continues below.
  const replayContext = await browser.newContext();
  const replayPage = await replayContext.newPage();
  await replayPage.goto(link);
  await expect(replayPage).not.toHaveURL(/proof=/u, { timeout: 10_000 });
  await expect(replayPage.getByRole("heading", { name: "Continue email sign-in" })).toBeVisible();
  await expect(
    replayPage.getByRole("button", { name: "Continue sign-in", exact: true }),
  ).toBeVisible();

  interface CompletionBody {
    completed: boolean;
    redirect_url: string | null;
    application_type: "web" | "native" | null;
  }
  let backendStatus: number | undefined;
  let backendBody: CompletionBody | undefined;
  let markBackendObserved: (() => void) | undefined;
  const backendObserved = new Promise<void>((resolve) => {
    markBackendObserved = resolve;
  });
  await page.route("**/auth/email/magic/confirm", async (route) => {
    const response = await route.fetch({
      headers: {
        ...route.request().headers(),
        origin: new URL(runtimeBase).origin,
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
      },
    });
    backendStatus = response.status();
    backendBody = (await response.json()) as CompletionBody;
    markBackendObserved?.();
    // The real backend has consumed the proof and returned the native handoff. Keep this browser
    // from invoking an unsupported OS custom-scheme handler; the Runtime branch is covered in
    // Vitest, while this browser receives the ordinary generic terminal representation.
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        completed: false,
        redirect_url: null,
        application_type: null,
      }),
    });
  });
  await page.goto(link);
  await expect(page).not.toHaveURL(/proof=/u, { timeout: 10_000 });
  await expect(page.getByRole("heading", { name: "Continue email sign-in" })).toBeVisible();
  await page.getByRole("button", { name: "Continue sign-in", exact: true }).click();
  await backendObserved;
  await page.unroute("**/auth/email/magic/confirm");
  expect(backendStatus, JSON.stringify(backendBody)).toBe(200);
  expect(backendBody?.completed).toBe(true);
  expect(backendBody?.application_type).toBe("native");
  expect(backendBody?.redirect_url).toMatch(/^com\.example\.owlauth\.[a-z0-9]+:\/callback\?/u);

  // Completion consumed both proof and parent login exactly once. The already-established fresh
  // transfer context still requires explicit confirmation, and its second POST is generic.

  const replayPending = replayPage.waitForResponse((response) =>
    response.url().endsWith("/auth/email/magic/confirm"),
  );
  await replayPage.getByRole("button", { name: "Continue sign-in", exact: true }).click();
  const replay = await replayPending;
  expect(replay.status(), await replay.text()).toBe(200);
  expect(await replay.json()).toEqual({
    completed: false,
    redirect_url: null,
    application_type: null,
  });
  await expect(replayPage.getByRole("heading", { name: "Link invalid or expired" })).toBeVisible({
    timeout: 10_000,
  });
  expect(replayPage.url()).not.toMatch(/^com\.example\.owlauth\./u);
  await replayContext.close();
  await page.request.delete(mailCaptureUrl);
});

test("scoped address suppression is API and Hosted-state indistinguishable", async ({
  page,
  browserName,
}) => {
  test.skip(browserName !== "chromium", "one browser exhausts the shared scoped-address lane");
  test.setTimeout(420_000);
  await page.request.delete(mailCaptureUrl);
  const suffix = `suppression-${Date.now().toString(36)}`;
  const { project, application } = await provisionEmail(page.request, suffix);
  const email = `hot-${suffix}@example.test`;
  const attempts: ChallengeAttempt[] = [];

  // EmailChallenge has a 256-request owner/client envelope and a 64-request scoped-address
  // bucket. Distinct interactions therefore saturate only the server-derived address dimension;
  // the 65th request must still commit and return the ordinary authoritative contract.
  for (let index = 0; index <= 64; index += 1) {
    const hostedUrl = await startLogin(
      page.request,
      project,
      application,
      `suppression-${suffix}-${String(index)}`,
    );
    await page.goto(hostedUrl);
    await page.getByRole("button", { name: "Continue with email" }).click();
    await page.getByRole("textbox", { name: "Email address", exact: true }).fill(email);
    const pending = page.waitForResponse(
      (response) =>
        response.request().method() === "POST" && response.url().endsWith("/email/challenges"),
    );
    await page.getByRole("button", { name: "Send sign-in email" }).click();
    const response = await pending;
    expect(response.status(), await response.text()).toBe(202);
    const request = response.request().postDataJSON() as ChallengeAttempt["request"];
    const accepted = (await response.json()) as EmailChallengeAccepted;
    expect(accepted.accepted).toBe(true);
    expect(accepted.revision).toBe(4);
    expect(accepted.generation).toBe(1);
    attempts.push({
      hostedUrl,
      challengeUrl: response.url(),
      request,
      response: accepted,
    });
  }

  const initialDeliveries = await waitForMail(page.request, 64);
  expect(initialDeliveries).toHaveLength(64);

  const admitted = attempts[0];
  const suppressed = attempts[64];
  if (admitted === undefined || suppressed === undefined) throw new Error("missing challenge");
  expectContractEquivalent(admitted.response, suppressed.response, 4, 1);
  expect(initialDeliveries.join("\n")).not.toContain(suppressed.response.challenge_id);
  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Verify code" })).toBeVisible();

  // A fresh Hosted document derives the same durable pending state, while opaque proof handles
  // remain page-memory-only exactly as for an admitted generation.
  const refreshed = await page.context().newPage();
  await refreshed.goto(suppressed.hostedUrl);
  await expect(refreshed.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await expect(refreshed.getByRole("button", { name: "Verify code" })).toHaveCount(0);
  await refreshed.close();

  // Saturate the independent resend address lane after one shared cooldown. Each interaction
  // advances to generation two; the final resend is suppressed yet returns the same contract as
  // the first admitted resend and keeps current/newest revision semantics.
  await page.waitForTimeout(31_000);
  const resends: EmailChallengeAccepted[] = [];
  for (const attempt of attempts) {
    const response = await sameOriginJsonPost(
      page,
      attempt.challengeUrl.replace(/email\/challenges$/u, "email/resend"),
      { ...attempt.request, expected_revision: 4 },
    );
    expect(response.status, response.body).toBe(202);
    resends.push(JSON.parse(response.body) as EmailChallengeAccepted);
  }
  const admittedResend = resends[0];
  const suppressedResend = resends[64];
  if (admittedResend === undefined || suppressedResend === undefined) {
    throw new Error("missing resend response");
  }
  expectContractEquivalent(admittedResend, suppressedResend, 5, 2);
  const allDeliveries = await waitForMail(page.request, 128);
  expect(allDeliveries).toHaveLength(128);
  expect(allDeliveries.join("\n")).not.toContain(suppressed.response.challenge_id);
  expect(allDeliveries.join("\n")).not.toContain(suppressedResend.challenge_id);

  const invalid = await sameOriginJsonPost(
    page,
    suppressed.challengeUrl.replace(/email\/challenges$/u, "email/otp/verify"),
    {
      csrf: suppressed.request.csrf,
      expected_revision: 5,
      challenge_id: suppressedResend.challenge_id,
      generation: suppressedResend.generation,
      otp: "000000",
    },
  );
  expect(invalid.status, invalid.body).toBe(200);
  const invalidBody = JSON.parse(invalid.body) as {
    completed: boolean;
    redirect_url: string | null;
    application_type: "web" | "native" | null;
  };
  expect(invalidBody).toEqual({
    completed: false,
    redirect_url: null,
    application_type: null,
  });

  // The original in-memory generation is now an older sibling and receives the same generic UI
  // result; neither response discloses which address-lane requests were suppressed.
  await page.getByLabel("One-time code").fill("000000");
  await page.getByRole("button", { name: "Verify code" }).click();
  await expect(page.getByRole("alert")).toContainText("Code invalid or expired.");

  // All 128 admitted jobs are now physically accounted for, while both suppressed generations
  // are absent. Clearing only after that exact drain makes the following Firefox project
  // hermetic without a retry delay or cooldown assumption.
  await page.request.delete(mailCaptureUrl);
});

async function sameOriginJsonPost(
  page: Page,
  url: string,
  data: unknown,
): Promise<{ status: number; body: string }> {
  return page.evaluate(
    async ({ requestUrl, requestData }) => {
      const response = await fetch(requestUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(requestData),
      });
      return { status: response.status, body: await response.text() };
    },
    { requestUrl: url, requestData: data },
  );
}

function expectContractEquivalent(
  admitted: EmailChallengeAccepted,
  suppressed: EmailChallengeAccepted,
  revision: number,
  generation: number,
): void {
  expect(Object.keys(suppressed).sort()).toEqual(Object.keys(admitted).sort());
  expect(suppressed.accepted).toBe(admitted.accepted);
  expect(suppressed.revision).toBe(revision);
  expect(suppressed.generation).toBe(generation);
  expect(suppressed.proof_modes).toEqual(admitted.proof_modes);
  expect(suppressed.challenge_id).toMatch(/^[0-9a-f-]{36}$/u);
  expect(Number.isNaN(Date.parse(suppressed.expires_at))).toBe(false);
}

async function provisionEmail(
  request: APIRequestContext,
  suffix: string,
  proofModes: { otp: boolean; magicLink: boolean } = { otp: true, magicLink: true },
  applicationType: "web" | "native" = "web",
): Promise<{ project: Project; application: Application }> {
  const project = await control<Project>(
    request,
    "POST",
    "projects",
    {
      display_name: `Passwordless ${suffix}`,
      belongs_to: null,
    },
    `email-project-${suffix}`,
  );
  let application = await control<Application>(
    request,
    "POST",
    `projects/${project.id}/applications`,
    { application_type: applicationType, display_name: "Passwordless E2E" },
    `email-app-${suffix}`,
  );
  application = await control<Application>(
    request,
    "PUT",
    `projects/${project.id}/applications/${application.id}/configuration`,
    {
      allowed_origins: [applicationOrigin],
      expected_security_revision: application.security_revision,
      redirect_uris: [
        applicationType === "native"
          ? `com.example.owlauth.${suffix.replace(/[^a-z0-9]/giu, "")}:/callback`
          : `${applicationOrigin}/sdk/callback`,
      ],
    },
  );
  const key = await control<{ id: string; ring_revision: number }>(
    request,
    "POST",
    `projects/${project.id}/signing-keys`,
    { expected_project_revision: project.metadata_revision },
    `email-key-${suffix}`,
  );
  const jwks = await request.get(
    `${runtimeBase}projects/${encodeURIComponent(project.public_id)}/.well-known/jwks.json`,
  );
  expect(jwks.ok()).toBe(true);
  await pageDelay(150);
  await control(request, "POST", `projects/${project.id}/signing-keys/${key.id}/activate`, {
    expected_ring_revision: key.ring_revision,
  });
  const policy = await get<Policy>(request, `projects/${project.id}/email-method`);
  await control(request, "PUT", `projects/${project.id}/email-method`, {
    enabled: true,
    otp_enabled: proofModes.otp,
    magic_link_enabled: proofModes.magicLink,
    otp_digits: 6,
    otp_validity_seconds: 300,
    otp_max_attempts: 3,
    resend_after_seconds: 30,
    max_generations: 3,
    magic_validity_seconds: 300,
    signup_enabled: true,
    transferred_magic_link_enabled: true,
    allow_deployment_default: true,
    expected_policy_revision: policy.policy_revision,
    expected_security_revision: policy.security_revision,
  });
  await control(
    request,
    "PUT",
    `projects/${project.id}/applications/${application.id}/email-method`,
    { enabled: true, expected_application_security_revision: application.security_revision },
  );
  return { project, application };
}

async function activateProjectSmtp(
  request: APIRequestContext,
  project: Project,
  suffix: string,
  recipient: string,
): Promise<void> {
  const configuration = await control<SmtpConfiguration>(
    request,
    "POST",
    `projects/${project.id}/smtp-configurations`,
    {
      host: "localhost",
      port: smtpPort,
      tls_mode: "implicit_tls",
      sender_address: "project-login@owlauth.test",
      sender_name: "OwlAuth Project E2E",
      reply_to: null,
      credential: JSON.stringify({ username: "capture-user", password: "capture-password" }),
      expected_project_security_revision: project.security_revision,
    },
    `project-smtp-${suffix}`,
  );
  const operation = await control<SmtpTestOperation>(
    request,
    "POST",
    `projects/${project.id}/smtp-configurations/${configuration.id}/test`,
    { recipient, expected_revision: configuration.revision },
    `project-smtp-test-${suffix}`,
  );
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const current = await get<SmtpTestOperation>(
      request,
      `projects/${project.id}/smtp-configurations/${configuration.id}/tests/${operation.id}`,
    );
    if (current.status === "delivered") {
      expect(current.outcome).toBe("delivered");
      await control(
        request,
        "POST",
        `projects/${project.id}/smtp-configurations/${configuration.id}/activate`,
        { expected_revision: configuration.revision },
      );
      return;
    }
    if (current.status === "failed") {
      throw new Error(`Project SMTP test failed with ${String(current.outcome)}`);
    }
    await pageDelay(250);
  }
  throw new Error("timed out waiting for Project SMTP test delivery");
}

async function startLogin(
  request: APIRequestContext,
  project: Project,
  application: Application,
  state: string,
): Promise<string> {
  const response = await request.post(
    `${runtimeBase}v1/projects/${encodeURIComponent(project.public_id)}/auth/login/start`,
    {
      headers: { origin: applicationOrigin },
      data: {
        application_id: application.public_id,
        publishable_key: application.configuration.publishable_keys[0],
        redirect_uri: application.configuration.redirect_uris[0],
        pkce_challenge: "A".repeat(43),
        presentation_hint: null,
        state,
      },
    },
  );
  expect(response.status(), await response.text()).toBe(201);
  return ((await response.json()) as { hosted_url: string }).hosted_url;
}

async function waitForMail(request: APIRequestContext, count: number): Promise<string[]> {
  for (let attempt = 0; attempt < 240; attempt += 1) {
    const response = await request.get(mailCaptureUrl);
    const messages = ((await response.json()) as { messages: string[] }).messages;
    if (messages.length >= count) return messages;
    await pageDelay(250);
  }
  throw new Error(`timed out waiting for ${String(count)} captured messages`);
}

function otp(message: string): string {
  const value = /One-time code: (\d{6,10})/u.exec(message)?.[1];
  if (value === undefined) throw new Error("captured message has no OTP");
  return value;
}

function magicLink(message: string): string {
  const value = /Sign-in link: (https?:\/\/\S+)/u.exec(message)?.[1];
  if (value === undefined) throw new Error("captured message has no magic link");
  return value;
}

function magicProof(link: string): string {
  const value = new URLSearchParams(new URL(link).hash.slice(1)).get("proof");
  if (value === null || value === "") throw new Error("captured magic link has no proof");
  return value;
}

async function get<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(`${controlBase}v1/${path}`, {
    headers: { authorization: `Bearer ${operatorKey}` },
  });
  expect(response.ok(), await response.text()).toBe(true);
  return (await response.json()) as T;
}

async function control<T = unknown>(
  request: APIRequestContext,
  method: "POST" | "PUT",
  path: string,
  data: unknown,
  idempotencyKey?: string,
): Promise<T> {
  const response = await request.fetch(`${controlBase}v1/${path}`, {
    method,
    data,
    headers: {
      authorization: `Bearer ${operatorKey}`,
      ...(idempotencyKey === undefined ? {} : { "idempotency-key": idempotencyKey }),
    },
  });
  expect(response.ok(), `${method} ${path}: ${await response.text()}`).toBe(true);
  return (await response.json()) as T;
}

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}

async function pageDelay(milliseconds: number): Promise<void> {
  await new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}
