import AxeBuilder from "@axe-core/playwright";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";

import { expect, test, type APIRequestContext, type Browser, type Page } from "@playwright/test";

import { BrowserEvidence, type BrowserEvidenceSnapshot } from "./browser-evidence";

const controlBase = required("OWLAUTH_E2E_CONTROL_BASE");
const runtimeBase = required("OWLAUTH_E2E_RUNTIME_BASE");
const operatorKey = required("OWLAUTH_E2E_OPERATOR_KEY");
const providerOrigin = required("OWLAUTH_E2E_PROVIDER_ORIGIN");
const providerClientId = required("OWLAUTH_E2E_PROVIDER_CLIENT_ID");
const providerClientSecret = required("OWLAUTH_E2E_PROVIDER_CLIENT_SECRET");
const applicationOrigin = required("OWLAUTH_E2E_APPLICATION_ORIGIN");
const mailCaptureUrl = required("OWLAUTH_E2E_MAIL_CAPTURE_URL");
const postgresContainer = required("OWLAUTH_E2E_POSTGRES_CONTAINER");
const runtimeLog = required("OWLAUTH_E2E_RUNTIME_LOG");
const controlLog = required("OWLAUTH_E2E_CONTROL_LOG");

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
interface Provider {
  id: string;
}
interface EmailPolicy {
  policy_revision: number;
  security_revision: number;
}
interface ProjectUser {
  id: string;
  public_id: string;
  status: "active" | "disabled" | "merged";
  user_revision: number;
  security_revision: number;
}
interface Identity {
  id: string;
  user_id: string;
  identity_kind: "provider" | "email";
  identity_revision: number;
  is_primary_source: boolean;
  status: "active" | "disabled";
  provider_key?: string;
  address?: "redacted";
}
interface Slot {
  id: string;
  role:
    "destination_owner" | "candidate_identity" | "identity_owner" | "winner_owner" | "loser_owner";
  identity_kind: "provider" | "email";
  method_kind: "provider" | "email";
  proved: boolean;
}
interface Intent {
  id: string;
  project_id: string;
  operation_kind: "link" | "unlink" | "merge";
  status: "pending_proof" | "ready" | "completed" | "expired" | "cancelled";
  revision: number;
  effective_expires_at: string;
  slots: Slot[];
  hosted_target?: string | null;
}
interface Credentials {
  project_id: string;
  application_id: string;
  user_id: string;
  session_id: string;
  refresh_generation: number;
  access_token: string;
  refresh_token: string;
  projection_revision: number;
  projection: {
    user_id: string;
    user_revision: number;
    projection_revision: number;
    projection_schema: string;
    verified_email: string | null;
  };
}
interface Authority {
  project: Project;
  application: Application;
  provider: Provider;
}

// The complete mutation lifecycle is intentionally one serial Chromium product journey. It uses
// only public Runtime/Control HTTP and browser surfaces for setup and mutation. PostgreSQL is read
// only after public commits to prove erasure, one-use, projection, ownership, and terminal state.
test("public identity Link, Email Link, Unlink, and Merge preserve exact authority", async ({
  browser,
  browserName,
}) => {
  test.skip(browserName !== "chromium", "the full state/race matrix runs once in Chromium");
  test.setTimeout(900_000);
  const suffix = `identity-${Date.now().toString(36)}`;
  const context = await browser.newContext();
  const evidence = await BrowserEvidence.create(context);
  const supplementalEvidence: BrowserEvidenceSnapshot[] = [];
  const page = await context.newPage();
  await page.request.delete(mailCaptureUrl);

  try {
    const authority = await provision(page.request, suffix);
    const firstEmail = `winner-${suffix}@example.test`;
    const linkedEmail = `linked-${suffix}@example.test`;
    const loserEmail = `loser-${suffix}@example.test`;

    const winnerCredentials = await emailLogin(page, authority, firstEmail, `winner-${suffix}`);
    let winner = await userByPublicId(
      page.request,
      authority.project.id,
      winnerCredentials.user_id,
    );
    let winnerIdentities = await identities(page.request, authority.project.id, winner.id);
    expect(winnerIdentities).toMatchObject([
      { identity_kind: "email", status: "active", address: "redacted", is_primary_source: true },
    ]);
    const firstEmailIdentity = only(winnerIdentities);

    const providerLink = await createIntent(
      page.request,
      authority.project.id,
      `link-provider-${suffix}`,
      {
        operation_kind: "link",
        destination: userTarget(winner),
        destination_identity: identityReference(firstEmailIdentity),
        candidate_identity_kind: "provider",
        destination_proof_authority: emailAuthority(authority.application),
        candidate_proof_authority: providerAuthority(authority),
      },
    );
    expect(providerLink.hosted_target).toBeTruthy();
    await completeEmailSlot(
      page,
      providerLink.hosted_target ?? "",
      "destination_owner",
      firstEmail,
    );
    await completeProviderSlot(page, "candidate_identity");
    await markReady(page);
    const readyProviderLink = await intent(page.request, authority.project.id, providerLink.id);
    expect(readyProviderLink.status).toBe("ready");

    // Stale Control revision cannot authorize the final operation. Two exact confirmations race;
    // one commits and the loser observes a conflict/terminal state rather than reopening receipts.
    const stale = await controlRaw(
      page.request,
      "POST",
      `projects/${authority.project.id}/identity-mutation-intents/${providerLink.id}/confirm`,
      {
        operation_kind: "link",
        expected_revision: readyProviderLink.revision - 1,
        confirmation: "link_identity",
      },
    );
    expect(stale.status()).toBe(409);
    const confirmation = {
      operation_kind: "link",
      expected_revision: readyProviderLink.revision,
      confirmation: "link_identity",
    };
    const [providerWinner, providerLoser] = await Promise.all([
      controlRaw(
        page.request,
        "POST",
        `projects/${authority.project.id}/identity-mutation-intents/${providerLink.id}/confirm`,
        confirmation,
      ),
      controlRaw(
        page.request,
        "POST",
        `projects/${authority.project.id}/identity-mutation-intents/${providerLink.id}/confirm`,
        confirmation,
      ),
    ]);
    expect([providerWinner.status(), providerLoser.status()].sort()).toEqual([200, 409]);

    winner = await userById(page.request, authority.project.id, winner.id);
    winnerIdentities = await identities(page.request, authority.project.id, winner.id);
    expect(
      winnerIdentities.filter(
        ({ identity_kind, status }) => identity_kind === "provider" && status === "active",
      ),
    ).toHaveLength(1);
    const providerIdentity = only(
      winnerIdentities.filter(
        ({ identity_kind, status }) => identity_kind === "provider" && status === "active",
      ),
    );

    // Runtime current-user stays the bounded projection contract (identities are Control-only),
    // while its independent projection revision remains coherent after the identity commit.
    const currentAfterProvider = await currentUser(
      page.request,
      authority.project,
      winnerCredentials.access_token,
    );
    expect(currentAfterProvider.user_id).toBe(winner.public_id);
    expect(currentAfterProvider.projection).not.toHaveProperty("identities");
    expect(currentAfterProvider.projection.projection_schema).toBe("owlauth.user.v1");
    expect(currentAfterProvider.projection_revision).toBeGreaterThanOrEqual(
      winnerCredentials.projection_revision,
    );

    const emailLink = await createIntent(
      page.request,
      authority.project.id,
      `link-email-${suffix}`,
      {
        operation_kind: "link",
        destination: userTarget(winner),
        destination_identity: identityReference(providerIdentity),
        candidate_identity_kind: "email",
        destination_proof_authority: providerAuthority(authority),
        candidate_proof_authority: emailAuthority(authority.application),
      },
    );
    await page.goto(emailLink.hosted_target ?? "");
    await completeProviderSlot(page, "destination_owner");
    supplementalEvidence.push(
      ...(await completeEmailMagicSlot(
        browser,
        page,
        page.url(),
        "candidate_identity",
        linkedEmail,
        only(emailLink.slots.filter(({ role }) => role === "destination_owner")).id,
      )),
    );
    await markReady(page);
    const readyEmailLink = await intent(page.request, authority.project.id, emailLink.id);
    await confirm(page.request, authority.project.id, readyEmailLink, "link_identity");

    winner = await userById(page.request, authority.project.id, winner.id);
    winnerIdentities = await identities(page.request, authority.project.id, winner.id);
    const linkedEmailIdentity = only(
      winnerIdentities.filter(
        ({ id, identity_kind, status }) =>
          id !== firstEmailIdentity.id && identity_kind === "email" && status === "active",
      ),
    );

    // Exact unlink proof removes only the selected non-primary email. Provider and original email
    // preserve login capability, and the fixed primary disposition cannot be altered at confirm.
    const unlink = await createIntent(page.request, authority.project.id, `unlink-${suffix}`, {
      operation_kind: "unlink",
      owner: userTarget(winner),
      identity: identityReference(linkedEmailIdentity),
      proof_authority: emailAuthority(authority.application),
      primary_source_disposition: { disposition: "preserve" },
    });
    await completeEmailSlot(page, unlink.hosted_target ?? "", "identity_owner", linkedEmail);
    await markReady(page);
    const readyUnlink = await intent(page.request, authority.project.id, unlink.id);
    await confirm(page.request, authority.project.id, readyUnlink, "unlink_identity");
    winner = await userById(page.request, authority.project.id, winner.id);
    winnerIdentities = await identities(page.request, authority.project.id, winner.id);
    expect(winnerIdentities.find(({ id }) => id === linkedEmailIdentity.id)?.status).toBe(
      "disabled",
    );
    expect(winnerIdentities.find(({ id }) => id === firstEmailIdentity.id)?.status).toBe("active");
    expect(winnerIdentities.find(({ id }) => id === providerIdentity.id)?.status).toBe("active");

    const loserCredentials = await emailLogin(page, authority, loserEmail, `loser-${suffix}`);
    let loser = await userByPublicId(page.request, authority.project.id, loserCredentials.user_id);
    const loserIdentity = only(await identities(page.request, authority.project.id, loser.id));

    // A provider candidate already owned by winner cannot silently turn a Link into Merge. The
    // candidate proof may be rejected or the immutable Link may conflict at confirmation, but no
    // public outcome moves ownership and both users remain distinct.
    const collision = await createIntent(
      page.request,
      authority.project.id,
      `collision-${suffix}`,
      {
        operation_kind: "link",
        destination: userTarget(loser),
        destination_identity: identityReference(loserIdentity),
        candidate_identity_kind: "provider",
        destination_proof_authority: emailAuthority(authority.application),
        candidate_proof_authority: providerAuthority(authority),
      },
    );
    await completeEmailSlot(page, collision.hosted_target ?? "", "destination_owner", loserEmail);
    await page.getByRole("button", { name: "Start provider proof" }).click();
    await expect(page).toHaveURL(/auth\/identity-mutations\//u, { timeout: 30_000 });
    const collisionState = await intent(page.request, authority.project.id, collision.id);
    expect(collisionState.operation_kind).toBe("link");
    expect(collisionState.status).not.toBe("completed");
    expect(
      (await identities(page.request, authority.project.id, winner.id)).find(
        ({ id }) => id === providerIdentity.id,
      )?.user_id,
    ).toBe(winner.id);
    await cancel(page.request, authority.project.id, collisionState);

    // Cancelled intent stays terminal and cannot be proved or confirmed.
    const cancelled = await createIntent(page.request, authority.project.id, `cancel-${suffix}`, {
      operation_kind: "unlink",
      owner: userTarget(winner),
      identity: identityReference(providerIdentity),
      proof_authority: providerAuthority(authority),
      primary_source_disposition: { disposition: "preserve" },
    });
    await page.goto(cancelled.hosted_target ?? "");
    const cancelledBound = await intent(page.request, authority.project.id, cancelled.id);
    const cancelledState = await cancel(page.request, authority.project.id, cancelledBound);
    expect(cancelledState.status).toBe("cancelled");
    await page.reload();
    await expect(page.getByRole("heading", { name: "Request unavailable" })).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByRole("alert")).toContainText("create a new identity-management request");
    expect(
      (
        await controlRaw(
          page.request,
          "POST",
          `projects/${authority.project.id}/identity-mutation-intents/${cancelled.id}/confirm`,
          {
            operation_kind: "unlink",
            expected_revision: cancelledState.revision,
            confirmation: "unlink_identity",
          },
        )
      ).status(),
    ).toBe(409);

    // Freeze one ordinary loser handoff before merge. It is public, PKCE-bound authority but must
    // lose after the loser tombstone commits, just like stale refresh authority.
    const loserHandoff = await emailLoginHandoff(
      page,
      authority,
      loserEmail,
      `loser-handoff-${suffix}`,
    );

    // Merge uses both fresh proofs and fixed dispositions. A duplicate provider callback is also
    // replayed while collecting winner proof; the duplicate remains bounded and does not mint a
    // second receipt or reopen the slot.
    winner = await userById(page.request, authority.project.id, winner.id);
    loser = await userById(page.request, authority.project.id, loser.id);
    const merge = await createIntent(page.request, authority.project.id, `merge-${suffix}`, {
      operation_kind: "merge",
      winner: userTarget(winner),
      winner_identity: identityReference(providerIdentity),
      winner_proof_authority: providerAuthority(authority),
      loser: userTarget(loser),
      loser_identity: identityReference(loserIdentity),
      loser_proof_authority: emailAuthority(authority.application),
      primary_source: identityReference(firstEmailIdentity),
      sessions_disposition: "loser_revoked",
      bindings_disposition: "winner_preferred",
    });
    await page.goto(merge.hosted_target ?? "");
    const callback = await completeProviderSlot(page, "winner_owner");
    const callbackReplay = await page.request.get(callback, { maxRedirects: 0 });
    expect([303, 400, 409]).toContain(callbackReplay.status());
    await completeEmailSlot(page, page.url(), "loser_owner", loserEmail);
    await markReady(page);
    const readyMerge = await intent(page.request, authority.project.id, merge.id);

    const refreshAtConfirmation = refresh(page.request, authority, loserCredentials.refresh_token);
    const mergeConfirmation = confirm(
      page.request,
      authority.project.id,
      readyMerge,
      "merge_users",
    );
    const [refreshResult, completedMerge] = await Promise.all([
      refreshAtConfirmation,
      mergeConfirmation,
    ]);
    expect(completedMerge.status).toBe("completed");
    // The refresh may linearize just before merge and succeed once, or lose. Any returned successor
    // is fenced by the merge and cannot remain usable afterward.
    let staleRefresh = loserCredentials.refresh_token;
    if (refreshResult.status() === 200) {
      staleRefresh = ((await refreshResult.json()) as Credentials).refresh_token;
    } else {
      expect([400, 409]).toContain(refreshResult.status());
    }
    expect((await refresh(page.request, authority, staleRefresh)).status()).not.toBe(200);
    expect((await exchangeHandoff(page.request, authority, loserHandoff)).status()).not.toBe(200);

    const finalWinner = await userById(page.request, authority.project.id, winner.id);
    const finalLoser = await userById(page.request, authority.project.id, loser.id);
    expect(finalWinner.status).toBe("active");
    expect(finalLoser.status).toBe("merged");
    const finalWinnerIdentities = await identities(page.request, authority.project.id, winner.id);
    expect(finalWinnerIdentities.find(({ id }) => id === loserIdentity.id)?.user_id).toBe(
      winner.id,
    );
    expect(finalWinnerIdentities.filter(({ status }) => status === "active")).toHaveLength(3);

    assertDatabasePostconditions(
      authority.project.id,
      [providerLink.id, emailLink.id, unlink.id, collision.id, cancelled.id, merge.id],
      winner.id,
      loser.id,
    );
    await assertEvidenceAndLogs(evidence, supplementalEvidence, [
      firstEmail,
      linkedEmail,
      loserEmail,
    ]);
  } finally {
    await context.close();
  }
});

// Firefox exercises the same embedded Runtime and Console documents with keyboard/focus/error and
// axe checks without duplicating the expensive merge/confirmation race matrix.
test("identity Runtime and Console flows are keyboard and accessibility safe", async ({
  browser,
  browserName,
}) => {
  test.setTimeout(360_000);
  expect(["chromium", "firefox"]).toContain(browserName);
  const suffix = `identity-a11y-${browserName}-${Date.now().toString(36)}`;
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.request.delete(mailCaptureUrl);
  try {
    const authority = await provision(page.request, suffix);
    const email = `a11y-${suffix}@example.test`;
    const credentials = await emailLogin(page, authority, email, suffix);
    const user = await userByPublicId(page.request, authority.project.id, credentials.user_id);
    const identity = only(await identities(page.request, authority.project.id, user.id));
    const mutation = await createIntent(page.request, authority.project.id, `a11y-${suffix}`, {
      operation_kind: "unlink",
      owner: userTarget(user),
      identity: identityReference(identity),
      proof_authority: emailAuthority(authority.application),
      primary_source_disposition: { disposition: "clear" },
    });
    await page.goto(mutation.hosted_target ?? "");
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    await page.keyboard.press("Tab");
    await expect(page.getByRole("button", { name: "Start email proof" })).toBeFocused();
    await page.getByRole("button", { name: "Start email proof" }).press("Enter");
    await page.getByLabel("Email address for this proof").fill(email);
    await page.getByRole("button", { name: "Send verification email" }).press("Enter");
    await waitForMail(page.request, 1);
    await page.getByLabel("One-time code").fill("000000");
    await page.getByRole("button", { name: "Verify newest code" }).press("Enter");
    await expect(page.getByRole("heading", { name: "Action not completed" })).toBeFocused();
    await expect(page.getByRole("alert")).toContainText("code was not accepted");
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);

    const consolePage = await context.newPage();
    await consolePage.goto(`${controlBase}console/`);
    await consolePage.getByLabel("Operator API key").fill(operatorKey);
    await consolePage.getByRole("button", { name: "Unlock console" }).press("Enter");
    await expect(consolePage.getByRole("heading", { name: "Projects" })).toBeVisible();
    await consolePage
      .getByRole("button", { name: new RegExp(`Identity ${suffix}`, "u") })
      .press("Enter");
    await consolePage.getByRole("button", { name: "Load Project users" }).press("Enter");
    await consolePage.getByRole("button", { name: new RegExp(user.public_id, "u") }).press("Enter");
    await expect(
      consolePage.getByRole("heading", { name: "Identity link, unlink, and merge" }),
    ).toBeVisible();
    expect((await new AxeBuilder({ page: consolePage }).analyze()).violations).toEqual([]);
    await consolePage.getByLabel("Operation").focus();
    await consolePage.getByLabel("Operation").selectOption("unlink");
    await expect(consolePage.getByLabel("Operation")).toBeFocused();
    await consolePage.getByLabel("Read an existing intent by ID").fill("not-a-uuid");
    await consolePage.getByRole("button", { name: "Read intent" }).press("Enter");
    await expect(consolePage.getByRole("status")).toContainText("Enter a valid intent ID");
    expect((await new AxeBuilder({ page: consolePage }).analyze()).violations).toEqual([]);
    expect(consolePage.url()).not.toContain(operatorKey);
  } finally {
    await context.close();
  }
});

async function provision(request: APIRequestContext, suffix: string): Promise<Authority> {
  const project = await control<Project>(
    request,
    "POST",
    "projects",
    { display_name: `Identity ${suffix}`, belongs_to: null },
    `identity-project-${suffix}`,
  );
  let application = await control<Application>(
    request,
    "POST",
    `projects/${project.id}/applications`,
    { application_type: "web", display_name: `Identity App ${suffix}` },
    `identity-app-${suffix}`,
  );
  application = await control<Application>(
    request,
    "PUT",
    `projects/${project.id}/applications/${application.id}/configuration`,
    {
      allowed_origins: [applicationOrigin],
      expected_security_revision: application.security_revision,
      redirect_uris: [`${applicationOrigin}/sdk/callback`],
    },
  );
  const signing = await control<{ id: string; ring_revision: number }>(
    request,
    "POST",
    `projects/${project.id}/signing-keys`,
    { expected_project_revision: project.metadata_revision },
    `identity-signing-${suffix}`,
  );
  expect(
    (
      await request.get(
        `${runtimeBase}projects/${encodeURIComponent(project.public_id)}/.well-known/jwks.json`,
      )
    ).ok(),
  ).toBe(true);
  await delay(150);
  await control(request, "POST", `projects/${project.id}/signing-keys/${signing.id}/activate`, {
    expected_ring_revision: signing.ring_revision,
  });
  const policy = await get<EmailPolicy>(request, `projects/${project.id}/email-method`);
  await control(request, "PUT", `projects/${project.id}/email-method`, {
    enabled: true,
    otp_enabled: true,
    magic_link_enabled: true,
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
  application = await get<Application>(
    request,
    `projects/${project.id}/applications/${application.id}`,
  );
  const provider = await control<Provider>(
    request,
    "POST",
    `projects/${project.id}/providers`,
    {
      client_id: providerClientId,
      client_secret: providerClientSecret,
      display_name: "Controlled Provider",
      expected_project_revision: project.metadata_revision,
      issuer: providerOrigin,
      managed_profile_enabled: true,
      provider_key: "controlled-provider",
    },
    `identity-provider-${suffix}`,
  );
  await control(
    request,
    "PUT",
    `projects/${project.id}/providers/${provider.id}/assignments/${application.id}`,
    { expected_application_revision: application.security_revision },
  );
  return { project, application, provider };
}

async function emailLogin(
  page: Page,
  authority: Authority,
  email: string,
  state: string,
): Promise<Credentials> {
  const pending = await emailLoginHandoff(page, authority, email, state);
  const response = await exchangeHandoff(page.request, authority, pending);
  expect(response.status(), await response.text()).toBe(200);
  return (await response.json()) as Credentials;
}

interface PendingHandoff {
  handoff: string;
  verifier: string;
}

async function emailLoginHandoff(
  page: Page,
  authority: Authority,
  email: string,
  state: string,
): Promise<PendingHandoff> {
  await page.request.delete(mailCaptureUrl);
  const verifier = randomBytes(32).toString("base64url");
  const hosted = await startLogin(page.request, authority, state, verifier);
  await page.goto(hosted);
  await page.getByRole("button", { name: "Continue with email" }).click();
  await page.getByRole("textbox", { name: "Email address", exact: true }).fill(email);
  await page.getByRole("button", { name: "Send sign-in email" }).click();
  const code = otp(only(await waitForMail(page.request, 1)));
  await page.getByLabel("One-time code").fill(code);
  await page.getByRole("button", { name: "Verify code" }).click();
  await page.waitForURL((url) => url.origin === applicationOrigin, { timeout: 30_000 });
  const handoff = new URL(page.url()).searchParams.get("handoff");
  if (handoff === null) throw new Error("ordinary email login omitted handoff");
  return { handoff, verifier };
}

function exchangeHandoff(
  request: APIRequestContext,
  authority: Authority,
  pending: PendingHandoff,
) {
  return request.post(
    `${runtimeBase}v1/projects/${encodeURIComponent(authority.project.public_id)}/auth/handoff/exchange`,
    {
      data: {
        application_id: authority.application.public_id,
        publishable_key: only(authority.application.configuration.publishable_keys),
        handoff: pending.handoff,
        pkce_verifier: pending.verifier,
      },
    },
  );
}

async function startLogin(
  request: APIRequestContext,
  authority: Authority,
  state: string,
  verifier: string,
): Promise<string> {
  const response = await request.post(
    `${runtimeBase}v1/projects/${encodeURIComponent(authority.project.public_id)}/auth/login/start`,
    {
      headers: { origin: applicationOrigin },
      data: {
        application_id: authority.application.public_id,
        publishable_key: only(authority.application.configuration.publishable_keys),
        redirect_uri: only(authority.application.configuration.redirect_uris),
        pkce_challenge: createHash("sha256").update(verifier).digest("base64url"),
        presentation_hint: null,
        state,
      },
    },
  );
  expect(response.status(), await response.text()).toBe(201);
  return ((await response.json()) as { hosted_url: string }).hosted_url;
}

async function completeEmailSlot(
  page: Page,
  target: string,
  role: Slot["role"],
  email: string,
): Promise<void> {
  if (page.url() !== target) await page.goto(target);
  const item = page.getByRole("listitem").filter({ hasText: roleLabel(role) });
  await item.getByRole("button", { name: "Start email proof" }).click();
  await item.getByLabel("Email address for this proof").fill(email);
  await page.request.delete(mailCaptureUrl);
  await item.getByRole("button", { name: "Send verification email" }).click();
  const code = otp(only(await waitForMail(page.request, 1)));
  await item.getByLabel("One-time code").fill(code);
  await item.getByRole("button", { name: "Verify newest code" }).click();
  await expect(item).toContainText("state: proved", { timeout: 30_000 });
}

async function completeEmailMagicSlot(
  browser: Browser,
  page: Page,
  target: string,
  role: Slot["role"],
  email: string,
  wrongSlotId: string,
): Promise<BrowserEvidenceSnapshot[]> {
  if (page.url() !== target) await page.goto(target);
  const item = page.getByRole("listitem").filter({ hasText: roleLabel(role) });
  await item.getByRole("button", { name: "Start email proof" }).click();
  await page.request.delete(mailCaptureUrl);
  await item.getByLabel("Email address for this proof").fill(email);
  await item.getByRole("button", { name: "Send verification email" }).click();
  const firstLink = magicLink(only(await waitForMail(page.request, 1)));

  // Identity-mutation resend has the same real 30-second minimum as ordinary login. Waiting for
  // the actual fence (rather than changing a clock) proves newest-generation authority.
  await page.waitForTimeout(31_000);
  await item.getByLabel("Email address for this proof").fill(email);
  await item.getByRole("button", { name: "Send a newer email" }).click();
  const messages = await waitForMail(page.request, 2);
  const secondLink = magicLink(messages[1] ?? "");
  expect(secondLink).not.toBe(firstLink);
  const proof = magicProof(secondLink);

  const snapshots: BrowserEvidenceSnapshot[] = [];
  // A real isolated top-level browser GET (the shape used by link scanners) receives no fragment
  // proof and cannot consume the newest challenge.
  const scannerContext = await browser.newContext();
  const scannerEvidence = await BrowserEvidence.create(scannerContext);
  try {
    const scannerPage = await scannerContext.newPage();
    const fragmentless = secondLink.split("#", 1)[0] ?? secondLink;
    const response = await scannerPage.goto(fragmentless);
    expect(response?.ok()).toBe(true);
    expect(scannerPage.url()).toBe(fragmentless);
    await expect(scannerPage.locator("body")).not.toContainText(proof);
    snapshots.push(await scannerEvidence.snapshot());
  } finally {
    await scannerContext.close();
  }

  // A caller-supplied wrong slot cannot override the exact slot frozen into the challenge. The
  // Hosted bootstrap and fragment disagree, so no POST or proof consumption occurs.
  const wrongContext = await browser.newContext();
  const wrongEvidence = await BrowserEvidence.create(wrongContext);
  try {
    const wrongPage = await wrongContext.newPage();
    const wrong = new URL(secondLink);
    const fragment = new URLSearchParams(wrong.hash.slice(1));
    fragment.set("slot", wrongSlotId);
    wrong.hash = fragment.toString();
    await wrongPage.goto(wrong.href);
    await expect(wrongPage).not.toHaveURL(/proof=/u);
    await expect(
      wrongPage.getByRole("heading", { name: "Verification link unavailable" }),
    ).toBeVisible();
    snapshots.push(await wrongEvidence.snapshot());
  } finally {
    await wrongContext.close();
  }

  const firstContext = await browser.newContext();
  const secondContext = await browser.newContext();
  const firstEvidence = await BrowserEvidence.create(firstContext);
  const secondEvidence = await BrowserEvidence.create(secondContext);
  try {
    const firstPage = await firstContext.newPage();
    const secondPage = await secondContext.newPage();
    await firstPage.goto(secondLink);
    await secondPage.goto(secondLink);
    for (const transferPage of [firstPage, secondPage]) {
      await expect(transferPage).not.toHaveURL(/proof=/u);
      await expect(transferPage.locator("body")).not.toContainText(proof);
      await expect(
        transferPage.getByRole("button", { name: "Transfer proof to the identity request" }),
      ).toBeVisible();
    }

    // Corrupt only the CSRF half while preserving the browser's HttpOnly transfer cookie. This is
    // an honest partial-capability mismatch test; it deliberately does not claim that theft of a
    // complete cookie+CSRF bearer is detectable.
    await secondPage.route("**/email/link/verify", async (route) => {
      const requestBody = route.request().postDataJSON() as Record<string, unknown>;
      const csrf = typeof requestBody["csrf"] === "string" ? requestBody["csrf"] : "";
      await route.continue({
        postData: JSON.stringify({
          ...requestBody,
          csrf: `${csrf.slice(0, -1)}${csrf.endsWith("A") ? "B" : "A"}`,
        }),
      });
    });
    await secondPage
      .getByRole("button", { name: "Transfer proof to the identity request" })
      .click();
    await expect(
      secondPage.getByRole("heading", { name: "Verification link unavailable" }),
    ).toBeVisible();

    await firstPage.getByRole("button", { name: "Transfer proof to the identity request" }).click();
    await expect(firstPage.getByRole("heading", { name: "Identity proof received" })).toBeVisible();
    snapshots.push(await firstEvidence.snapshot(), await secondEvidence.snapshot());
  } finally {
    await Promise.all([firstContext.close(), secondContext.close()]);
  }

  // A fresh transfer context after the winner sees the generic one-use failure.
  const replayContext = await browser.newContext();
  const replayEvidence = await BrowserEvidence.create(replayContext);
  try {
    const replayPage = await replayContext.newPage();
    await replayPage.goto(secondLink);
    const replayTransfer = replayPage.getByRole("button", {
      name: "Transfer proof to the identity request",
    });
    if ((await replayTransfer.count()) === 1) await replayTransfer.click();
    await expect(
      replayPage.getByRole("heading", { name: "Verification link unavailable" }),
    ).toBeVisible();
    snapshots.push(await replayEvidence.snapshot());
  } finally {
    await replayContext.close();
  }

  await page.reload();
  await expect(page.getByRole("listitem").filter({ hasText: roleLabel(role) })).toContainText(
    "state: proved",
  );
  return snapshots;
}

async function completeProviderSlot(page: Page, role: Slot["role"]): Promise<string> {
  const item = page.getByRole("listitem").filter({ hasText: roleLabel(role) });
  await item.getByRole("button", { name: "Start provider proof" }).click();
  await page.waitForURL(/auth\/identity-mutations\//u, { timeout: 30_000 });
  const callback = page.url();
  await expect(page.getByRole("listitem").filter({ hasText: roleLabel(role) })).toContainText(
    "state: proved",
  );
  return callback;
}

async function markReady(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Mark proofs ready for operator review" }).click();
  await expect(
    page.getByRole("heading", { name: "Proofs ready for operator review" }),
  ).toBeVisible();
}

function roleLabel(role: Slot["role"]): string {
  return (
    {
      destination_owner: "Destination owner proof",
      candidate_identity: "New identity proof",
      identity_owner: "Identity owner proof",
      winner_owner: "Winning user proof",
      loser_owner: "Losing user proof",
    } as const
  )[role];
}

async function createIntent(
  request: APIRequestContext,
  projectId: string,
  key: string,
  body: unknown,
): Promise<Intent> {
  return control<Intent>(
    request,
    "POST",
    `projects/${projectId}/identity-mutation-intents`,
    body,
    key,
  );
}
async function intent(
  request: APIRequestContext,
  projectId: string,
  intentId: string,
): Promise<Intent> {
  return get(request, `projects/${projectId}/identity-mutation-intents/${intentId}`);
}
async function cancel(
  request: APIRequestContext,
  projectId: string,
  current: Intent,
): Promise<Intent> {
  const path = `projects/${projectId}/identity-mutation-intents/${current.id}/cancel`;
  let candidate = current;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (candidate.status === "cancelled" || candidate.status === "expired") return candidate;
    const response = await controlRaw(request, "POST", path, {
      expected_revision: candidate.revision,
    });
    if (response.ok()) return (await response.json()) as Intent;
    expect(response.status(), await response.text()).toBe(409);
    await delay(50);
    candidate = await intent(request, projectId, current.id);
  }
  throw new Error("identity mutation did not reach a cancellable stable revision");
}
async function confirm(
  request: APIRequestContext,
  projectId: string,
  current: Intent,
  confirmation: "link_identity" | "unlink_identity" | "merge_users",
): Promise<Intent> {
  return control(
    request,
    "POST",
    `projects/${projectId}/identity-mutation-intents/${current.id}/confirm`,
    { operation_kind: current.operation_kind, expected_revision: current.revision, confirmation },
  );
}
async function identities(
  request: APIRequestContext,
  projectId: string,
  userId: string,
): Promise<Identity[]> {
  return (
    await get<{ items: Identity[] }>(request, `projects/${projectId}/users/${userId}/identities`)
  ).items;
}
async function userById(
  request: APIRequestContext,
  projectId: string,
  userId: string,
): Promise<ProjectUser> {
  return get(request, `projects/${projectId}/users/${userId}`);
}
async function userByPublicId(
  request: APIRequestContext,
  projectId: string,
  publicId: string,
): Promise<ProjectUser> {
  const users = (await get<{ items: ProjectUser[] }>(request, `projects/${projectId}/users`)).items;
  const user = users.find((candidate) => candidate.public_id === publicId);
  if (user === undefined) throw new Error(`Control inventory omitted Runtime user ${publicId}`);
  return user;
}
function userTarget(user: ProjectUser) {
  return {
    user_id: user.id,
    expected_user_revision: user.user_revision,
    expected_user_security_revision: user.security_revision,
  };
}
function identityReference(identity: Identity) {
  return {
    identity_kind: identity.identity_kind,
    identity_id: identity.id,
    expected_identity_revision: identity.identity_revision,
  };
}
function emailAuthority(application: Application) {
  return { method_kind: "email", application_id: application.id };
}
function providerAuthority(authority: Authority) {
  return {
    method_kind: "provider",
    application_id: authority.application.id,
    provider_id: authority.provider.id,
  };
}
async function currentUser(
  request: APIRequestContext,
  project: Project,
  accessToken: string,
): Promise<{
  user_id: string;
  projection_revision: number;
  projection: Credentials["projection"];
}> {
  const response = await request.get(
    `${runtimeBase}v1/projects/${encodeURIComponent(project.public_id)}/auth/users/me`,
    { headers: { authorization: `Bearer ${accessToken}` } },
  );
  expect(response.status(), await response.text()).toBe(200);
  return (await response.json()) as {
    user_id: string;
    projection_revision: number;
    projection: Credentials["projection"];
  };
}
function refresh(request: APIRequestContext, authority: Authority, refreshToken: string) {
  return request.post(
    `${runtimeBase}v1/projects/${encodeURIComponent(authority.project.public_id)}/auth/sessions/refresh`,
    {
      data: {
        application_id: authority.application.public_id,
        publishable_key: only(authority.application.configuration.publishable_keys),
        refresh_token: refreshToken,
      },
    },
  );
}

function assertDatabasePostconditions(
  projectId: string,
  intentIds: string[],
  winnerId: string,
  loserId: string,
): void {
  const ids = intentIds.map((id) => `'${id.replaceAll("'", "''")}'`).join(",");
  const result = postgresJson(`
    SELECT json_build_object(
      'receipts', (SELECT json_agg(json_build_object('intent_id',intent_id,'status',status,'consumed',consumed_at IS NOT NULL)) FROM identity_proof_receipts WHERE intent_id IN (${ids})),
      'evidence_count', (SELECT count(*) FROM identity_mutation_candidate_evidence WHERE intent_id IN (${ids})),
      'live_create_results', (SELECT count(*) FROM identity_mutation_create_results WHERE intent_id IN (${ids}) AND create_result_ciphertext IS NOT NULL),
      'winner_projection', (SELECT max(projection_revision) FROM application_user_projections WHERE project_id='${projectId}' AND user_id='${winnerId}'),
      'loser', (SELECT json_build_object('status',status,'merged_into_user_id',merged_into_user_id) FROM project_users WHERE project_id='${projectId}' AND id='${loserId}'),
      'loser_sessions', (SELECT json_agg(status) FROM application_sessions WHERE project_id='${projectId}' AND user_id='${loserId}')
    );
  `) as {
    receipts: { intent_id: string; status: string; consumed: boolean }[];
    evidence_count: number;
    live_create_results: number;
    winner_projection: number;
    loser: { status: string; merged_into_user_id: string };
    loser_sessions: string[];
  };
  const completed = new Set(intentIds.slice(0, 3).concat(intentIds.at(-1) ?? ""));
  expect(
    result.receipts
      .filter(({ intent_id }) => completed.has(intent_id))
      .every(({ status, consumed }) => status === "consumed" && consumed),
  ).toBe(true);
  expect(result.evidence_count).toBe(0);
  expect(result.live_create_results).toBe(0);
  expect(result.winner_projection).toBeGreaterThan(0);
  expect(result.loser).toEqual({ status: "merged", merged_into_user_id: winnerId });
  expect(result.loser_sessions.every((status) => status !== "active")).toBe(true);
}

function postgresJson(sql: string): unknown {
  const wrapped = `BEGIN READ ONLY; ${sql} COMMIT;`;
  const output = execFileSync(
    "docker",
    [
      "exec",
      postgresContainer,
      "psql",
      "-U",
      "postgres",
      "-d",
      "postgres",
      "-X",
      "-q",
      "-t",
      "-A",
      "-c",
      wrapped,
    ],
    { encoding: "utf8" },
  );
  const line = output
    .split("\n")
    .map((value) => value.trim())
    .find((value) => value.startsWith("{"));
  if (line === undefined)
    throw new Error(`read-only PostgreSQL inspection returned no JSON: ${output}`);
  return JSON.parse(line) as unknown;
}

async function assertEvidenceAndLogs(
  evidence: BrowserEvidence,
  supplemental: BrowserEvidenceSnapshot[],
  emails: string[],
): Promise<void> {
  const snapshots = [await evidence.snapshot(), ...supplemental];
  for (const snapshot of snapshots) {
    assertBrowserEvidence(snapshot);
    const consoleDocument = snapshot.consoleMessages.join("\n");
    for (const email of emails) expect(consoleDocument).not.toContain(email);
  }
  const logs = `${await readFile(runtimeLog, "utf8")}\n${await readFile(controlLog, "utf8")}`;
  for (const email of emails) expect(logs).not.toContain(email);
  expect(logs).not.toMatch(/managed-(?:access|refresh)-[A-Za-z0-9_-]+/u);
  expect(logs).not.toMatch(/One-time code:\s*\d{6,10}/u);
}

function assertBrowserEvidence(snapshot: BrowserEvidenceSnapshot): void {
  expect(snapshot.consoleMessages.join("\n")).not.toMatch(
    /One-time code|managed-(?:access|refresh)-|access_token|refresh_token|id_token|proof=/u,
  );
  expect(snapshot.storageState).not.toMatch(/One-time code|managed-(?:access|refresh)-/u);
  for (const sample of snapshot.lifecycle) {
    expect(
      `${sample.cookies}\n${sample.history}\n${JSON.stringify(sample.local)}\n${JSON.stringify(sample.session)}`,
    ).not.toMatch(/managed-(?:access|refresh)-|\b\d{6}\b/u);
    expect(sample.url).not.toMatch(/access_token|refresh_token|id_token/u);
    // The reviewed magic-link transport necessarily exists in the pre-application fragment URL.
    // The flow assertions above and every final sample prove synchronous removal before transfer.
    if (sample.reason === "final") expect(sample.url).not.toContain("proof=");
  }
  for (const record of [...snapshot.requests, ...snapshot.responses]) {
    expect(record.url).not.toMatch(/access_token|refresh_token|id_token|proof=/u);
  }
}

async function waitForMail(request: APIRequestContext, count: number): Promise<string[]> {
  for (let attempt = 0; attempt < 240; attempt += 1) {
    const response = await request.get(mailCaptureUrl);
    const messages = ((await response.json()) as { messages: string[] }).messages;
    if (messages.length >= count) return messages;
    await delay(250);
  }
  throw new Error(`timed out waiting for ${String(count)} messages`);
}
function otp(message: string): string {
  const value = /One-time code: (\d{6,10})/u.exec(message)?.[1];
  if (value === undefined) throw new Error("captured message has no OTP");
  return value;
}
function magicLink(message: string): string {
  const value = /(?:Sign-in|Verification) link: (https?:\/\/\S+)/u.exec(message)?.[1];
  if (value === undefined) throw new Error("captured message has no magic link");
  return value;
}
function magicProof(link: string): string {
  const proof = new URLSearchParams(new URL(link).hash.slice(1)).get("proof");
  if (proof === null || proof === "") throw new Error("magic link omitted fragment proof");
  return proof;
}
async function get<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(`${controlBase}v1/${path}`, {
    headers: { authorization: `Bearer ${operatorKey}` },
  });
  expect(response.ok(), `GET ${path}: ${await response.text()}`).toBe(true);
  return (await response.json()) as T;
}
async function control<T = unknown>(
  request: APIRequestContext,
  method: "POST" | "PUT",
  path: string,
  data: unknown,
  idempotencyKey?: string,
): Promise<T> {
  const response = await controlRaw(request, method, path, data, idempotencyKey);
  if (!response.ok()) {
    const [problem, runtime, control] = await Promise.all([
      response.text(),
      readFile(runtimeLog, "utf8"),
      readFile(controlLog, "utf8"),
    ]);
    throw new Error(
      `${method} ${path}: ${problem}\nRuntime log tail:\n${tail(runtime)}\nControl log tail:\n${tail(control)}`,
    );
  }
  return (await response.json()) as T;
}
function controlRaw(
  request: APIRequestContext,
  method: "POST" | "PUT",
  path: string,
  data: unknown,
  idempotencyKey?: string,
) {
  return request.fetch(`${controlBase}v1/${path}`, {
    method,
    data,
    headers: {
      authorization: `Bearer ${operatorKey}`,
      ...(idempotencyKey === undefined ? {} : { "idempotency-key": idempotencyKey }),
    },
  });
}
function only<T>(values: T[]): T {
  expect(values).toHaveLength(1);
  const value = values[0];
  if (value === undefined) throw new Error("expected one item");
  return value;
}
function tail(value: string): string {
  return value.split("\n").slice(-80).join("\n");
}
function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}
async function delay(milliseconds: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}
