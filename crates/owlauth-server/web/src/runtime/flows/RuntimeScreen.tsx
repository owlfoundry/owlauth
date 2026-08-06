import type { Dispatch, SetStateAction } from "react";

import { HostedCard, MethodButton, MethodDivider, TerminalState } from "../../shared/hosted/Hosted";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert } from "../../shared/primitives/Feedback";
import { Field, Input } from "../../shared/primitives/Field";
import type { HostedProvider, ViewState } from "../App";
import { IdentityMutationFlow } from "./IdentityMutationFlow";
import { IdentityMutationMagicFlow } from "./IdentityMutationMagicFlow";
import styles from "./runtime-flow.module.css";

interface RuntimeScreenProps {
  readonly state: ViewState;
  readonly emailAddress: string;
  readonly setEmailAddress: Dispatch<SetStateAction<string>>;
  readonly otp: string;
  readonly setOtp: Dispatch<SetStateAction<string>>;
  readonly otpError: string | null;
  readonly selectProvider: (provider: HostedProvider) => Promise<void>;
  readonly selectEmail: () => Promise<void>;
  readonly reuseSession: () => Promise<void>;
  readonly sendEmailChallenge: (resend?: boolean) => Promise<void>;
  readonly verifyOtp: () => Promise<void>;
  readonly confirmMagic: () => Promise<void>;
  readonly startManagedReauthorization: () => Promise<void>;
  readonly confirmLogout: () => Promise<void>;
  readonly cancelLogout: () => void;
}

export function RuntimeScreen(props: RuntimeScreenProps) {
  const { state } = props;
  const title = runtimeTitle(state);
  const projectName = runtimeProjectName(state);
  const exactCeremony =
    state.status === "identity-mutation" || state.status === "identity-mutation-magic";

  return (
    <HostedCard
      title={title}
      {...(projectName === undefined ? {} : { projectName })}
      wide={exactCeremony}
    >
      {state.status === "identity-mutation" ? (
        <IdentityMutationFlow handle={state.handle} bootstrap={state.bootstrap} />
      ) : state.status === "identity-mutation-magic" ? (
        <IdentityMutationMagicFlow bootstrap={state.bootstrap} />
      ) : state.status === "ready-interaction" ? (
        <MethodSelection {...props} state={state} />
      ) : state.status === "email-entry" ? (
        <EmailEntry {...props} state={state} />
      ) : state.status === "email-proof" ? (
        <EmailProof {...props} state={state} />
      ) : state.status === "ready-magic" ? (
        <MagicConfirmation {...props} state={state} />
      ) : state.status === "ready-managed-reauthorization" ? (
        <ManagedReauthorization {...props} state={state} />
      ) : state.status === "ready-logout" ? (
        <LogoutConfirmation {...props} state={state} />
      ) : state.status === "submitting" ? (
        <TerminalState title={state.title}>
          <p role="status" aria-busy="true">
            {state.message}
          </p>
        </TerminalState>
      ) : state.status === "error" || state.status === "complete" || state.status === "progress" ? (
        <TerminalState title={state.title}>
          {state.status === "error" ? (
            <InlineAlert tone="danger">{state.message}</InlineAlert>
          ) : (
            <p role="status">{state.message}</p>
          )}
        </TerminalState>
      ) : (
        <TerminalState title="No sign-in is active">
          <p>Return to your Application and start sign-in again.</p>
        </TerminalState>
      )}
    </HostedCard>
  );
}

function MethodSelection({
  state,
  selectProvider,
  selectEmail,
  reuseSession,
}: RuntimeScreenProps & { readonly state: Extract<ViewState, { status: "ready-interaction" }> }) {
  return (
    <section className={styles["flow"]} aria-label="Choose a sign-in method">
      <p className={styles["summary"]}>Choose one way to continue.</p>
      {state.bootstrap.presentation_hint === undefined ||
      state.bootstrap.presentation_hint === null ? null : (
        <InlineAlert tone="info">{state.bootstrap.presentation_hint}</InlineAlert>
      )}
      <div className={styles["methods"]} role="group" aria-label="Sign-in methods">
        {state.bootstrap.email_available ? (
          <MethodButton kind="email" onClick={() => void selectEmail()}>
            Continue with email
          </MethodButton>
        ) : null}
        {state.bootstrap.providers.map((provider) => (
          <MethodButton
            kind={provider.kind}
            key={provider.key}
            onClick={() => void selectProvider(provider)}
          >
            Continue with {provider.display_name}
          </MethodButton>
        ))}
      </div>
      {state.bootstrap.session_reuse_available ? (
        <>
          <MethodDivider />
          <section className={styles["reuse"]} aria-labelledby="reuse-session">
            <h2 id="reuse-session">Use your current Project session</h2>
            <p className={styles["summary"]}>
              This requires a separate confirmation and does not select an identity provider.
            </p>
            <Button type="button" variant="secondary" onClick={() => void reuseSession()}>
              Continue with current session
            </Button>
          </section>
        </>
      ) : null}
    </section>
  );
}

function EmailEntry({
  state,
  emailAddress,
  setEmailAddress,
  sendEmailChallenge,
}: RuntimeScreenProps & { readonly state: Extract<ViewState, { status: "email-entry" }> }) {
  return (
    <section className={styles["flow"]} aria-labelledby="email-entry-title">
      <h2 id="email-entry-title">Enter your email address</h2>
      <p className={styles["summary"]}>
        We respond the same way whether or not an account already exists.
      </p>
      <form
        className={styles["form"]}
        onSubmit={(event) => {
          event.preventDefault();
          void sendEmailChallenge();
        }}
      >
        <Field label="Email address" htmlFor="email-address">
          <Input
            id="email-address"
            name="email"
            type="email"
            autoComplete="email"
            required
            maxLength={254}
            value={emailAddress}
            onChange={(event) => {
              setEmailAddress(event.target.value);
            }}
          />
        </Field>
        <Button type="submit" variant="primary" fullWidth>
          Send sign-in email
        </Button>
      </form>
      <span className="visually-hidden">{state.bootstrap.application_display_name}</span>
    </section>
  );
}

function EmailProof({
  state,
  emailAddress,
  setEmailAddress,
  otp,
  setOtp,
  otpError,
  verifyOtp,
  sendEmailChallenge,
}: RuntimeScreenProps & { readonly state: Extract<ViewState, { status: "email-proof" }> }) {
  const instruction =
    state.proofModes.length === 2
      ? "Use the newest code or open the newest sign-in link."
      : state.proofModes.includes("otp")
        ? "Use the newest code."
        : "Open the newest sign-in link.";
  return (
    <section className={styles["flow"]} aria-labelledby="email-proof-title">
      <h2 id="email-proof-title">Check your email</h2>
      <p role="status">{instruction}</p>
      <p className={styles["expires"]}>
        This challenge expires at {new Date(state.expiresAt).toLocaleTimeString()}.
      </p>
      {otpError === null ? null : (
        <InlineAlert tone="danger">
          <strong>Code invalid or expired.</strong> {otpError}
        </InlineAlert>
      )}
      {state.proofModes.includes("otp") ? (
        <form
          className={styles["form"]}
          onSubmit={(event) => {
            event.preventDefault();
            void verifyOtp();
          }}
        >
          <Field label="One-time code" htmlFor="email-otp">
            <Input
              className={styles["otp"]}
              id="email-otp"
              name="otp"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6,10}"
              minLength={6}
              maxLength={10}
              required
              value={otp}
              onChange={(event) => {
                setOtp(event.target.value.replace(/\D/gu, "").slice(0, 10));
              }}
            />
          </Field>
          <Button type="submit" variant="primary" fullWidth>
            Verify code
          </Button>
        </form>
      ) : null}
      <form
        className={styles["form"]}
        onSubmit={(event) => {
          event.preventDefault();
          void sendEmailChallenge(true);
        }}
      >
        <p className={styles["summary"]}>
          Requesting another message invalidates the older code and link.
        </p>
        <Field label="Email address" htmlFor="resend-email">
          <Input
            id="resend-email"
            name="email"
            type="email"
            autoComplete="email"
            required
            maxLength={254}
            value={emailAddress}
            onChange={(event) => {
              setEmailAddress(event.target.value);
            }}
          />
        </Field>
        <Button type="submit" variant="secondary">
          Send a new message
        </Button>
      </form>
    </section>
  );
}

function MagicConfirmation({
  state,
  confirmMagic,
}: RuntimeScreenProps & { readonly state: Extract<ViewState, { status: "ready-magic" }> }) {
  return state.context === null ? (
    <TerminalState title="This link cannot be used">
      <InlineAlert tone="danger">Return to the browser where sign-in started.</InlineAlert>
    </TerminalState>
  ) : (
    <section className={styles["flow"]} aria-labelledby="magic-confirm-title">
      <h2 id="magic-confirm-title">Continue email sign-in</h2>
      <p>
        The proof was removed from browser history. Continue only if you requested this sign-in.
      </p>
      <Button type="button" variant="primary" fullWidth onClick={() => void confirmMagic()}>
        Continue sign-in
      </Button>
    </section>
  );
}

function ManagedReauthorization({
  state,
  startManagedReauthorization,
}: RuntimeScreenProps & {
  readonly state: Extract<ViewState, { status: "ready-managed-reauthorization" }>;
}) {
  return (
    <section className={styles["flow"]} aria-labelledby="managed-reauthorization">
      <h2 id="managed-reauthorization">Replace a provider credential</h2>
      <p>
        Continue only with {state.bootstrap.provider_display_name}. This replaces one managed
        credential and does not sign you in to an Application.
      </p>
      <MethodButton
        kind={state.bootstrap.provider_kind}
        onClick={() => void startManagedReauthorization()}
      >
        Continue with {state.bootstrap.provider_display_name}
      </MethodButton>
    </section>
  );
}

function LogoutConfirmation({
  confirmLogout,
  cancelLogout,
}: RuntimeScreenProps & { readonly state: Extract<ViewState, { status: "ready-logout" }> }) {
  return (
    <section className={styles["flow"]} aria-labelledby="confirm-sign-out">
      <h2 id="confirm-sign-out">Sign out of this Project?</h2>
      <p>This ends the Project browser session and sessions derived from it.</p>
      <div className={styles["actions"]}>
        <Button type="button" variant="danger" onClick={() => void confirmLogout()}>
          Confirm sign out
        </Button>
        <Button type="button" variant="secondary" onClick={cancelLogout}>
          Cancel
        </Button>
      </div>
    </section>
  );
}

function runtimeTitle(state: ViewState): string {
  if (
    state.status === "ready-interaction" ||
    state.status === "email-entry" ||
    state.status === "email-proof"
  ) {
    return state.bootstrap.application_display_name;
  }
  if (state.status === "ready-magic") return "Confirm email sign-in";
  if (state.status === "identity-mutation" || state.status === "identity-mutation-magic") {
    return "Identity verification";
  }
  if (state.status === "ready-managed-reauthorization") return "Reauthorize managed connection";
  if (state.status === "ready-logout") return "Sign out";
  return "Hosted authentication";
}

function runtimeProjectName(state: ViewState): string | undefined {
  if (
    state.status === "ready-interaction" ||
    state.status === "email-entry" ||
    state.status === "email-proof"
  ) {
    return state.bootstrap.project_display_name;
  }
  if (state.status === "ready-managed-reauthorization") return state.bootstrap.project_public_id;
  return undefined;
}
