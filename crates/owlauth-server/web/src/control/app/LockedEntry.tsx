import { useEffect, useRef } from "react";
import type { SyntheticEvent } from "react";

import { OwlAuthMark } from "../../shared/brand/OwlAuthMark";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert } from "../../shared/primitives/Feedback";
import { Field, Input } from "../../shared/primitives/Field";
import styles from "./control-shell.module.css";

interface LockedEntryProps {
  readonly verifying: boolean;
  readonly denied: boolean;
  readonly onUnlock: (key: string) => void;
}

export function LockedEntry({ verifying, denied, onUnlock }: LockedEntryProps) {
  const keyInput = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    keyInput.current?.focus();
  }, [denied]);

  function submit(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const input = keyInput.current;
    if (input === null || input.value === "") return;
    const key = input.value;
    input.value = "";
    onUnlock(key);
  }

  return (
    <main className={styles["lockedCanvas"]}>
      <section className={styles["lockedPanel"]} aria-labelledby="connect-title">
        <OwlAuthWordmark />
        <h1 id="connect-title">Connect to this deployment</h1>
        <p>
          Enter the deployment operator API key. It remains only in this page's active memory and is
          discarded when you exit or leave the console.
        </p>
        <form className={styles["lockedForm"]} onSubmit={submit}>
          {denied ? (
            <InlineAlert tone="danger">The API key could not be verified.</InlineAlert>
          ) : null}
          <Field label="Operator API key" htmlFor="operator-key">
            <Input
              ref={keyInput}
              id="operator-key"
              name="operator-key"
              type="password"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              required
              disabled={verifying}
            />
          </Field>
          <Button type="submit" variant="primary" fullWidth busy={verifying}>
            {verifying ? "Verifying key" : "Unlock console"}
          </Button>
        </form>
      </section>
    </main>
  );
}

export function VerifiedBootstrapFailure({
  retrying,
  onRetry,
  onLock,
}: {
  readonly retrying: boolean;
  readonly onRetry: () => void;
  readonly onLock: () => void;
}) {
  return (
    <main className={styles["lockedCanvas"]}>
      <section className={styles["lockedPanel"]} aria-labelledby="projects-unavailable-title">
        <OwlAuthWordmark />
        <h1 id="projects-unavailable-title">Projects are unavailable</h1>
        <InlineAlert tone="danger">
          The operator key was verified, but the Project directory could not be loaded. Retry the
          safe read or exit the console.
        </InlineAlert>
        <div className={styles["lockedForm"]}>
          <Button type="button" variant="primary" fullWidth busy={retrying} onClick={onRetry}>
            {retrying ? "Retrying Project directory" : "Retry Project directory"}
          </Button>
          <Button type="button" variant="quiet" fullWidth disabled={retrying} onClick={onLock}>
            Exit console
          </Button>
        </div>
      </section>
    </main>
  );
}

export function OwlAuthWordmark() {
  return (
    <div className={styles["wordmark"]} aria-label="OwlAuth">
      <OwlAuthMark className={styles["mark"]} />
      <span>OwlAuth</span>
    </div>
  );
}
