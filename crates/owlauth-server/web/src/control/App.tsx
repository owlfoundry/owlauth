import { useEffect, useRef, useState } from "react";
import type { SyntheticEvent } from "react";
import { Route, Routes } from "react-router";

import { readConfiguredBase } from "../shared/configured-base";
import { Shell } from "../shared/Shell";
import styles from "./app.module.css";
import { type DisposableControlClient, verifyControlKey } from "./client";

type ConsoleState = "locked" | "verifying" | "unlocked" | "denied";

function Console() {
  const [state, setState] = useState<ConsoleState>("locked");
  const client = useRef<DisposableControlClient | null>(null);
  const keyInput = useRef<HTMLInputElement | null>(null);

  useEffect(
    () => () => {
      client.current?.dispose();
      client.current = null;
    },
    [],
  );

  function unlock(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const input = keyInput.current;
    if (input === null || input.value === "") return;

    let submittedKey = input.value;
    input.value = "";
    setState("verifying");
    void (async () => {
      try {
        const verified = await verifyControlKey(readConfiguredBase("control"), submittedKey);
        client.current?.dispose();
        client.current = verified;
        setState("unlocked");
      } catch {
        client.current?.dispose();
        client.current = null;
        setState("denied");
        keyInput.current?.focus();
      } finally {
        submittedKey = "";
      }
    })();
  }

  function lock() {
    client.current?.dispose();
    client.current = null;
    setState("locked");
    queueMicrotask(() => keyInput.current?.focus());
  }

  return (
    <Shell eyebrow="OwlAuth Control" title="Management Console">
      {state === "unlocked" ? (
        <section aria-labelledby="console-status">
          <p id="console-status">No management capabilities are enabled on this server.</p>
          <button type="button" onClick={lock}>
            Lock console
          </button>
        </section>
      ) : (
        <form className={styles["form"]} onSubmit={unlock}>
          <p>Enter the deployment operator API key to connect to the Control API.</p>
          <label htmlFor="operator-key">Operator API key</label>
          <input
            ref={keyInput}
            id="operator-key"
            name="operator-key"
            type="password"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            required
            disabled={state === "verifying"}
          />
          {state === "denied" ? <p role="alert">Authentication failed.</p> : null}
          <button type="submit" disabled={state === "verifying"}>
            {state === "verifying" ? "Verifying…" : "Unlock console"}
          </button>
        </form>
      )}
    </Shell>
  );
}

export function ControlApp() {
  return (
    <Routes>
      <Route path="*" element={<Console />} />
    </Routes>
  );
}
