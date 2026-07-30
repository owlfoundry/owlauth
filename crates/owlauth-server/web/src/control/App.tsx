import { useCallback, useEffect, useRef, useState } from "react";
import type { SyntheticEvent } from "react";
import { Route, Routes } from "react-router";

import { readConfiguredBase } from "../shared/configured-base";
import { Shell } from "../shared/Shell";
import styles from "./app.module.css";
import {
  ControlRequestError,
  type DisposableControlClient,
  IdempotencyAttempt,
  type Project,
  requireData,
  verifyControlKey,
} from "./client";
import { ProjectWorkspace } from "./ProjectWorkspace";

type ConsoleState = "locked" | "verifying" | "unlocked" | "denied";

function Console() {
  const [state, setState] = useState<ConsoleState>("locked");
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [activeClient, setActiveClient] = useState<DisposableControlClient | null>(null);
  const client = useRef<DisposableControlClient | null>(null);
  const keyInput = useRef<HTMLInputElement | null>(null);
  const generation = useRef(0);
  const verification = useRef<AbortController | null>(null);
  const createProjectAttempt = useRef(new IdempotencyAttempt());

  const lock = useCallback(() => {
    generation.current += 1;
    verification.current?.abort();
    verification.current = null;
    client.current?.dispose();
    client.current = null;
    createProjectAttempt.current.abandon();
    setActiveClient(null);
    setProjects([]);
    setSelectedId(null);
    setMessage(null);
    setState("locked");
    queueMicrotask(() => keyInput.current?.focus());
  }, []);

  useEffect(() => {
    const dispose = () => {
      generation.current += 1;
      verification.current?.abort();
      verification.current = null;
      client.current?.dispose();
      client.current = null;
    };
    window.addEventListener("pagehide", dispose);
    return () => {
      window.removeEventListener("pagehide", dispose);
      dispose();
    };
  }, []);

  const refreshProjects = useCallback(async () => {
    const session = client.current;
    if (session === null) return;
    const result = await session.client.GET("/v1/projects");
    const list = requireData(result.data, result.error, result.response).items;
    setProjects(list);
    setSelectedId((current) =>
      current !== null && list.some((project) => project.id === current)
        ? current
        : (list[0]?.id ?? null),
    );
  }, []);

  const handleError = useCallback(
    async (error: unknown) => {
      if (error instanceof ControlRequestError && error.status === 401) {
        lock();
        return;
      }
      if (error instanceof ControlRequestError && error.status === 409) {
        try {
          await refreshProjects();
          setMessage("The resource changed. Current revisions were refreshed; review and retry.");
        } catch (refreshError) {
          setMessage(
            refreshError instanceof ControlRequestError
              ? refreshError.message
              : "The current state could not be refreshed.",
          );
        }
        return;
      }
      setMessage(error instanceof ControlRequestError ? error.message : "The request failed.");
    },
    [lock, refreshProjects],
  );

  function unlock(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const input = keyInput.current;
    if (input === null || input.value === "") return;

    let submittedKey = input.value;
    input.value = "";
    const attempt = generation.current + 1;
    generation.current = attempt;
    verification.current?.abort();
    const controller = new AbortController();
    verification.current = controller;
    setState("verifying");
    setMessage(null);
    void (async () => {
      try {
        const verified = await verifyControlKey(
          readConfiguredBase("control"),
          submittedKey,
          fetch,
          controller.signal,
        );
        if (generation.current !== attempt || controller.signal.aborted) {
          verified.dispose();
          return;
        }
        client.current?.dispose();
        client.current = verified;
        setActiveClient(verified);
        verification.current = null;
        setState("unlocked");
        await refreshProjects();
      } catch {
        if (generation.current !== attempt || controller.signal.aborted) return;
        client.current?.dispose();
        client.current = null;
        verification.current = null;
        setState("denied");
        keyInput.current?.focus();
      } finally {
        submittedKey = "";
      }
    })();
  }

  async function createProject(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const session = client.current;
    if (session === null) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    const idempotencyKey = createProjectAttempt.current.begin();
    if (idempotencyKey === null) return;
    setMessage(null);
    try {
      const result = await session.client.POST("/v1/projects", {
        params: { header: { "Idempotency-Key": idempotencyKey } },
        body: {
          display_name: fieldText(fields, "display_name"),
          belongs_to: optionalText(fields, "belongs_to"),
        },
      });
      const created = requireData(result.data, result.error, result.response);
      createProjectAttempt.current.settle();
      form.reset();
      await refreshProjects();
      setSelectedId(created.id);
      setMessage("Project created.");
    } catch (error) {
      createProjectAttempt.current.settle(error);
      void handleError(error);
    }
  }

  const selected = projects.find((project) => project.id === selectedId) ?? null;

  return (
    <Shell eyebrow="OwlAuth Control" title="Management Console">
      {state === "unlocked" && activeClient !== null ? (
        <div className={styles["workspace"]}>
          <header className={styles["toolbar"]}>
            <p>Authenticated as the deployment operator.</p>
            <button type="button" onClick={lock}>
              Lock console
            </button>
          </header>
          {message === null ? null : <p role="status">{message}</p>}
          <section aria-labelledby="projects-heading">
            <h2 id="projects-heading">Projects</h2>
            <form className={styles["form"]} onSubmit={(event) => void createProject(event)}>
              <label htmlFor="project-name">Display name</label>
              <input id="project-name" name="display_name" required maxLength={128} />
              <label htmlFor="project-owner">External owner metadata (optional)</label>
              <input id="project-owner" name="belongs_to" maxLength={256} />
              <button type="submit">Create Project</button>
            </form>
            {projects.length === 0 ? (
              <p>No Projects yet.</p>
            ) : (
              <ul className={styles["list"]}>
                {projects.map((project) => (
                  <li key={project.id}>
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedId(project.id);
                      }}
                      aria-pressed={project.id === selectedId}
                    >
                      {project.display_name} <span>{project.status}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
          {selected === null ? null : (
            <ProjectWorkspace
              key={selected.id}
              session={activeClient}
              project={selected}
              onError={handleError}
              onProjectChanged={async (project) => {
                await refreshProjects();
                setSelectedId(project.id);
              }}
              setMessage={setMessage}
            />
          )}
        </div>
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

function fieldText(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}

function optionalText(fields: FormData, name: string): string | null {
  const text = fieldText(fields, name).trim();
  return text === "" ? null : text;
}

export function ControlApp() {
  return (
    <Routes>
      <Route path="*" element={<Console />} />
    </Routes>
  );
}
