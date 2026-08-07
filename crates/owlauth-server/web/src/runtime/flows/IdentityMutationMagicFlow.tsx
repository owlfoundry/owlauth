import { useEffect, useRef, useState } from "react";

import { readConfiguredBase } from "../../shared/configured-base";
import { Button } from "../../shared/primitives/Button";
import styles from "./identity.module.css";
import { createRuntimeClient } from "../client";

interface IdentityMutationMagicContext {
  proof: string;
  project: string;
  interaction: string;
  slot: string;
  csrf: string;
  generation: number;
  revision: number;
}

export interface IdentityMutationMagicBootstrap {
  challengeId: string | null;
  context: IdentityMutationMagicContext | null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const HANDLE = /^[A-Za-z0-9._-]{1,256}$/u;
const PROOF = /^[A-Za-z0-9_-]{22,128}$/u;
const CSRF = /^[A-Za-z0-9_-]{1,64}$/u;

function takeMeta(name: string): string | null {
  const element = document.head.querySelector<HTMLMetaElement>(`meta[name="${name}"]`);
  const value = element?.content ?? null;
  element?.remove();
  return value;
}

function positiveInteger(value: string | null, maximum = Number.MAX_SAFE_INTEGER): number | null {
  if (value === null || !/^[1-9][0-9]*$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed <= maximum ? parsed : null;
}

function challengeFromPath(): string | null {
  const marker = "/auth/identity-mutations/email/confirm/";
  const index = window.location.pathname.lastIndexOf(marker);
  if (index < 0) return null;
  const encoded = window.location.pathname.slice(index + marker.length);
  if (encoded.length === 0 || encoded.includes("/")) return null;
  try {
    const value = decodeURIComponent(encoded);
    return UUID.test(value) ? value : null;
  } catch {
    return null;
  }
}

/**
 * Stages fragment authority synchronously and scrubs it before React can render or any request can
 * begin. Values are retained only in this returned in-memory object.
 */
export function consumeIdentityMutationMagicBootstrap(): IdentityMutationMagicBootstrap {
  const challengeId = challengeFromPath();
  const csrf = takeMeta("owlauth-identity-magic-csrf");
  const metaProject = takeMeta("owlauth-identity-magic-project");
  const metaSlot = takeMeta("owlauth-identity-magic-slot");
  const metaGeneration = takeMeta("owlauth-identity-magic-generation");
  const metaRevision = takeMeta("owlauth-identity-magic-revision");
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const proof = fragment.get("proof");
  const project = fragment.get("project");
  const interaction = fragment.get("interaction");
  const slot = fragment.get("slot");
  const generationText = fragment.get("generation");
  const revisionText = fragment.get("revision");

  // This must remain before validation and before returning control to React. It also scrubs
  // malformed fragments so they cannot linger in history.
  window.history.replaceState(
    window.history.state,
    "",
    window.location.pathname + window.location.search,
  );

  const generation = positiveInteger(generationText, 32_767);
  const revision = positiveInteger(revisionText);
  const metaGenerationNumber = positiveInteger(metaGeneration, 32_767);
  const metaRevisionNumber = positiveInteger(metaRevision);
  const valid =
    challengeId !== null &&
    proof !== null &&
    PROOF.test(proof) &&
    project !== null &&
    HANDLE.test(project) &&
    interaction !== null &&
    HANDLE.test(interaction) &&
    slot !== null &&
    UUID.test(slot) &&
    csrf !== null &&
    CSRF.test(csrf) &&
    metaProject === project &&
    metaSlot === slot &&
    generation !== null &&
    generation === metaGenerationNumber &&
    revision !== null &&
    revision === metaRevisionNumber;

  return {
    challengeId,
    context: valid ? { proof, project, interaction, slot, csrf, generation, revision } : null,
  };
}

export function IdentityMutationMagicFlow({
  bootstrap,
}: {
  readonly bootstrap: IdentityMutationMagicBootstrap;
}) {
  const [state, setState] = useState<"ready" | "submitting" | "complete" | "error">(
    bootstrap.challengeId !== null && bootstrap.context !== null ? "ready" : "error",
  );
  const abort = useRef<AbortController | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(
    () => () => {
      abort.current?.abort();
      abort.current = null;
    },
    [],
  );
  useEffect(() => {
    heading.current?.focus();
  }, [state]);

  async function transferProof() {
    if (state !== "ready" || bootstrap.challengeId === null || bootstrap.context === null) return;
    const context = bootstrap.context;
    const controller = new AbortController();
    abort.current?.abort();
    abort.current = controller;
    setState("submitting");
    try {
      const { data, response } = await createRuntimeClient(readConfiguredBase("runtime")).POST(
        "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/email/link/verify",
        {
          params: {
            path: {
              project_public_id: context.project,
              intent: context.interaction,
              proof_slot: context.slot,
            },
          },
          body: {
            expected_revision: context.revision,
            csrf: context.csrf,
            challenge_id: bootstrap.challengeId,
            generation: context.generation,
            token: context.proof,
          },
          signal: controller.signal,
        },
      );
      if (controller.signal.aborted) return;
      setState(
        response.ok &&
          data?.state === "proved" &&
          Number.isSafeInteger(data.revision) &&
          data.revision > 0
          ? "complete"
          : "error",
      );
    } catch {
      if (!controller.signal.aborted) setState("error");
    } finally {
      if (abort.current === controller) abort.current = null;
    }
  }

  return (
    <section
      aria-labelledby="identity-magic-heading"
      aria-live="polite"
      aria-busy={state === "submitting"}
    >
      <h2 id="identity-magic-heading" ref={heading} tabIndex={-1} className={styles["focusTarget"]}>
        {state === "complete"
          ? "Identity proof received"
          : state === "error"
            ? "Verification link unavailable"
            : "Continue identity verification"}
      </h2>
      {state === "ready" ? (
        <>
          <p role="status">
            The proof fragment has been removed from browser history. Continue only if you requested
            this identity verification.
          </p>
          <Button variant="primary" type="button" onClick={() => void transferProof()}>
            Transfer proof to the identity request
          </Button>
        </>
      ) : state === "submitting" ? (
        <p role="status">Transferring the one-use proof…</p>
      ) : state === "complete" ? (
        <p role="status">
          The proof was attached to its exact slot. Return to the original verification window;
          identity ownership has not changed.
        </p>
      ) : (
        <p role="alert" className={styles["error"]}>
          Use only the newest link, or return to the original verification window and request
          another message.
        </p>
      )}
    </section>
  );
}
