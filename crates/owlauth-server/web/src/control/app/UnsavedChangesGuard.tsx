import { useEffect } from "react";
import { useBlocker } from "react-router";

import { Button } from "../../shared/primitives/Button";
import { Dialog } from "../../shared/primitives/Overlay";

interface UnsavedChangesGuardProps {
  readonly dirty: boolean;
  readonly submitting: boolean;
  readonly onDiscard: () => void;
}

export function UnsavedChangesGuard({ dirty, submitting, onDiscard }: UnsavedChangesGuardProps) {
  const blocker = useBlocker(
    ({ currentLocation, nextLocation }) =>
      (dirty || submitting) &&
      `${currentLocation.pathname}${currentLocation.search}${currentLocation.hash}` !==
        `${nextLocation.pathname}${nextLocation.search}${nextLocation.hash}`,
  );

  useEffect(() => {
    if (blocker.state === "blocked" && !dirty && !submitting) blocker.reset();
  }, [blocker, dirty, submitting]);

  useEffect(() => {
    if (!dirty && !submitting) return;
    const preventUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
    };
    window.addEventListener("beforeunload", preventUnload);
    return () => {
      window.removeEventListener("beforeunload", preventUnload);
    };
  }, [dirty, submitting]);

  const blocked = blocker.state === "blocked";
  return (
    <Dialog
      open={blocked}
      title="Discard unsaved changes?"
      onClose={() => {
        if (blocker.state === "blocked") blocker.reset();
      }}
      actions={
        <>
          <Button
            type="button"
            variant="secondary"
            onClick={() => {
              if (blocker.state === "blocked") blocker.reset();
            }}
          >
            Keep editing
          </Button>
          <Button
            type="button"
            variant="danger"
            disabled={submitting}
            onClick={() => {
              if (blocker.state !== "blocked" || submitting) return;
              onDiscard();
              blocker.proceed();
            }}
          >
            {submitting ? "Request in progress" : "Discard and leave"}
          </Button>
        </>
      }
    >
      <p>
        {submitting
          ? "A request is still in progress. Stay on this page until its outcome is known."
          : "Your changes have not been saved. Leaving this page will discard them."}
      </p>
    </Dialog>
  );
}
