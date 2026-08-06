import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { ControlRequestError, type DisposableControlClient } from "../client";
import { ControlProvider, useControl } from "./ControlContext";

function ConflictHarness() {
  const { handleError } = useControl();
  return (
    <button
      type="button"
      onClick={() => {
        void handleError(
          new ControlRequestError(
            {
              code: "revision_conflict",
              detail: "Refresh the resource and retry with its current revision.",
              request_id: "request-1",
              status: 409,
              title: "Revision conflict",
              type: "about:blank",
            },
            409,
          ),
          () => Promise.reject(new ControlRequestError(undefined, 401)),
        );
      }}
    >
      Trigger conflict
    </button>
  );
}

it("locks when a conflict refresh receives an authentication failure", async () => {
  const lock = vi.fn();
  const session = {
    client: { GET: vi.fn() },
    dispose: vi.fn(),
  } as unknown as DisposableControlClient;

  render(
    <ControlProvider session={session} initialProjects={[]} lock={lock}>
      <ConflictHarness />
    </ControlProvider>,
  );

  fireEvent.click(screen.getByRole("button", { name: "Trigger conflict" }));

  await waitFor(() => {
    expect(lock).toHaveBeenCalledTimes(1);
  });
});
