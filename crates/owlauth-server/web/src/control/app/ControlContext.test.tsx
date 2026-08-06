import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useNavigate } from "react-router";

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
    <MemoryRouter>
      <ControlProvider session={session} initialProjects={[]} lock={lock}>
        <ConflictHarness />
      </ControlProvider>
    </MemoryRouter>,
  );

  fireEvent.click(screen.getByRole("button", { name: "Trigger conflict" }));

  await waitFor(() => {
    expect(lock).toHaveBeenCalledTimes(1);
  });
});

function FeedbackHarness() {
  const { message, toasts, setMessage } = useControl();
  const navigate = useNavigate();
  return (
    <>
      <button
        type="button"
        onClick={() => {
          setMessage("Failed request", "danger");
          setMessage("Saved resource", "success");
        }}
      >
        Fail then succeed
      </button>
      <button
        type="button"
        onClick={() => {
          const completeOldRequest = setMessage;
          void navigate("/next");
          window.setTimeout(() => {
            void navigate(-1);
            window.setTimeout(() => {
              completeOldRequest("Stale completion", "success");
            }, 0);
          }, 0);
        }}
      >
        Complete after navigation
      </button>
      <output aria-label="persistent message">{message ?? "none"}</output>
      <output aria-label="toast messages">{toasts.map((toast) => toast.message).join("|")}</output>
    </>
  );
}

it("clears stale errors on success and ignores feedback completed on an old route", async () => {
  const session = {
    client: { GET: vi.fn() },
    dispose: vi.fn(),
  } as unknown as DisposableControlClient;

  render(
    <MemoryRouter>
      <ControlProvider session={session} initialProjects={[]} lock={vi.fn()}>
        <FeedbackHarness />
      </ControlProvider>
    </MemoryRouter>,
  );

  fireEvent.click(screen.getByRole("button", { name: "Fail then succeed" }));
  expect(screen.getByLabelText("persistent message")).toHaveTextContent("none");
  expect(screen.getByLabelText("toast messages")).toHaveTextContent("Saved resource");

  fireEvent.click(screen.getByRole("button", { name: "Complete after navigation" }));
  await act(async () => {
    await new Promise((resolve) => window.setTimeout(resolve, 10));
  });
  expect(screen.getByLabelText("toast messages")).not.toHaveTextContent("Stale completion");
});
