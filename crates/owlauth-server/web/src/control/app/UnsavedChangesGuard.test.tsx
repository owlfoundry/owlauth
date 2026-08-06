import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { createMemoryRouter, Link, RouterProvider } from "react-router";

import { UnsavedChangesGuard } from "./UnsavedChangesGuard";

function DirtyEditor() {
  const [dirty, setDirty] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  return (
    <>
      <UnsavedChangesGuard
        dirty={dirty}
        submitting={submitting}
        onDiscard={() => {
          setDirty(false);
        }}
      />
      <h1>Editor</h1>
      <output aria-label="draft state">{dirty ? "dirty" : "discarded"}</output>
      <button
        type="button"
        onClick={() => {
          setSubmitting(true);
        }}
      >
        Submit request
      </button>
      <Link to="/next">Next page</Link>
    </>
  );
}

function renderHistory() {
  const router = createMemoryRouter(
    [
      { path: "/previous", element: <h1>Previous page</h1> },
      { path: "/edit", element: <DirtyEditor /> },
      { path: "/next", element: <h1>Next page</h1> },
    ],
    { initialEntries: ["/previous", "/edit"], initialIndex: 1 },
  );
  render(<RouterProvider router={router} />);
  return router;
}

test("blocks SPA links until the draft is explicitly discarded", async () => {
  renderHistory();

  fireEvent.click(screen.getByRole("link", { name: "Next page" }));
  const dialog = await screen.findByRole("dialog", { name: "Discard unsaved changes?" });
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(screen.getByRole("heading", { name: "Editor" })).toBeVisible();

  fireEvent.click(screen.getByRole("link", { name: "Next page" }));
  fireEvent.click(await screen.findByRole("button", { name: "Discard and leave" }));
  await screen.findByRole("heading", { name: "Next page" });
  expect(dialog).not.toBeInTheDocument();
});

test("does not discard recovery state while a mutation is in flight", async () => {
  renderHistory();

  fireEvent.click(screen.getByRole("button", { name: "Submit request" }));
  fireEvent.click(screen.getByRole("link", { name: "Next page" }));
  const pending = await screen.findByRole("button", { name: "Request in progress" });
  expect(pending).toBeDisabled();
  expect(screen.getByRole("heading", { name: "Editor" })).toBeVisible();
});

test("blocks history navigation without unmounting the draft", async () => {
  const router = renderHistory();

  await act(async () => {
    await router.navigate(-1);
  });
  await screen.findByRole("dialog", { name: "Discard unsaved changes?" });
  expect(screen.getByLabelText("draft state")).toHaveTextContent("dirty");
  expect(screen.getByRole("heading", { name: "Editor" })).toBeVisible();

  fireEvent.click(screen.getByRole("button", { name: "Discard and leave" }));
  await waitFor(() => {
    expect(screen.getByRole("heading", { name: "Previous page" })).toBeVisible();
  });
});
