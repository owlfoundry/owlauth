import { fireEvent, render, screen } from "@testing-library/react";

import { Dialog } from "./Overlay";

function surface(open: boolean, onClose: () => void) {
  return (
    <>
      <button type="button">Open settings</button>
      <Dialog open={open} title="Settings" onClose={onClose}>
        <label htmlFor="modal-name">Name</label>
        <input id="modal-name" data-owl-initial-focus />
        <button type="button">Last action</button>
      </Dialog>
    </>
  );
}

describe("modal focus lifecycle", () => {
  it("keeps focus across parent rerenders, uses the latest close callback, and restores once", () => {
    const firstClose = vi.fn();
    const latestClose = vi.fn();
    const view = render(surface(false, firstClose));
    const trigger = screen.getByRole("button", { name: "Open settings" });
    trigger.focus();

    view.rerender(surface(true, firstClose));
    const input = screen.getByLabelText("Name");
    expect(input).toHaveFocus();

    view.rerender(surface(true, latestClose));
    expect(input).toHaveFocus();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(firstClose).not.toHaveBeenCalled();
    expect(latestClose).toHaveBeenCalledTimes(1);

    view.rerender(surface(false, latestClose));
    expect(trigger).toHaveFocus();
  });

  it("keeps an acknowledgement dialog open without an escape or close affordance", () => {
    const onClose = vi.fn();
    render(
      <Dialog open title="One-time credential" dismissible={false} onClose={onClose}>
        <button type="button">Acknowledge</button>
      </Dialog>,
    );

    expect(screen.queryByRole("button", { name: "Close dialog" })).toBeNull();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog", { name: "One-time credential" })).toBeVisible();
  });

  it("contains forward and reverse tab focus within the active dialog", () => {
    const view = render(surface(false, vi.fn()));
    const background = screen.getByRole("button", { name: "Open settings" });
    background.focus();
    view.rerender(surface(true, vi.fn()));

    const first = screen.getByRole("button", { name: "Close dialog" });
    const last = screen.getByRole("button", { name: "Last action" });
    last.focus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(first).toHaveFocus();

    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(last).toHaveFocus();

    background.focus();
    expect(first).toHaveFocus();
  });

  it("lets only the topmost stacked dialog handle Escape", () => {
    const closeEditor = vi.fn();
    const keepEditing = vi.fn();
    render(
      <>
        <Dialog open title="Edit Application" onClose={closeEditor}>
          <input aria-label="Application name" defaultValue="Unsaved name" />
        </Dialog>
        <Dialog open title="Discard unsaved changes?" onClose={keepEditing}>
          <button type="button">Keep editing</button>
        </Dialog>
      </>,
    );

    fireEvent.keyDown(document, { key: "Escape" });
    expect(keepEditing).toHaveBeenCalledTimes(1);
    expect(closeEditor).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Application name")).toHaveValue("Unsaved name");
  });
});
