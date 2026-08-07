import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { CopyButton, CopyValue } from "./CopyValue";

function stubClipboard(writeText: (value: string) => Promise<void>) {
  const navigatorWithClipboard = Object.create(navigator) as Navigator;
  Object.defineProperty(navigatorWithClipboard, "clipboard", {
    configurable: true,
    value: { writeText },
  });
  vi.stubGlobal("navigator", navigatorWithClipboard);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

test("announces a successful copy without requiring an external callback", async () => {
  const writeText = vi.fn(() => Promise.resolve());
  stubClipboard(writeText);
  render(<CopyValue value="prj_public123" label="Project public ID" />);

  fireEvent.click(screen.getByRole("button", { name: "Copy Project public ID" }));

  await waitFor(() => {
    expect(writeText).toHaveBeenCalledWith("prj_public123");
  });
  expect(screen.getByRole("status")).toHaveTextContent("Project public ID copied.");
});

test("delegates the success announcement when an external callback is provided", async () => {
  const writeText = vi.fn(() => Promise.resolve());
  const onCopied = vi.fn();
  stubClipboard(writeText);
  render(<CopyValue value="prj_public123" label="Project public ID" onCopied={onCopied} />);

  fireEvent.click(screen.getByRole("button", { name: "Copy Project public ID" }));

  await waitFor(() => {
    expect(onCopied).toHaveBeenCalledWith("Project public ID copied.");
  });
  expect(screen.getByRole("status")).toBeEmptyDOMElement();
});

test("renders a labeled copy action without exposing the value", async () => {
  const writeText = vi.fn(() => Promise.resolve());
  stubClipboard(writeText);
  render(
    <CopyButton value="internal-project-id" label="Project ID">
      Copy ID
    </CopyButton>,
  );

  fireEvent.click(screen.getByRole("button", { name: "Copy Project ID" }));

  await waitFor(() => {
    expect(writeText).toHaveBeenCalledWith("internal-project-id");
  });
  expect(screen.queryByText("internal-project-id")).toBeNull();
  expect(screen.getByRole("status")).toHaveTextContent("Project ID copied.");
});

test("announces manual recovery when a visible value cannot be copied", async () => {
  stubClipboard(() => Promise.reject(new Error("clipboard unavailable")));
  render(<CopyValue value="prj_public123" label="Project public ID" />);

  fireEvent.click(screen.getByRole("button", { name: "Copy Project public ID" }));

  expect(
    await screen.findByRole("button", { name: "Copy Project public ID unavailable" }),
  ).toBeVisible();
  expect(screen.getByRole("status")).toHaveTextContent(
    "Copy unavailable. Select the value and copy it manually.",
  );
});

test("does not suggest selecting a hidden value when a labeled copy fails", async () => {
  stubClipboard(() => Promise.reject(new Error("clipboard unavailable")));
  render(
    <CopyButton value="internal-project-id" label="Project ID">
      Copy ID
    </CopyButton>,
  );

  fireEvent.click(screen.getByRole("button", { name: "Copy Project ID" }));

  const button = await screen.findByRole("button", { name: "Copy Project ID unavailable" });
  expect(button).toHaveAttribute("title", "Copy unavailable.");
  expect(screen.getByRole("status")).toHaveTextContent("Copy unavailable.");
  expect(screen.getByRole("status")).not.toHaveTextContent("Select the value");
});
