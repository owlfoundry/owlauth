import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";

import { ControlApp } from "./App";

describe("Control shell", () => {
  beforeEach(() => {
    document.head.innerHTML = '<meta name="owlauth-control-base" content="/admin/">';
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("verifies, clears, and disposes a page-memory operator key", async () => {
    const fetchImplementation = vi.fn<typeof fetch>(() =>
      Promise.resolve(Response.json({ product: "owlauth-server", project_auth: false })),
    );
    vi.stubGlobal("fetch", fetchImplementation);
    const { unmount } = render(
      <MemoryRouter>
        <ControlApp />
      </MemoryRouter>,
    );

    const input = screen.getByLabelText("Operator API key");
    fireEvent.change(input, { target: { value: "owl_ctrl_v1_test" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));

    expect(await screen.findByText(/No management capabilities are enabled/u)).toBeVisible();
    expect((input as HTMLInputElement).value).toBe("");
    expect(document.body.textContent).not.toContain("owl_ctrl_v1_test");
    expect(fetchImplementation).toHaveBeenCalledOnce();

    fireEvent.click(screen.getByRole("button", { name: "Lock console" }));
    expect(screen.getByRole("button", { name: "Unlock console" })).toBeVisible();
    unmount();
  });

  it("renders only a bounded authentication failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() => Promise.resolve(new Response(null, { status: 401 }))),
    );
    render(
      <MemoryRouter>
        <ControlApp />
      </MemoryRouter>,
    );
    fireEvent.change(screen.getByLabelText("Operator API key"), {
      target: { value: "wrong" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock console" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Authentication failed.");
    expect(document.body.textContent).not.toContain("wrong");
  });
});
