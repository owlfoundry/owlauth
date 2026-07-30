import { render, screen } from "@testing-library/react";

import { RuntimeApp } from "./App";

describe("Runtime shell", () => {
  it("identifies itself without advertising an unimplemented workflow", () => {
    render(<RuntimeApp />);

    expect(screen.getByRole("heading", { name: "Hosted authentication" })).toBeVisible();
    expect(screen.getByText(/No authentication interaction is active/u)).toBeVisible();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
