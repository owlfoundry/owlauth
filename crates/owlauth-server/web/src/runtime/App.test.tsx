import { render, screen } from "@testing-library/react";

import { RuntimeApp } from "./App";

describe("Runtime shell", () => {
  beforeEach(() => {
    document.head.innerHTML = '<meta name="owlauth-runtime-base" content="/runtime/">';
    window.history.replaceState({}, "", "/runtime/auth/");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("identifies itself without advertising an unimplemented workflow", () => {
    render(<RuntimeApp />);
    expect(screen.getByRole("heading", { name: "Hosted authentication" })).toBeVisible();
    expect(screen.getByText(/No authentication interaction is active/u)).toBeVisible();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("renders bounded public branding while keeping login unavailable", async () => {
    window.history.replaceState(
      {},
      "",
      "/runtime/auth/?project_id=prj_public&application_id=app_public",
    );
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const request = input as Request;
        expect(request.url).toContain("/runtime/v1/projects/prj_public/auth/config");
        expect(request.headers.has("authorization")).toBe(false);
        return Promise.resolve(
          Response.json({
            project_public_id: "prj_public",
            project_display_name: "Production",
            application_public_id: "app_public",
            application_display_name: "Customer portal",
            publishable_keys: ["owl_app_public"],
            providers: [{ key: "workforce", display_name: "Workforce SSO", kind: "oidc" }],
            login_available: false,
          }),
        );
      }),
    );
    render(<RuntimeApp />);
    expect(await screen.findByRole("heading", { name: "Customer portal" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "Production" })).toBeVisible();
    expect(screen.getByText(/Login is not available/u)).toBeVisible();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
