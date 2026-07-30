import { ControlAuthenticationError, verifyControlKey } from "./client";

describe("verified Control client", () => {
  it("confines the Bearer credential to the configured base and disposes it on lock", async () => {
    const observed = vi.fn<typeof fetch>((request) => {
      const headers = request instanceof Request ? request.headers : new Headers();
      expect(headers.get("authorization")).toBe("Bearer owl_ctrl_v1_test");
      return Promise.resolve(Response.json({ product: "owlauth-server", project_auth: false }));
    });
    const disposable = await verifyControlKey("/admin/", "owl_ctrl_v1_test", observed);

    expect(observed).toHaveBeenCalledOnce();
    const request = observed.mock.calls[0]?.[0];
    expect(request).toBeInstanceOf(Request);
    expect((request as Request).url).toBe("http://localhost:3000/admin/v1/system");

    disposable.dispose();
    await expect(disposable.client.GET("/v1/system")).rejects.toThrow("Control client is locked");
    expect(observed).toHaveBeenCalledOnce();
  });

  it("disposes denied credentials and returns only a bounded error", async () => {
    const denied = vi.fn<typeof fetch>(() => Promise.resolve(new Response(null, { status: 401 })));
    await expect(verifyControlKey("/admin/", "wrong", denied)).rejects.toBeInstanceOf(
      ControlAuthenticationError,
    );
    expect(denied).toHaveBeenCalledOnce();
  });
});
