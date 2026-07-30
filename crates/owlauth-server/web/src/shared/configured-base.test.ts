import { assertSameOriginPlaneUrl, readConfiguredBase } from "./configured-base";

describe("configured plane bases", () => {
  it("reads only canonical server-authored path metadata", () => {
    document.head.innerHTML = '<meta name="owlauth-runtime-base" content="/auth/runtime/">';
    expect(readConfiguredBase("runtime")).toBe("/auth/runtime/");
  });

  it.each(["https://other.example/", "//other.example/", "/runtime/../control/", "/runtime"])(
    "rejects an unsafe configured value: %s",
    (value) => {
      document.head.innerHTML = `<meta name="owlauth-runtime-base" content="${value}">`;
      expect(() => readConfiguredBase("runtime")).toThrow(/invalid configured runtime base/u);
    },
  );

  it("confines request URLs to the configured same-origin plane", () => {
    expect(assertSameOriginPlaneUrl("/runtime/v1/status", "/runtime/").pathname).toBe(
      "/runtime/v1/status",
    );
    expect(() => assertSameOriginPlaneUrl("/control/v1/system", "/runtime/")).toThrow(
      /outside the configured plane base/u,
    );
    expect(() =>
      assertSameOriginPlaneUrl("https://example.invalid/runtime/v1", "/runtime/"),
    ).toThrow(/outside the configured plane base/u);
  });
});
