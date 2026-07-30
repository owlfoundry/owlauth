export type Plane = "runtime" | "control";

const CANONICAL_BASE = /^\/(?:[A-Za-z0-9._~-]+\/)*$/u;

/** Reads a server-authored, non-secret base path without deriving it from browser routing. */
export function readConfiguredBase(plane: Plane, documentRoot: Document = document): string {
  const element = documentRoot.querySelector<HTMLMetaElement>(`meta[name="owlauth-${plane}-base"]`);
  const value = element?.content;

  const segments = value?.split("/").slice(1, -1) ?? [];
  if (
    value === undefined ||
    !CANONICAL_BASE.test(value) ||
    value.includes("/" + "/") ||
    segments.some((segment) => segment === "." || segment === "..")
  ) {
    throw new Error(`Missing or invalid configured ${plane} base path`);
  }

  return value;
}

export function assertSameOriginPlaneUrl(value: string, basePath: string): URL {
  const url = new URL(value, window.location.origin);
  if (
    url.origin !== window.location.origin ||
    url.username !== "" ||
    url.password !== "" ||
    !url.pathname.startsWith(basePath)
  ) {
    throw new TypeError("Request URL is outside the configured plane base");
  }
  return url;
}
