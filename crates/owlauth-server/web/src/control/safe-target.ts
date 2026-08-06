export function safeHostedTarget(value: string | null | undefined): string | null {
  if (value === null || value === undefined || value.length === 0 || value.length > 512) {
    return null;
  }
  let target: URL;
  try {
    target = new URL(value);
  } catch {
    return null;
  }
  if (target.username !== "" || target.password !== "" || target.hash !== "") return null;
  if (target.protocol === "https:") return target.href;
  const loopback =
    target.hostname === "localhost" ||
    target.hostname === "127.0.0.1" ||
    target.hostname === "[::1]";
  return target.protocol === "http:" && loopback ? target.href : null;
}
