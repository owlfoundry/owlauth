import type { Mermaid } from "mermaid";

let mermaidPromise: Promise<Mermaid> | undefined;

function loadMermaid(): Promise<Mermaid> {
  mermaidPromise ??= import("mermaid").then(({ default: mermaid }) => {
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "neutral",
    });
    return mermaid;
  });
  return mermaidPromise;
}

export async function renderMermaid(id: string, graph: string): Promise<string> {
  const mermaid = await loadMermaid();
  const { svg } = await mermaid.render(id, graph);
  return svg;
}
