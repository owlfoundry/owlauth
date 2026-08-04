import { defineConfig } from "vitepress";

export default defineConfig({
  title: "OwlAuth",
  description:
    "Self-hostable, project-scoped authentication and identity infrastructure",
  cleanUrls: true,
  sitemap: {
    hostname: "https://owlauth-docs.owlfoundry.org",
  },
  head: [
    ["link", { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" }],
    ["meta", { name: "theme-color", content: "#7c3aed" }],
  ],
  markdown: {
    config(markdown) {
      const defaultFence = markdown.renderer.rules.fence;
      markdown.renderer.rules.fence = (
        tokens,
        index,
        options,
        environment,
        renderer,
      ) => {
        const token = tokens[index];
        if (token.info.trim().split(/\s+/, 1)[0] === "mermaid") {
          const encoded = encodeURIComponent(token.content);
          return `<MermaidDiagram encoded="${encoded}"></MermaidDiagram>`;
        }
        return (
          defaultFence?.(tokens, index, options, environment, renderer) ?? ""
        );
      };
    },
  },
  themeConfig: {
    logo: "/favicon.svg",
    nav: [
      { text: "Guide", link: "/guide/getting-started" },
      { text: "Architecture", link: "/guide/architecture" },
      { text: "SDKs", link: "/guide/sdks" },
      { text: "CLI & agents", link: "/guide/agent-integrations" },
    ],
    sidebar: [
      {
        text: "OwlAuth guide",
        items: [
          { text: "Getting started", link: "/guide/getting-started" },
          { text: "Architecture", link: "/guide/architecture" },
          { text: "SDKs", link: "/guide/sdks" },
          { text: "Building a SaaS", link: "/guide/building-saas" },
          {
            text: "CLI & agent integrations",
            link: "/guide/agent-integrations",
          },
          { text: "Security", link: "/guide/security" },
        ],
      },
    ],
    socialLinks: [
      { icon: "github", link: "https://github.com/owlfoundry/owlauth" },
    ],
    search: {
      provider: "local",
    },
    footer: {
      message: "Released under the BSD 3-Clause License.",
      copyright: "Copyright © 2026 OwlFoundry",
    },
  },
});
