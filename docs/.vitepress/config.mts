import { defineConfig } from "vitepress";

export default defineConfig({
  title: "OwlAuth",
  description: "Self-hostable OAuth 2.1 authorization server and user management platform",
  cleanUrls: true,
  sitemap: {
    hostname: "https://owlauth.owlfoundry.org",
  },
  head: [["meta", { name: "theme-color", content: "#7c3aed" }]],
  themeConfig: {
    nav: [
      { text: "Guide", link: "/guide/getting-started" },
      { text: "SDKs", link: "/guide/sdks" },
      { text: "Agent integrations", link: "/guide/agent-integrations" },
    ],
    sidebar: [
      {
        text: "Guide",
        items: [
          { text: "Getting started", link: "/guide/getting-started" },
          { text: "Architecture", link: "/guide/architecture" },
          { text: "SDKs", link: "/guide/sdks" },
          { text: "Agent integrations", link: "/guide/agent-integrations" },
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
