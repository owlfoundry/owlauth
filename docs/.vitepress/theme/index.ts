import { defineAsyncComponent } from "vue";
import DefaultTheme from "vitepress/theme";
import type { Theme } from "vitepress";

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component(
      "MermaidDiagram",
      defineAsyncComponent(() => import("./MermaidDiagram.vue")),
    );
  },
} satisfies Theme;
