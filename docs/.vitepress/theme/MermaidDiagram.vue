<script setup lang="ts">
import { nextTick, onMounted, ref } from "vue";

import { renderMermaid } from "./mermaid";

const props = defineProps<{ encoded: string }>();
const container = ref<HTMLElement>();
const status = ref<"loading" | "ready" | "failed">("loading");

onMounted(async () => {
  try {
    const graph = decodeURIComponent(props.encoded);
    const id = `owlauth-mermaid-${crypto.randomUUID()}`;
    const svg = await renderMermaid(id, graph);
    status.value = "ready";
    await nextTick();
    if (container.value) {
      container.value.innerHTML = svg;
    }
  } catch {
    status.value = "failed";
  }
});
</script>

<template>
  <div
    ref="container"
    class="owlauth-mermaid"
    role="img"
    aria-label="Architecture diagram"
    :aria-busy="status === 'loading'"
  >
    <span v-if="status === 'loading'">Loading diagram…</span>
    <span v-else-if="status === 'failed'">Diagram could not be rendered.</span>
  </div>
</template>

<style scoped>
.owlauth-mermaid {
  margin: 24px 0;
  min-height: 48px;
  overflow-x: auto;
  text-align: center;
}

.owlauth-mermaid :deep(svg) {
  height: auto;
  max-width: 100%;
}
</style>
