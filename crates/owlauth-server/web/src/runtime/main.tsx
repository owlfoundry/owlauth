import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { RuntimeApp } from "./App";

const root = document.getElementById("owlauth-root");
if (root === null) {
  throw new Error("OwlAuth Runtime shell root is missing");
}

createRoot(root).render(
  <StrictMode>
    <RuntimeApp />
  </StrictMode>,
);
