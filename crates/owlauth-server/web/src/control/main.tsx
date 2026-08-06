import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";

import { readConfiguredBase } from "../shared/configured-base";
import "../shared/styles/tokens.css";
import { ControlApp } from "./App";

const root = document.getElementById("owlauth-root");
if (root === null) {
  throw new Error("OwlAuth Control shell root is missing");
}

const basename = `${readConfiguredBase("control")}console`;
createRoot(root).render(
  <StrictMode>
    <BrowserRouter basename={basename}>
      <ControlApp />
    </BrowserRouter>
  </StrictMode>,
);
