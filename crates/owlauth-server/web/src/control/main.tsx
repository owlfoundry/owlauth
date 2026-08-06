import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router";

import { readConfiguredBase } from "../shared/configured-base";
import "../shared/styles/tokens.css";
import { ControlApp } from "./App";

const root = document.getElementById("owlauth-root");
if (root === null) {
  throw new Error("OwlAuth Control shell root is missing");
}

const basename = `${readConfiguredBase("control")}console`;
const router = createBrowserRouter([{ path: "*", element: <ControlApp /> }], { basename });
createRoot(root).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
