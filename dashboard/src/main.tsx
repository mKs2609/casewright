import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
// The fonts are bundled into the app and served by this site (the page policy allows no other).
import "@fontsource-variable/inter-tight/wght.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "@fontsource/source-serif-4/latin-300.css";
import "@fontsource/source-serif-4/latin-300-italic.css";
import "./styles/tokens.css";
import "./styles/app.css";
import "./styles/branched-menu.css";
import "./styles/lattice-loader.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
