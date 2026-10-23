import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import "./index.css";
import App from "./App.jsx";
import { ToastProvider } from "./components/Toast";

// Only Chromium renders SVG filters inside backdrop-filter; elsewhere the CSS keeps a plain blur.
const isChromium = /Chrome\//.test(navigator.userAgent) && !/Firefox\//.test(navigator.userAgent);
if (isChromium && CSS.supports("backdrop-filter", "url(#lg-refract) blur(1px)")) {
  document.documentElement.classList.add("ir-refract");
}

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <BrowserRouter>
      <ToastProvider>
        <App />
      </ToastProvider>
    </BrowserRouter>
  </StrictMode>,
);
