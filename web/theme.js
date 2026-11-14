// Applies saved display settings before the first paint, so the page never flashes the wrong
// theme. Loaded as a file because the Content-Security-Policy forbids inline scripts.
(function () {
  const root = document.documentElement;
  const get = (key, fallback) => {
    try {
      return localStorage.getItem("iam-trace-" + key) || fallback;
    } catch (e) {
      return fallback; // storage can be unavailable (private windows, embedded frames)
    }
  };
  const mode = get("mode", "light");
  const dark = mode === "system" ? window.matchMedia("(prefers-color-scheme: dark)").matches : mode === "dark";
  root.dataset.mode = dark ? "dark" : "light";
  root.dataset.style = get("style", "bold");
  root.dataset.nodes = get("nodes", "card");
  if (root.dataset.style === "brand") root.style.setProperty("--accent", get("brand", "#19b6a4"));
  if (get("anim", "1") === "0") root.classList.add("no-anim");
  if (get("labels", "1") === "0") root.classList.add("no-labels");
})();
