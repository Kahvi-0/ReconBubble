// Global "running processes" indicator (top right of every page).
// Polls /api/jobs/active, which aggregates every registered long-running
// process (tool runs, screenshot jobs, and anything added in the future).
//
// Renders a bare spinner; the running jobs are shown in a tooltip on hover
// (and via aria-label for screen readers).
(function () {
  const POLL_MS = 2500;

  function el(id) {
    return document.getElementById(id);
  }

  const box = el("globalJobsIndicator");
  if (!box) return;

  const tip = el("jobsIndicatorTip");

  let timer = null;
  let inFlight = false;
  let lastJobs = [];

  function render() {
    if (!lastJobs.length) {
      box.hidden = true;
      if (tip) tip.textContent = "";
      box.setAttribute("aria-label", "");
      return;
    }
    box.hidden = false;
    const lines = lastJobs.map((j) => j.label);
    if (tip) tip.textContent = lines.join("\n");
    box.setAttribute(
      "aria-label",
      lines.length === 1
        ? lines[0]
        : lines.length + " jobs running: " + lines.join(", ")
    );
  }

  function onClick() {
    if (!lastJobs.length) return;
    const href = lastJobs[0].href;
    if (href && href !== window.location.pathname) {
      window.location.href = href;
    }
  }

  async function poll() {
    if (inFlight) return;
    inFlight = true;
    try {
      const resp = await fetch("/api/jobs/active", { cache: "no-store" });
      const data = await resp.json();
      lastJobs = data.ok ? data.jobs : [];
      render();
    } catch (e) {
      // Network hiccup: keep last state.
    } finally {
      inFlight = false;
    }
  }

  function start() {
    if (timer) return;
    poll();
    timer = setInterval(() => {
      if (!document.hidden) poll();
    }, POLL_MS);
  }

  box.addEventListener("click", onClick);
  box.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onClick();
    }
  });
  start();
})();
