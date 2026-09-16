// Global "running processes" indicator (top right of every page).
// Polls /api/jobs/active, which aggregates every registered long-running
// process (tool runs, screenshot jobs, and anything added in the future).
(function () {
  const POLL_MS = 2500;

  function el(id) {
    return document.getElementById(id);
  }

  const box = el("globalJobsIndicator");
  if (!box) return;

  const icon = el("jobsIndicatorIcon");
  const label = el("jobsIndicatorLabel");

  let timer = null;
  let inFlight = false;
  let lastJobs = [];

  function render() {
    if (!lastJobs.length) {
      box.hidden = true;
      box.removeAttribute("title");
      return;
    }
    box.hidden = false;
    if (lastJobs.length === 1) {
      label.textContent = lastJobs[0].label;
      box.setAttribute("title", lastJobs[0].label);
    } else {
      label.textContent = lastJobs.length + " running";
      box.setAttribute("title", lastJobs.map((j) => j.label).join("\n"));
    }
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
  start();
})();
