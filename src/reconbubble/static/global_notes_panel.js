(function () {
  const panel = document.getElementById("globalNotesPanel");
  const handle = document.getElementById("globalNotesHandle");
  const toggleBtn = document.getElementById("globalNotesToggle");
  const text = document.getElementById("globalNotesText");
  const status = document.getElementById("globalNotesStatus");
  if (!panel || !handle || !toggleBtn || !text || !status) return;

  const PIN_KEY = "reconbubble.globalNotesPinned";
  let pinned = localStorage.getItem(PIN_KEY) === "1";
  let hideTimer = null;
  let saveTimer = null;

  function setOpen(open) {
    panel.classList.toggle("open", !!open);
    panel.setAttribute("aria-hidden", open ? "false" : "true");
  }

  function applyPinState() {
    toggleBtn.textContent = pinned ? "Unpin" : "Pin";
    if (pinned) {
      setOpen(true);
    }
  }

  async function loadNote() {
    try {
      const res = await fetch("/api/global-notes");
      const data = await res.json();
      text.value = data.note || "";
      status.textContent = "";
      status.style.opacity = "0";
    } catch (_) {
      status.textContent = "Error";
      status.style.opacity = "1";
      setTimeout(() => { status.style.opacity = "0"; }, 5000);
    }
  }

  async function saveNow() {
    try {
      status.textContent = "Saving";
      status.style.opacity = "1";
      setTimeout(() => { if (status.textContent === "Saving") status.style.opacity = "0"; }, 3000);
      const fd = new FormData();
      fd.append("note", text.value || "");
      const res = await fetch("/api/global-notes", { method: "POST", body: fd });
      if (!res.ok) throw new Error("save failed");
      status.textContent = "Saved";
      setTimeout(() => { status.style.opacity = "0"; }, 1000);
    } catch (_) {
      status.textContent = "Save failed";
      status.style.opacity = "1";
      setTimeout(() => { status.style.opacity = "0"; }, 5000);
    }
  }

  function queueSave() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(saveNow, 500);
  }

  handle.addEventListener("mouseenter", () => {
    clearTimeout(hideTimer);
    setOpen(true);
  });

  panel.addEventListener("mouseenter", () => {
    clearTimeout(hideTimer);
  });

  panel.addEventListener("mouseleave", () => {
    if (pinned) return;
    hideTimer = setTimeout(() => setOpen(false), 680);
  });

  handle.addEventListener("click", () => {
    setOpen(!panel.classList.contains("open"));
  });

  toggleBtn.addEventListener("click", () => {
    pinned = !pinned;
    localStorage.setItem(PIN_KEY, pinned ? "1" : "0");
    applyPinState();
    if (!pinned) setOpen(false);
  });

  text.addEventListener("input", queueSave);

  applyPinState();
  loadNote();
})();
