(function () {
  const panel = document.getElementById("globalNotesPanel");
  const handle = document.getElementById("globalNotesHandle");
  const toggleBtn = document.getElementById("globalNotesToggle");
  const timelineTab = document.getElementById("notesTimelineTab");
  const timelineContent = document.getElementById("timelineContent");
  const timelineAddDay = document.getElementById("timelineAddDay");
  let timelineDays = [];
  let timelineLoaded = false;
  const text = document.getElementById("globalNotesText");
  const status = document.getElementById("globalNotesStatus");
  const quickTab = document.getElementById("notesQuickTab");
  const tableTab = document.getElementById("notesTableTab");
  const sprayTab = document.getElementById("notesSprayTab");
  const tableBody = document.getElementById("globalNotesTableBody");
  const addRowBtn = document.getElementById("globalNotesAddRow");
  const tabBtns = document.querySelectorAll(".notes-tab");
  const sprayServiceList = document.getElementById("sprayServiceList");
  const sprayContent = document.getElementById("sprayContent");
  const sprayAddService = document.getElementById("sprayAddService");
  const sprayCopyToWord = document.getElementById("sprayCopyToWord");
  if (!panel || !handle || !toggleBtn || !text || !status) return;

  const PIN_KEY = "reconbubble.globalNotesPinned";
  const SPRAY_KEY = "reconbubble.sprayActiveService";
  let pinned = localStorage.getItem(PIN_KEY) === "1";
  let hideTimer = null;
  let saveTimer = null;
  let noteRows = [];
  let sprayServices = [];
  let sprayActiveServiceId = null;
  let sprayLoaded = false;

  function setOpen(open) {
    panel.classList.toggle("open", !!open);
    panel.setAttribute("aria-hidden", open ? "false" : "true");
  }

  function applyPinState() {
    toggleBtn.textContent = pinned ? "\uD83D\uDD12" : "\uD83D\uDD13";
    toggleBtn.classList.toggle("unlocked", !pinned);
    toggleBtn.classList.toggle("locked", pinned);
    if (pinned) setOpen(true);
  }

  function switchTab(tabName) {
    tabBtns.forEach(b => b.classList.toggle("active", b.dataset.notesTab === tabName));
    quickTab.style.display = tabName === "quick" ? "" : "none";
    tableTab.style.display = tabName === "table" ? "" : "none";
    if (sprayTab) {
      sprayTab.style.display = tabName === "spray" ? "" : "none";
      if (tabName === "spray" && !sprayLoaded) {
        sprayLoaded = true;
        loadSprayServices();
      }
    }
    if (timelineTab) {
      timelineTab.style.display = tabName === "timeline" ? "" : "none";
      if (tabName === "timeline" && !timelineLoaded) {
        timelineLoaded = true;
        loadTimeline();
      }
    }
  }

  tabBtns.forEach(b => {
    b.addEventListener("click", () => switchTab(b.dataset.notesTab));
  });

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

  async function loadTableRows() {
    try {
      const res = await fetch("/api/global-notes-table");
      const data = await res.json();
      noteRows = data.rows || [];
      renderTableRows();
    } catch (_) {}
  }

  function renderTableRows() {
    tableBody.innerHTML = "";
    noteRows.forEach((row, i) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><input type="text" class="note-title" value="${escHtml(row.title)}" /></td>
        <td><input type="text" class="note-body" value="${escHtml(row.body)}" /></td>
        <td><button class="cred-action-btn del note-del" title="Delete" type="button">✕</button></td>
      `;
      tr.querySelector(".note-title").addEventListener("input", debounceSaveRow(i));
      tr.querySelector(".note-body").addEventListener("input", debounceSaveRow(i));
      tr.querySelector(".note-del").addEventListener("click", () => deleteRow(i));
      tableBody.appendChild(tr);
    });
  }

  let rowSaveTimers = {};
  function debounceSaveRow(idx) {
    return () => {
      const timer = rowSaveTimers[idx];
      if (timer) clearTimeout(timer);
      const tr = tableBody.children[idx];
      if (!tr) return;
      const title = tr.querySelector(".note-title").value;
      const body = tr.querySelector(".note-body").value;
      rowSaveTimers[idx] = setTimeout(async () => {
        try {
          const fd = new FormData();
          fd.append("title", title);
          fd.append("body", body);
          await fetch(`/api/global-notes-table/${noteRows[idx].id}`, {
            method: "PATCH",
            body: fd,
          });
        } catch (_) {}
      }, 400);
    };
  }

  async function addRow() {
    try {
      const res = await fetch("/api/global-notes-table", {
        method: "POST",
        body: new FormData(),
      });
      const data = await res.json();
      if (data.ok) {
        noteRows.push({ id: data.id, title: "", body: "", order_index: noteRows.length });
        renderTableRows();
        const firstInput = tableBody.querySelector(".note-title");
        if (firstInput) firstInput.focus();
      }
    } catch (_) {}
  }

  async function deleteRow(idx) {
    const row = noteRows[idx];
    if (!row) return;
    try {
      await fetch(`/api/global-notes-table/${row.id}`, { method: "DELETE" });
      noteRows.splice(idx, 1);
      renderTableRows();
    } catch (_) {}
  }

  function escHtml(s) {
    const d = document.createElement("div");
    d.textContent = s || "";
    return d.innerHTML;
  }

  addRowBtn.addEventListener("click", addRow);

  /* --- Spray tab --- */
  async function loadSprayServices() {
    try {
      const res = await fetch("/api/password-spray/services");
      const data = await res.json();
      sprayServices = (data.services || []).filter(s => s.name != null);
      renderSprayServices();
      if (sprayServices.length > 0) {
        const savedId = localStorage.getItem(SPRAY_KEY);
        const restored = savedId && sprayServices.find(s => String(s.id) === savedId);
        switchSprayService(restored ? restored.id : sprayServices[0].id);
      } else {
        sprayContent.innerHTML = '<p style="color:#888; margin:16px;">No services. Click + Service to start.</p>';
      }
    } catch (_) {
      sprayContent.innerHTML = '<p style="color:#c66; margin:16px;">Failed to load spray data.</p>';
    }
  }

  function renderSprayServices() {
    if (!sprayServiceList) return;
    sprayServiceList.innerHTML = '';
    sprayServices.forEach(svc => {
      const btn = document.createElement("button");
      btn.className = "btn spray-service-btn";
      btn.type = "button";
      btn.textContent = svc.name;
      btn.style.cssText = "font-size:11px; padding:4px 8px; background:#4c1d95; border-color:#7c3aed;";
      btn.addEventListener("click", () => switchSprayService(svc.id));
      sprayServiceList.appendChild(btn);
    });
  }

  if (sprayAddService) {
    sprayAddService.addEventListener("click", () => {
      const name = prompt("Service name:");
      if (!name || !name.trim()) return;
      createSprayService(name.trim());
    });
  }

  if (sprayCopyToWord) {
    sprayCopyToWord.addEventListener("click", sprayExportToWord);
  }

  function sprayExportToWord() {
    const svc = sprayServices.find(s => s.id === sprayActiveServiceId);
    if (!svc) return;
    const allRows = [];
    svc.attempts.forEach(at => {
      const password = (at.password || "").trim();
      const attemptedAt = (at.attempted_at || "").trim();
      const notes = (at.notes || "").trim();
      if (password || attemptedAt || notes) {
        allRows.push({ password, attemptedAt, notes });
      }
    });

    let html = '<table style="border-collapse:collapse; font-family:Calibri,sans-serif; font-size:11pt;">';
    html += '<tr><th style="padding:6px;" colspan="4">Passwords Attempted</th></tr>';
    for (let i = 0; i < allRows.length; i += 4) {
      const rowPasswords = allRows.slice(i, i + 4).map(r => r.password || "").map(p => `<td style="padding:6px; width:100px;">${p}</td>`).join("");
      html += `<tr>${rowPasswords}</tr>`;
    }
    html += '</table>';

    const div = document.createElement("div");
    div.style = "position:fixed; top:0; left:0; width:0; height:0;";
    div.innerHTML = html;
    document.body.appendChild(div);

    const range = document.createRange();
    range.selectNode(div);

    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);

    document.execCommand("copy");
    window.getSelection().removeAllRanges();

    div.remove();

    sprayCopyToWord.textContent = "Copied!";
    setTimeout(() => {
      sprayCopyToWord.textContent = "Copy";
    }, 1500);
  }

  function switchSprayService(serviceId) {
    sprayActiveServiceId = serviceId;
    localStorage.setItem(SPRAY_KEY, String(serviceId));
    (document.querySelectorAll(".spray-service-btn") || []).forEach(b => {
      b.style.fontWeight = b.textContent === (sprayServices.find(s => s.id === serviceId) || {}).name ? "bold" : "";
    });
    renderSprayAttempts(serviceId);
  }

  function renderSprayAttempts(serviceId) {
    if (!sprayContent) return;
    const svc = sprayServices.find(s => s.id === serviceId);
    if (!svc) return;
    sprayContent.innerHTML = '';
    const table = document.createElement("table");
    table.innerHTML = `
      <thead><tr><th>Password</th><th>Attempted At</th><th>Notes</th><th style="width:28px;"></th></tr></thead>
      <tbody></tbody>
    `;
    const tbody = table.querySelector("tbody");
    svc.attempts.forEach(at => {
      const tr = document.createElement("tr");
      tr.dataset.attemptId = at.id;
      tr.innerHTML = `
        <td><input type="text" value="${escHtml(at.password)}" style="width:100%;box-sizing:border-box;" /></td>
        <td><input type="text" value="${escHtml(at.attempted_at)}" style="width:100%;box-sizing:border-box;" /></td>
        <td><input type="text" value="${escHtml(at.notes)}" style="width:100%;box-sizing:border-box;" /></td>
        <td><button class="cred-action-btn del" title="Delete" type="button">✕</button></td>
      `;
      bindSprayEditRow(tr, svc.id);
      tr.querySelector(".del").addEventListener("click", () => deleteSprayAttempt(at.id, svc.id));
      tbody.appendChild(tr);
    });
    const inputRow = document.createElement("tr");
    inputRow.innerHTML = `
      <td><input type="text" placeholder="Spring2026!" style="width:100%;box-sizing:border-box;" /></td>
      <td><input type="text" placeholder="2026-05-07 14:10" style="width:100%;box-sizing:border-box;" /></td>
      <td><input type="text" placeholder="result / notes" style="width:100%;box-sizing:border-box;" /></td>
      <td></td>
    `;
    bindSprayInputRow(inputRow, svc.id);
    tbody.appendChild(inputRow);
    sprayContent.appendChild(table);
  }

  function bindSprayEditRow(row, serviceId) {
    let timer = null;
    const save = async () => {
      const attemptId = row.dataset.attemptId;
      if (!attemptId) return;
      clearTimeout(timer);
      timer = setTimeout(async () => {
        const inputs = row.querySelectorAll("input");
        try {
          const fd = new FormData();
          fd.append("password", inputs[0].value.trim());
          fd.append("attempted_at", inputs[1].value.trim());
          fd.append("notes", inputs[2].value.trim());
          await fetch(`/api/password-spray/attempt/${attemptId}`, { method: "POST", body: fd });
        } catch (_) {}
      }, 400);
    };
    row.querySelectorAll("input").forEach(inp => {
      inp.addEventListener("input", save);
      inp.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); save(); } });
    });
  }

  function bindSprayInputRow(row, serviceId) {
    const commit = async () => {
      const inputs = row.querySelectorAll("input");
      const password = inputs[0].value.trim();
      const attemptedAt = inputs[1].value.trim();
      const notes = inputs[2].value.trim();
      if (!password && !attemptedAt && !notes) return;
      try {
        const fd = new FormData();
        fd.append("service_id", serviceId);
        fd.append("password", password);
        fd.append("attempted_at", attemptedAt);
        fd.append("notes", notes);
        const res = await fetch("/api/password-spray/attempt", { method: "POST", body: fd });
        const data = await res.json();
        if (data.ok) {
          const svc = sprayServices.find(s => s.id === serviceId);
          if (svc) svc.attempts.push(data);
          renderSprayAttempts(serviceId);
        }
      } catch (_) {}
    };
    row.querySelectorAll("input").forEach(inp => {
      inp.addEventListener("blur", commit);
      inp.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); commit(); } });
    });
  }

  async function createSprayService(name) {
    try {
      const fd = new FormData();
      fd.append("name", name);
      const res = await fetch("/api/password-spray/service", { method: "POST", body: fd });
      const data = await res.json();
      if (data.ok) {
        if (!sprayServices.find(s => s.id === data.id)) {
          sprayServices.push({ id: data.id, name: data.name, attempts: [] });
        }
        renderSprayServices();
        switchSprayService(data.id);
      }
    } catch (_) {}
  }

  async function deleteSprayAttempt(attemptId, serviceId) {
    if (!confirm("Delete this attempt?")) return;
    try {
      await fetch(`/api/password-spray/attempt/${attemptId}`, { method: "DELETE" });
      const svc = sprayServices.find(s => s.id === serviceId);
      if (svc) svc.attempts = svc.attempts.filter(a => a.id !== attemptId);
      renderSprayAttempts(serviceId);
    } catch (_) {}
  }

  /* --- Timeline tab --- */
  async function loadTimeline() {
    try {
      const res = await fetch("/api/timeline");
      const data = await res.json();
      timelineDays = data.days || [];
      renderTimeline();
    } catch (_) {
      timelineContent.innerHTML = '<p style="color:#c66; margin:16px;">Failed to load timeline.</p>';
    }
  }

  function renderTimeline() {
    if (!timelineContent) return;
    timelineContent.innerHTML = "";
    const sorted = [...timelineDays].sort((a, b) => (a.day_date || "").localeCompare(b.day_date || ""));
    if (sorted.length === 0) {
      timelineContent.innerHTML = '<p style="color:#888; margin:16px;">No days yet. Click +Day to create one.</p>';
      return;
    }
    sorted.forEach(day => {
      const wrapper = document.createElement("div");
      wrapper.className = "timeline-day-wrapper";
      wrapper.style.cssText = "margin-bottom:12px;";
      wrapper.dataset.dayId = day.id;

      const headerRow = document.createElement("div");
      headerRow.style.cssText = "display:flex; gap:6px; align-items:center; margin-bottom:4px;";
      const dateInput = document.createElement("input");
      dateInput.type = "date";
      dateInput.value = day.day_date || "";
      dateInput.style.cssText = "font-size:12px; padding:4px 8px; font-family:monospace;";
      dateInput.addEventListener("change", () => saveTimelineDate(day.id, dateInput.value));
      const delDayBtn = document.createElement("button");
      delDayBtn.textContent = "✕";
      delDayBtn.title = "Delete day";
      delDayBtn.type = "button";
      delDayBtn.className = "cred-action-btn del";
      delDayBtn.addEventListener("click", () => deleteDay(day.id));
      headerRow.appendChild(dateInput);
      headerRow.appendChild(delDayBtn);
      wrapper.appendChild(headerRow);

      const table = document.createElement("table");
      table.style.cssText = "width:100%; border-collapse:collapse;";
      const tbody = document.createElement("tbody");
      (day.entries || []).forEach(entry => {
        const tr = document.createElement("tr");
        const td1 = document.createElement("td");
        td1.style.padding = "2px";
        const ta = document.createElement("textarea");
        ta.className = "timeline-entry-content";
        ta.dataset.entryId = entry.id;
        ta.style.cssText = "width:100%;box-sizing:border-box;resize:vertical;font-family:monospace;font-size:12px;padding:4px;min-height:28px;";
        ta.value = entry.content || "";
        td1.appendChild(ta);
        const td2 = document.createElement("td");
        td2.style.padding = "2px";
        td2.style.width = "28px";
        const delBtn = document.createElement("button");
        delBtn.className = "cred-action-btn del timeline-entry-del";
        delBtn.title = "Delete";
        delBtn.type = "button";
        delBtn.textContent = "✕";
        td2.appendChild(delBtn);
        tr.appendChild(td1);
        tr.appendChild(td2);
        const saveHandler = debounceTimelineSave(entry.id, day.id);
        ta.addEventListener("input", saveHandler);
        delBtn.addEventListener("click", () => deleteEntry(entry.id, day.id));
        tbody.appendChild(tr);
      });

      const inputRow = document.createElement("tr");
      inputRow.innerHTML = `
        <td style="padding:2px;"><textarea placeholder="Entry…" style="width:100%;box-sizing:border-box;resize:vertical;font-family:monospace;font-size:12px;padding:4px;min-height:28px;"></textarea></td>
        <td style="padding:2px; width:28px;"></td>
      `;
      bindTimelineInputRow(inputRow, day.id);
      tbody.appendChild(inputRow);
      table.appendChild(tbody);
      wrapper.appendChild(table);
      timelineContent.appendChild(wrapper);
    });
    requestAnimationFrame(() => {
      timelineContent.querySelectorAll(".timeline-entry-content").forEach(autoResizeTa);
    });
  }

  let tlSaveTimers = {};
  function autoResizeTa(ta) {
    ta.style.height = "auto";
    ta.style.height = ta.scrollHeight + "px";
  }
  function debounceTimelineSave(entryId, dayId) {
    return () => {
      const key = `e${entryId}`;
      const timer = tlSaveTimers[key];
      if (timer) clearTimeout(timer);
      const ta = document.querySelector(`.timeline-entry-content[data-entry-id="${entryId}"]`);
      const content = ta ? ta.value : "";
      const day = timelineDays.find(d => d.id === dayId);
      if (day) {
        const entry = day.entries.find(e => e.id === entryId);
        if (entry) entry.content = content;
      }
      tlSaveTimers[key] = setTimeout(async () => {
        try {
          const fd = new FormData();
          fd.append("content", content);
          await fetch(`/api/timeline/entry/${entryId}`, { method: "PATCH", body: fd });
        } catch (_) {}
      }, 400);
    };
  }

  function bindTimelineInputRow(row, dayId) {
    const commit = async () => {
      const ta = row.querySelector("textarea");
      const content = ta.value.trim();
      if (!content) return;
      try {
        const fd = new FormData();
        fd.append("day_id", dayId);
        fd.append("content", content);
        const res = await fetch("/api/timeline/entry", { method: "POST", body: fd });
        const data = await res.json();
        if (data.ok) {
          const day = timelineDays.find(d => d.id === dayId);
          if (day) {
            if (!day.entries) day.entries = [];
            day.entries.push(data);
          }
          renderTimeline();
        }
      } catch (_) {}
    };
    const ta = row.querySelector("textarea");
    ta.addEventListener("blur", commit);
    ta.addEventListener("keydown", e => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        commit();
      }
    });
  }

  async function saveTimelineDate(dayId, dateValue) {
    try {
      const fd = new FormData();
      fd.append("day_date", dateValue);
      await fetch(`/api/timeline/day/${dayId}`, { method: "PATCH", body: fd });
      const day = timelineDays.find(d => d.id === dayId);
      if (day) day.day_date = dateValue;
      renderTimeline();
    } catch (_) {}
  }

  async function addDay() {
    try {
      const today = new Date().toISOString().split("T")[0];
      const fd = new FormData();
      fd.append("day_date", today);
      const res = await fetch("/api/timeline/day", { method: "POST", body: fd });
      const data = await res.json();
      if (data.ok) {
        timelineDays.push({ id: data.id, day_date: today, entries: [] });
        renderTimeline();
      }
    } catch (_) {}
  }

  async function deleteDay(dayId) {
    if (!confirm("Delete this day and all its entries?")) return;
    try {
      await fetch(`/api/timeline/day/${dayId}`, { method: "DELETE" });
      timelineDays = timelineDays.filter(d => d.id !== dayId);
      renderTimeline();
    } catch (_) {}
  }

  async function deleteEntry(entryId, dayId) {
    try {
      await fetch(`/api/timeline/entry/${entryId}`, { method: "DELETE" });
      const day = timelineDays.find(d => d.id === dayId);
      if (day) day.entries = day.entries.filter(e => e.id !== entryId);
      renderTimeline();
    } catch (_) {}
  }

  if (timelineAddDay) {
    timelineAddDay.addEventListener("click", addDay);
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

  const lockWrapper = document.querySelector(".notes-lock-wrapper");
  if (lockWrapper) {
    lockWrapper.addEventListener("click", e => e.stopPropagation());
    lockWrapper.addEventListener("mouseenter", e => e.stopPropagation());
    lockWrapper.addEventListener("mouseleave", e => e.stopPropagation());
  }

  toggleBtn.addEventListener("click", () => {
    toggleBtn.classList.add("bounce");
    setTimeout(() => toggleBtn.classList.remove("bounce"), 300);
    pinned = !pinned;
    localStorage.setItem(PIN_KEY, pinned ? "1" : "0");
    applyPinState();
    // Don't close — let existing mouseleave logic handle it
  });

  text.addEventListener("input", queueSave);

  applyPinState();
  loadNote();
  loadTableRows();
})();
