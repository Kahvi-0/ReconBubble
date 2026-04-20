(function () {
  const el = document.getElementById("topologyCy");
  const inspector = document.getElementById("topologyInspector");
  const statusEl = document.getElementById("topologyStatus");
  if (!el || !window.cytoscape) return;

  const ICONS = {
    computer: "💻",
    server: "🗄️",
    router: "📡",
    switch: "🔀",
    firewall: "🧱",
    user: "👤",
    domain: "🌐",
  };

  const initial = window.TOPOLOGY_DATA || { nodes: [], edges: [] };
  const elements = [];
  (initial.nodes || []).forEach((n, i) => {
    const label = (n.label || "Node").trim();
    const type = (n.type || "computer").trim();
    const icon = ICONS[type] || "📍";
    const nodeId = String(n.id || `nseed${i + 1}`);
    elements.push({
      group: "nodes",
      data: {
        id: nodeId,
        label: label,
        type: type,
        color: n.color || "#1f6feb",
        notes: n.notes || "",
        floating_notes: Array.isArray(n.floating_notes) ? n.floating_notes : [],
        compromised: !!n.compromised,
        display: `${icon} ${label}`,
      },
      position: { x: n.x || 120, y: n.y || 120 },
    });
  });
  (initial.edges || []).forEach((e, i) => {
    const edgeId = String(e.id || `eseed${i + 1}`);
    if (!e.source || !e.target) return;
    elements.push({ group: "edges", data: { id: edgeId, source: e.source, target: e.target, label: e.label || "" } });
  });

  const cy = cytoscape({
    container: el,
    elements,
    layout: { name: "preset" },
    style: [
      {
        selector: "node",
        style: {
          "background-color": "data(color)",
          "label": "data(display)",
          "text-wrap": "wrap",
          "text-max-width": 140,
          "font-size": 12,
          "text-valign": "center",
          "text-halign": "center",
          "color": "#e5eefb",
          "shape": "round-rectangle",
          "width": 90,
          "height": 56,
          "border-width": 2,
          "border-color": "#0b1220",
          "z-index": 20,
        },
      },
      {
        selector: 'node[type = "domain"]',
        style: {
          "shape": "ellipse",
          "width": 76,
          "height": 76,
          "background-color": "#16a34a",
          "border-color": "#14532d",
          "border-width": 3,
          "text-wrap": "wrap",
          "text-max-width": 70,
          "font-size": 11,
        },
      },
      {
        selector: 'node[type = "handle"]',
        style: {
          "shape": "ellipse",
          "width": 14,
          "height": 14,
          "background-color": "#f59e0b",
          "border-width": 2,
          "border-color": "#111827",
          "label": "",
          "z-index": 999,
        },
      },
      {
        selector: 'node[type = "badge"]',
        style: {
          "shape": "round-rectangle",
          "width": 34,
          "height": 16,
          "background-color": "#b91c1c",
          "border-width": 1,
          "border-color": "#7f1d1d",
          "label": "PWNED",
          "font-size": 7,
          "font-weight": 800,
          "color": "#fee2e2",
          "text-valign": "center",
          "text-halign": "center",
          "z-index": 998,
        },
      },
      {
        selector: 'node[type = "floating_note"]',
        style: {
          "shape": "round-rectangle",
          "width": 150,
          "height": 24,
          "background-color": "#052e16",
          "border-width": 1,
          "border-color": "#22c55e",
          "label": "data(text)",
          "font-size": 10,
          "font-weight": 500,
          "color": "#bbf7d0",
          "text-valign": "center",
          "text-halign": "center",
          "text-wrap": "ellipsis",
          "text-max-width": 138,
          "z-index": 5,
        },
      },
      {
        selector: "edge",
        style: {
          "width": 3,
          "line-color": "#8da2bf",
          "target-arrow-shape": "triangle",
          "target-arrow-color": "#8da2bf",
          "curve-style": "bezier",
          "label": "data(label)",
          "font-size": 11,
          "color": "#e2e8f0",
          "text-background-color": "#0f172a",
          "text-background-opacity": 0.85,
          "text-background-padding": 3,
        },
      },
      {
        selector: "edge.draft",
        style: {
          "line-color": "#f59e0b",
          "target-arrow-color": "#f59e0b",
          "line-style": "dashed",
          "width": 2,
          "label": "",
        },
      },
      {
        selector: ":selected",
        style: {
          "overlay-color": "#60a5fa",
          "overlay-opacity": 0.2,
          "overlay-padding": 10,
        },
      },
    ],
    wheelSensitivity: 0.2,
  });

  let dragFromOwner = null;
  let dragDraftEdgeId = null;
  let palettePreviewId = null;
  let saveTimer = null;
  let nextNodeId = 1;
  let nextEdgeId = 1;

  cy.nodes().forEach((n) => {
    const m = String(n.id()).match(/^n(\d+)$/);
    if (m) nextNodeId = Math.max(nextNodeId, parseInt(m[1], 10) + 1);
  });
  cy.edges().forEach((e) => {
    const m = String(e.id()).match(/^e(\d+)$/);
    if (m) nextEdgeId = Math.max(nextEdgeId, parseInt(m[1], 10) + 1);
  });

  function setStatus(msg) {
    if (statusEl) statusEl.textContent = msg;
  }

  const ctxMenu = document.createElement("div");
  ctxMenu.style.position = "fixed";
  ctxMenu.style.zIndex = "1400";
  ctxMenu.style.minWidth = "190px";
  ctxMenu.style.background = "#0f172a";
  ctxMenu.style.border = "1px solid #334155";
  ctxMenu.style.borderRadius = "10px";
  ctxMenu.style.boxShadow = "0 12px 28px rgba(0,0,0,0.45)";
  ctxMenu.style.padding = "6px";
  ctxMenu.style.display = "none";
  document.body.appendChild(ctxMenu);

  function hideContextMenu() {
    ctxMenu.style.display = "none";
    ctxMenu.innerHTML = "";
  }

  function showContextMenu(clientX, clientY, actions) {
    ctxMenu.innerHTML = "";
    actions.forEach((a) => {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = a.label;
      b.className = "btn";
      b.style.width = "100%";
      b.style.textAlign = "left";
      b.style.margin = "3px 0";
      b.onclick = () => {
        hideContextMenu();
        a.onClick();
      };
      ctxMenu.appendChild(b);
    });
    const maxX = Math.max(8, window.innerWidth - 220);
    const maxY = Math.max(8, window.innerHeight - 160);
    ctxMenu.style.left = `${Math.min(clientX, maxX)}px`;
    ctxMenu.style.top = `${Math.min(clientY, maxY)}px`;
    ctxMenu.style.display = "block";
  }

  function isHandle(node) {
    return node && node.isNode && node.isNode() && node.data("type") === "handle";
  }

  function isBadge(node) {
    return node && node.isNode && node.isNode() && node.data("type") === "badge";
  }

  function isPreview(node) {
    return node && node.isNode && node.isNode() && node.data("type") === "preview";
  }

  function isFloatingNote(node) {
    return node && node.isNode && node.isNode() && node.data("type") === "floating_note";
  }

  function isVirtualNode(node) {
    return isHandle(node) || isBadge(node) || isPreview(node) || isFloatingNote(node);
  }

  function realNodes() {
    return cy.nodes().filter((n) => !isVirtualNode(n));
  }

  function handleIdFor(nodeId) {
    return `h_${nodeId}`;
  }

  function badgeIdFor(nodeId) {
    return `b_${nodeId}`;
  }

  function floatingNoteId(ownerId, noteId) {
    return `fn_${ownerId}_${noteId}`;
  }

  function syncHandlePosition(nodeId) {
    const owner = cy.getElementById(nodeId);
    const handle = cy.getElementById(handleIdFor(nodeId));
    if (!owner || !owner.length || !handle || !handle.length) return;
    const p = owner.position();
    handle.position({ x: p.x + 44, y: p.y + 28 });
  }

  function syncBadgePosition(nodeId) {
    const owner = cy.getElementById(nodeId);
    const badge = cy.getElementById(badgeIdFor(nodeId));
    if (!owner || !owner.length || !badge || !badge.length) return;
    const p = owner.position();
    badge.position({ x: p.x + 38, y: p.y - 24 });
  }

  function ensureHandle(nodeId) {
    if (cy.getElementById(handleIdFor(nodeId)).length) return;
    cy.add({
      group: "nodes",
      data: { id: handleIdFor(nodeId), type: "handle", owner: nodeId, label: "" },
      position: { x: 0, y: 0 },
      grabbable: true,
      selectable: false,
    });
    syncHandlePosition(nodeId);
  }

  function ensureAllHandles() {
    realNodes().forEach((n) => ensureHandle(n.id()));
  }

  function ensureBadge(nodeId) {
    if (cy.getElementById(badgeIdFor(nodeId)).length) return;
    cy.add({
      group: "nodes",
      data: { id: badgeIdFor(nodeId), type: "badge", owner: nodeId, label: "PWNED" },
      position: { x: 0, y: 0 },
      grabbable: false,
      selectable: false,
    });
    syncBadgePosition(nodeId);
  }

  function removeBadge(nodeId) {
    const b = cy.getElementById(badgeIdFor(nodeId));
    if (b && b.length) b.remove();
  }

  function removeFloatingNotes(ownerId) {
    cy.nodes().forEach((n) => {
      if (isFloatingNote(n) && n.data("owner") === ownerId) n.remove();
    });
  }

  function refreshFloatingNotes(ownerId) {
    removeFloatingNotes(ownerId);
    const owner = cy.getElementById(ownerId);
    if (!owner || !owner.length) return;
    const notes = Array.isArray(owner.data("floating_notes")) ? owner.data("floating_notes") : [];
    const p = owner.position();
    notes.forEach((note, idx) => {
      const id = floatingNoteId(ownerId, String(note.id || idx + 1));
      cy.add({
        group: "nodes",
        data: {
          id,
          type: "floating_note",
          owner: ownerId,
          note_id: String(note.id || idx + 1),
          text: String(note.text || "Note"),
        },
        position: { x: p.x + 110, y: p.y - 20 + idx * 28 },
        grabbable: false,
        selectable: false,
      });
    });
  }

  function deleteFloatingNoteNode(noteNode) {
    const ownerId = String(noteNode.data("owner") || "");
    const noteId = String(noteNode.data("note_id") || "");
    if (!ownerId || !noteId) return;
    const owner = cy.getElementById(ownerId);
    if (!owner || !owner.length) return;
    const arr = Array.isArray(owner.data("floating_notes")) ? [...owner.data("floating_notes")] : [];
    owner.data(
      "floating_notes",
      arr.filter((x) => String((x || {}).id || "") !== noteId)
    );
    refreshFloatingNotes(ownerId);
    queueSave();
    setStatus("Floating note deleted");
  }

  function findDropTarget(sourceId, worldPos) {
    let best = null;
    let bestDist = Number.POSITIVE_INFINITY;
    realNodes().forEach((n) => {
      if (n.id() === sourceId) return;
      const p = n.position();
      const dx = p.x - worldPos.x;
      const dy = p.y - worldPos.y;
      const d = Math.sqrt(dx * dx + dy * dy);
      if (d < bestDist && d < 55) {
        bestDist = d;
        best = n;
      }
    });
    return best;
  }

  async function saveNow() {
    const nodes = realNodes().map((n) => ({
      id: n.id(),
      label: n.data("label") || "Node",
      type: n.data("type") || "computer",
      color: n.data("color") || "#1f6feb",
      notes: n.data("notes") || "",
      floating_notes: Array.isArray(n.data("floating_notes")) ? n.data("floating_notes") : [],
      compromised: !!n.data("compromised"),
      x: n.position("x"),
      y: n.position("y"),
    }));
    const edges = cy
      .edges()
      .filter((e) => !e.hasClass("draft") && !isVirtualNode(e.source()) && !isVirtualNode(e.target()))
      .map((e) => ({ id: e.id(), source: e.source().id(), target: e.target().id(), label: e.data("label") || "" }));
    setStatus("Saving...");
    try {
      await fetch("/api/topology", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        keepalive: true,
        body: JSON.stringify({ nodes, edges }),
      });
      setStatus("Saved");
    } catch (_e) {
      setStatus("Save failed");
    }
  }

  function queueSave() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(saveNow, 350);
  }

  function updateNodeClass(node) {
    if (!!node.data("compromised")) ensureBadge(node.id());
    else removeBadge(node.id());
  }

  function addNode(type) {
    const label = type.charAt(0).toUpperCase() + type.slice(1);
    const p = cy.extent();
    const x = (p.x1 + p.x2) / 2;
    const y = (p.y1 + p.y2) / 2;
    return addNodeAt(type, x, y);
  }

  function addNodeAt(type, x, y) {
    const label = type.charAt(0).toUpperCase() + type.slice(1);
    const icon = ICONS[type] || "📍";
    const node = cy.add({
      group: "nodes",
      data: {
        id: `n${nextNodeId++}`,
        label: `${label} ${nextNodeId - 1}`,
        type: type,
        color: "#1f6feb",
        notes: "",
        floating_notes: [],
        compromised: false,
        display: `${icon} ${label} ${nextNodeId - 1}`,
      },
      position: { x, y },
    });
    ensureHandle(node.id());
    cy.$(node).select();
    renderInspector(node);
    queueSave();
    return node;
  }

  function clientToGraphPosition(clientX, clientY) {
    const rect = el.getBoundingClientRect();
    const rx = clientX - rect.left;
    const ry = clientY - rect.top;
    const pan = cy.pan();
    const zoom = cy.zoom();
    return {
      x: (rx - pan.x) / zoom,
      y: (ry - pan.y) / zoom,
    };
  }

  function clearPalettePreview() {
    if (!palettePreviewId) return;
    const p = cy.getElementById(palettePreviewId);
    if (p && p.length) p.remove();
    palettePreviewId = null;
  }

  function ensurePalettePreview(type, x, y) {
    const icon = ICONS[type] || "📍";
    const label = type.charAt(0).toUpperCase() + type.slice(1);
    if (!palettePreviewId) {
      palettePreviewId = "palette_preview";
      cy.add({
        group: "nodes",
        data: {
          id: palettePreviewId,
          type: "preview",
          label,
          color: "#64748b",
          notes: "",
          compromised: false,
          display: `${icon} ${label}`,
        },
        position: { x, y },
        selectable: false,
        grabbable: false,
        classes: "preview",
      });
    } else {
      const p = cy.getElementById(palettePreviewId);
      if (p && p.length) {
        p.data("label", label);
        p.data("display", `${icon} ${label}`);
        p.position({ x, y });
      }
    }
  }

  function renderInspector(node) {
    if (!node || !node.isNode()) {
      inspector.innerHTML = '<span class="muted">Click a node to edit label, notes, color, and compromise state.</span>';
      return;
    }
    const d = node.data();
    inspector.innerHTML = `
      <label>Label</label>
      <input id="topoLabel" value="${escapeHtml(d.label || "")}" />
      <label style="margin-top:8px;">Color</label>
      <input id="topoColor" type="color" value="${escapeHtml(d.color || "#1f6feb")}" />
      <label class="checkbox-label" style="margin-top:10px;">
        <input id="topoCompromised" type="checkbox" ${d.compromised ? "checked" : ""} />
        Mark as compromised
      </label>
      <label style="margin-top:8px;">Notes</label>
      <textarea id="topoNotes" rows="10" style="resize:vertical;">${escapeHtml(d.notes || "")}</textarea>
      <div class="muted" style="margin-top:8px;">Tip: Drag the small orange bubble on a node to another node to create a link.</div>
    `;

    const labelEl = document.getElementById("topoLabel");
    const colorEl = document.getElementById("topoColor");
    const notesEl = document.getElementById("topoNotes");
    const compEl = document.getElementById("topoCompromised");

    function applyDisplay() {
      const icon = ICONS[node.data("type")] || "📍";
      node.data("display", `${icon} ${node.data("label") || "Node"}`);
    }

    labelEl && labelEl.addEventListener("input", () => {
      node.data("label", labelEl.value || "Node");
      applyDisplay();
      queueSave();
    });
    colorEl && colorEl.addEventListener("input", () => {
      node.data("color", colorEl.value || "#1f6feb");
      queueSave();
    });
    notesEl && notesEl.addEventListener("input", () => {
      node.data("notes", notesEl.value || "");
      queueSave();
    });
    compEl && compEl.addEventListener("change", () => {
      node.data("compromised", !!compEl.checked);
      updateNodeClass(node);
      queueSave();
    });
  }

  function escapeHtml(s) {
    return String(s || "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  cy.nodes().forEach(updateNodeClass);
  ensureAllHandles();
  realNodes().forEach((n) => refreshFloatingNotes(n.id()));
  cy.on("tap", "node", (evt) => {
    const node = evt.target;
    if (isVirtualNode(node)) {
      return;
    }
    renderInspector(node);
  });

  cy.on("tap", (evt) => {
    if (evt.target === cy) renderInspector(null);
  });

  cy.on("dragfree", "node", (evt) => {
    const n = evt.target;
    if (!isVirtualNode(n)) {
      syncHandlePosition(n.id());
      syncBadgePosition(n.id());
      refreshFloatingNotes(n.id());
      saveNow();
    }
  });

  cy.on("drag", "node", (evt) => {
    const n = evt.target;
    if (!isVirtualNode(n)) {
      syncHandlePosition(n.id());
      syncBadgePosition(n.id());
      refreshFloatingNotes(n.id());
    }
  });

  cy.on("add", "node", (evt) => {
    const n = evt.target;
    if (!isVirtualNode(n)) {
      ensureHandle(n.id());
      updateNodeClass(n);
      refreshFloatingNotes(n.id());
    }
  });

  cy.on("remove", "node", (evt) => {
    const n = evt.target;
    if (!isVirtualNode(n)) {
      const h = cy.getElementById(handleIdFor(n.id()));
      if (h && h.length) h.remove();
      removeBadge(n.id());
      removeFloatingNotes(n.id());
      queueSave();
    }
  });

  cy.on("grab", 'node[type = "handle"]', (evt) => {
    dragFromOwner = evt.target.data("owner") || null;
    if (dragFromOwner) {
      dragDraftEdgeId = `draft_${dragFromOwner}`;
      const existingDraft = cy.getElementById(dragDraftEdgeId);
      if (existingDraft && existingDraft.length) existingDraft.remove();
      cy.add({
        group: "edges",
        classes: "draft",
        data: { id: dragDraftEdgeId, source: dragFromOwner, target: evt.target.id() },
      });
    }
    setStatus(dragFromOwner ? `Drag from ${dragFromOwner} to target node` : "Drag to target node");
  });

  cy.on("free", 'node[type = "handle"]', (evt) => {
    const handle = evt.target;
    const ownerId = handle.data("owner") || dragFromOwner;
    const pos = handle.position();
    const target = ownerId ? findDropTarget(ownerId, pos) : null;
    if (ownerId && target) {
      const existing = cy
        .edges()
        .filter((e) => e.source().id() === ownerId && e.target().id() === target.id());
      if (existing.length === 0) {
        cy.add({ group: "edges", data: { id: `e${nextEdgeId++}`, source: ownerId, target: target.id() } });
        queueSave();
      }
      setStatus(`Linked ${ownerId} -> ${target.id()}`);
    } else {
      setStatus("Ready");
    }
    if (dragDraftEdgeId) {
      const d = cy.getElementById(dragDraftEdgeId);
      if (d && d.length) d.remove();
    }
    if (ownerId) syncHandlePosition(ownerId);
    dragFromOwner = null;
    dragDraftEdgeId = null;
  });

  cy.on("cxttap", "node", (evt) => {
    const node = evt.target;
    if (isFloatingNote(node)) {
      const oe = evt.originalEvent || {};
      showContextMenu(oe.clientX || 24, oe.clientY || 24, [
        {
          label: "Delete Floating Note",
          onClick: () => deleteFloatingNoteNode(node),
        },
      ]);
      return;
    }
    if (isVirtualNode(node)) return;
    const oe = evt.originalEvent || {};
    showContextMenu(oe.clientX || 24, oe.clientY || 24, [
      {
        label: "Add Floating Note",
        onClick: () => {
          const text = window.prompt("Floating note text", "");
          if (text === null) return;
          const arr = Array.isArray(node.data("floating_notes")) ? [...node.data("floating_notes")] : [];
          arr.push({ id: String(Date.now()), text: String(text || "Note").trim() || "Note" });
          node.data("floating_notes", arr);
          refreshFloatingNotes(node.id());
          queueSave();
          setStatus("Floating note added");
        },
      },
      {
        label: "Delete Node",
        onClick: () => {
          node.remove();
          renderInspector(null);
          queueSave();
          setStatus("Node deleted");
        },
      },
    ]);
  });

  cy.on("cxttap", "edge", (evt) => {
    const edge = evt.target;
    if (edge.hasClass("draft")) return;
    const oe = evt.originalEvent || {};
    showContextMenu(oe.clientX || 24, oe.clientY || 24, [
      {
        label: "Rename Arrow",
        onClick: () => {
          const current = edge.data("label") || "";
          const value = window.prompt("Arrow label", current);
          if (value === null) return;
          edge.data("label", String(value).trim());
          queueSave();
          setStatus("Arrow label saved");
        },
      },
      {
        label: "Delete Arrow",
        onClick: () => {
          edge.remove();
          queueSave();
          setStatus("Arrow deleted");
        },
      },
    ]);
  });

  el.addEventListener("contextmenu", (e) => e.preventDefault());
  window.addEventListener("beforeunload", () => { saveNow(); });
  window.addEventListener("click", hideContextMenu);
  cy.on("tap", () => hideContextMenu());
  cy.on("pan zoom", () => hideContextMenu());

  document.querySelectorAll("[data-node-type]").forEach((tool) => {
    tool.addEventListener("dragstart", (ev) => {
      const type = tool.getAttribute("data-node-type") || "computer";
      ev.dataTransfer && ev.dataTransfer.setData("text/topology-node", type);
      ev.dataTransfer && (ev.dataTransfer.effectAllowed = "copy");
      setStatus(`Dragging ${type}... drop onto map`);
    });
    tool.addEventListener("dragend", () => {
      clearPalettePreview();
      setStatus("Ready");
    });
  });

  el.addEventListener("dragover", (ev) => {
    ev.preventDefault();
    const type = (ev.dataTransfer && ev.dataTransfer.getData("text/topology-node")) || "";
    if (!type) return;
    const p = clientToGraphPosition(ev.clientX, ev.clientY);
    ensurePalettePreview(type, p.x, p.y);
  });

  el.addEventListener("drop", (ev) => {
    ev.preventDefault();
    const type = (ev.dataTransfer && ev.dataTransfer.getData("text/topology-node")) || "";
    if (!type) return;
    const p = clientToGraphPosition(ev.clientX, ev.clientY);
    clearPalettePreview();
    addNodeAt(type, p.x, p.y);
    setStatus(`Added ${type}`);
  });

  el.addEventListener("dragleave", (ev) => {
    if (ev.relatedTarget && el.contains(ev.relatedTarget)) return;
    clearPalettePreview();
  });

  const fitBtn = document.getElementById("fitView");
  fitBtn && fitBtn.addEventListener("click", () => cy.fit(undefined, 40));

  if (cy.nodes().length) cy.fit(undefined, 40);
})();
