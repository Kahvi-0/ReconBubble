(function () {
  const el = document.getElementById("topologyCy");
  const inspector = document.getElementById("topologyInspector");
  const inspectorWrap = document.getElementById("topologyInspectorWrap");
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
    company: "🏢",
    asn: "🌍",
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
        linked_asset_id: n.linked_asset_id || "",
        linked_name_id: n.linked_name_id || "",
        asn: n.asn || "",
        registrar: n.registrar || "",
        netblocks: n.netblocks || "",
        subdomain_ips: n.subdomain_ips || "",
        first_name: n.first_name || "",
        last_name: n.last_name || "",
        email: n.email || "",
        phone: n.phone || "",
        display: `${icon}\n\n${label}`,
      },
      position: { x: n.x || 120, y: n.y || 120 },
    });
  });
  (initial.edges || []).forEach((e, i) => {
    const edgeId = String(e.id || `eseed${i + 1}`);
    if (!e.source || !e.target) return;
    elements.push({
      group: "edges",
      data: {
        id: edgeId,
        source: e.source,
        target: e.target,
        label: e.label || "",
        arrowDirection: e.arrowDirection || "target",
        lineStyle: e.lineStyle || "solid",
      },
    });
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
        "text-max-width": 220,
         "font-size": 14,
          "text-valign": "center",
          "text-halign": "center",
          "color": "#e5eefb",
          "shape": "round-rectangle",
  "width": 120,
          "height": 120,
          "border-width": 2,
          "border-color": "#0b1220",
          "background-opacity": 0.35,
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
      "text-max-width": 400,
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
          "opacity": 0,
        },
      },
      {
        selector: 'node[type = "handle"]:hover',
        style: {
          "opacity": 0.9,
        },
      },
      {
        selector: 'node[type = "badge"]',
        style: {
          "shape": "round-rectangle",
           "width": 76,
          "height": 16,
          "background-color": "#b91c1c",
          "border-width": 1,
          "border-color": "#7f1d1d",
           "label": "COMPROMISED",
          "font-size": 7,
          "font-weight": 800,
          "color": "#fee2e2",
          "text-valign": "center",
          "text-halign": "center",
          "z-index": 10001,
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
        selector: 'node[type = "note_indicator"]',
        style: {
          "shape": "ellipse",
          "width": 16,
          "height": 16,
          "background-color": "#64748b",
          "border-width": 1,
          "border-color": "#334155",
          "label": "data(display)",
          "font-size": 9,
          "font-weight": 700,
          "color": "#f1f5f9",
          "text-valign": "center",
          "text-halign": "center",
          "opacity": 0.5,
          "z-index": 10002,
        },
      },
      {
        selector: 'node[type = "note_indicator"]:active',
        style: {
          "opacity": 0.9,
          "background-color": "#94a3b8",
        },
      },
      {
        selector: "edge",
        style: {
          "width": 3,
          "line-color": "#8da2bf",
          "target-arrow-color": "#8da2bf",
          "source-arrow-color": "#8da2bf",
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
        selector: 'edge[arrowDirection = "none"]',
        style: {
          "target-arrow-shape": "none",
          "source-arrow-shape": "none",
        },
      },
      {
        selector: 'edge[arrowDirection = "target"]',
        style: {
          "target-arrow-shape": "triangle",
          "source-arrow-shape": "none",
        },
      },
      {
        selector: 'edge[arrowDirection = "source"]',
        style: {
          "target-arrow-shape": "none",
          "source-arrow-shape": "triangle",
        },
      },
      {
        selector: 'edge[arrowDirection = "both"]',
        style: {
          "target-arrow-shape": "triangle",
          "source-arrow-shape": "triangle",
        },
      },
      {
        selector: 'edge[lineStyle = "dotted"]',
        style: {
          "line-style": "dotted",
        },
      },
      {
        selector: 'edge[lineStyle = "dashed"]',
        style: {
          "line-style": "dashed",
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

  const notesTooltip = document.createElement("div");
  notesTooltip.style.position = "fixed";
  notesTooltip.style.zIndex = "2000";
  notesTooltip.style.maxWidth = "320px";
  notesTooltip.style.maxHeight = "240px";
  notesTooltip.style.overflowY = "auto";
  notesTooltip.style.background = "#0f172a";
  notesTooltip.style.border = "1px solid #334155";
  notesTooltip.style.borderRadius = "8px";
  notesTooltip.style.boxShadow = "0 12px 28px rgba(0,0,0,0.5)";
  notesTooltip.style.padding = "10px 12px";
  notesTooltip.style.fontSize = "11px";
  notesTooltip.style.color = "#cbd5e1";
  notesTooltip.style.whiteSpace = "pre-wrap";
  notesTooltip.style.display = "none";
  notesTooltip.style.lineHeight = "1.5";
  notesTooltip.style.fontFamily = "'JetBrains Mono', monospace";
  document.body.appendChild(notesTooltip);

  function showNotesTooltip(clientX, clientY, text) {
    const maxX = Math.max(8, window.innerWidth - 340);
    const maxY = Math.max(8, window.innerHeight - 260);
    notesTooltip.style.left = `${Math.min(clientX + 14, maxX)}px`;
    notesTooltip.style.top = `${Math.min(clientY - 10, maxY)}px`;
    notesTooltip.textContent = text;
    notesTooltip.style.display = "block";
  }

  function hideNotesTooltip() {
    notesTooltip.style.display = "none";
  }

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

  function isNoteIndicator(node) {
    return node && node.isNode && node.isNode() && node.data("type") === "note_indicator";
  }

  function isVirtualNode(node) {
    return isHandle(node) || isBadge(node) || isPreview(node) || isFloatingNote(node) || isNoteIndicator(node);
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

  function noteIndicatorIdFor(nodeId) {
    return `ni_${nodeId}`;
  }

  function syncNoteIndicatorPosition(nodeId) {
    const owner = cy.getElementById(nodeId);
    const indicator = cy.getElementById(noteIndicatorIdFor(nodeId));
    if (!owner || !owner.length || !indicator || !indicator.length) return;
    const p = owner.position();
    const w = owner.width();
    const h = owner.height();
    indicator.position({ x: p.x - w / 2 + 10, y: p.y - h / 2 - 10 });
  }

  function syncBadgePosition(nodeId) {
    const owner = cy.getElementById(nodeId);
    const badge = cy.getElementById(badgeIdFor(nodeId));
    if (!owner || !owner.length || !badge || !badge.length) return;
    const p = owner.position();
    const w = owner.width();
    const h = owner.height();
    const bw = badge.width();
    const bh = badge.height();
    badge.position({ x: p.x + w / 2 - bw / 2 + 2, y: p.y - h / 2 - bh / 2 - 2 });
  }

  function ensureNoteIndicator(nodeId) {
    const owner = cy.getElementById(nodeId);
    if (!owner || !owner.length) return;
    const notes = owner.data("notes") || "";
    if (!notes.trim()) {
      removeNoteIndicator(nodeId);
      return;
    }
    if (cy.getElementById(noteIndicatorIdFor(nodeId)).length) return;
    cy.add({
      group: "nodes",
      data: { id: noteIndicatorIdFor(nodeId), type: "note_indicator", owner: nodeId, label: "", display: "💬", notes: notes },
      position: { x: 0, y: 0 },
      grabbable: false,
      selectable: true,
    });
    syncNoteIndicatorPosition(nodeId);
  }

  function removeNoteIndicator(nodeId) {
    const ind = cy.getElementById(noteIndicatorIdFor(nodeId));
    if (ind && ind.length) ind.remove();
  }

  function refreshNoteIndicator(nodeId) {
    const owner = cy.getElementById(nodeId);
    if (!owner || !owner.length) return;
    const notes = owner.data("notes") || "";
    if (notes.trim()) {
      const existing = cy.getElementById(noteIndicatorIdFor(nodeId));
      if (existing && existing.length) {
        existing.data("notes", notes);
        syncNoteIndicatorPosition(nodeId);
        return;
      }
    }
    ensureNoteIndicator(nodeId);
  }

  function ensureAllNoteIndicators() {
    realNodes().forEach((n) => ensureNoteIndicator(n.id()));
  }

  function syncHandlePosition(nodeId) {
    const owner = cy.getElementById(nodeId);
    const handle = cy.getElementById(handleIdFor(nodeId));
    if (!owner || !owner.length || !handle || !handle.length) return;
    const p = owner.position();
    handle.position({ x: p.x + 44, y: p.y + 28 });
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
       data: { id: badgeIdFor(nodeId), type: "badge", owner: nodeId, label: "COMPROMISED" },
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
      linked_asset_id: n.data("linked_asset_id") || "",
      linked_name_id: n.data("linked_name_id") || "",
      asn: n.data("asn") || "",
      registrar: n.data("registrar") || "",
      netblocks: n.data("netblocks") || "",
      subdomain_ips: n.data("subdomain_ips") || "",
      first_name: n.data("first_name") || "",
      last_name: n.data("last_name") || "",
      email: n.data("email") || "",
      phone: n.data("phone") || "",
      x: n.position("x"),
      y: n.position("y"),
    }));
    const edges = cy
      .edges()
      .filter((e) => !e.hasClass("draft") && !isVirtualNode(e.source()) && !isVirtualNode(e.target()))
      .map((e) => ({
        id: e.id(),
        source: e.source().id(),
        target: e.target().id(),
        label: e.data("label") || "",
        arrowDirection: e.data("arrowDirection") || "target",
        lineStyle: e.data("lineStyle") || "solid",
      }));
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
        linked_asset_id: "",
        linked_name_id: "",
        display: `${icon}\n\n${label} ${nextNodeId - 1}`,
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
        display: `${icon}\n\n${label}`,
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

  let allHostsCache = [];
  let currentAssetHosts = [];
  let allNamesCache = [];

  async function loadHosts() {
    if (allHostsCache.length) return allHostsCache;
    try {
      const r = await fetch("/api/hosts/list");
      const j = await r.json();
      allHostsCache = j.hosts || [];
    } catch (_) {}
    return allHostsCache;
  }

  async function loadNames() {
    if (allNamesCache.length) return allNamesCache;
    try {
      const r = await fetch("/api/names/list");
      const j = await r.json();
      allNamesCache = j.names || [];
    } catch (_) {}
    return allNamesCache;
  }

  function buildAssetCombobox(targetNode, selectedId) {
    const wrapId = "topoAssetWrap";
    const inputId = "topoAssetInput";
    const listId = "topoAssetList";

    const currentHost = currentAssetHosts.find((h) => String(h.id) === String(selectedId));
    const displayVal = currentHost ? `${currentHost.ip} ${currentHost.hostname}`.trim() : "";

    const wrap = document.createElement("div");
    wrap.id = wrapId;
    wrap.style.position = "relative";

    const input = document.createElement("input");
    input.id = inputId;
    input.type = "text";
    input.placeholder = "Type IP or hostname to filter assets...";
    input.value = displayVal;
    input.autocomplete = "off";

    const list = document.createElement("div");
    list.id = listId;
    list.style.position = "absolute";
    list.style.top = "100%";
    list.style.left = "0";
    list.style.right = "0";
    list.style.maxHeight = "180px";
    list.style.overflowY = "auto";
    list.style.background = "#0f172a";
    list.style.border = "1px solid #334155";
    list.style.borderRadius = "6px";
    list.style.zIndex = "100";
    list.style.display = "none";
    list.style.marginTop = "2px";

    wrap.appendChild(input);
    wrap.appendChild(list);

    function renderList(filter) {
      list.innerHTML = "";
      const q = (filter || "").toLowerCase().trim();
      const filtered = currentAssetHosts.filter((h) => {
        if (!q) return true;
        const search = `${h.ip} ${h.hostname} ${h.os_guess}`.toLowerCase();
        return search.includes(q);
      });
      if (filtered.length === 0) {
        const empty = document.createElement("div");
        empty.className = "muted";
        empty.style.padding = "6px 8px";
        empty.style.fontSize = "12px";
        empty.textContent = q ? "No matching assets" : "No assets";
        list.appendChild(empty);
      }
      filtered.forEach((h) => {
        const opt = document.createElement("div");
        opt.style.padding = "6px 8px";
        opt.style.cursor = "pointer";
        opt.style.fontSize = "12px";
        opt.style.borderBottom = "1px solid #1e293b";
        opt.style.color = String(h.id) === String(selectedId) ? "#60a5fa" : "#cbd5e1";
        const label = `${h.ip}`;
        const sub = `${h.hostname} ${h.os_guess}`.trim();
        opt.innerHTML = `<div>${escapeHtml(label)}</div>${sub ? `<div class="muted" style="font-size:10px;">${escapeHtml(sub)}</div>` : ""}`;
        opt.addEventListener("click", () => {
          input.value = `${h.ip} ${h.hostname}`.trim();
          list.style.display = "none";
          onAssetSelect(targetNode, h.id);
        });
        opt.addEventListener("mouseenter", () => { opt.style.background = "#1e293b"; });
        opt.addEventListener("mouseleave", () => { opt.style.background = ""; });
        list.appendChild(opt);
      });
    }

    function showList() {
      list.style.display = "block";
      renderList(input.value);
    }

    function hideList() {
      list.style.display = "none";
    }

    input.addEventListener("focus", showList);
    input.addEventListener("input", () => {
      showList();
    });
    input.addEventListener("blur", () => {
      setTimeout(hideList, 150);
    });

    renderList(input.value);

    return { wrap, input, list, showList, hideList, renderList };
  }

  async function onAssetSelect(targetNode, assetId) {
    const newId = String(assetId || "");
    targetNode.data("linked_asset_id", newId);
    queueSave();
    await renderAssetInfo(targetNode, newId);
  }

  function buildNamesCombobox(targetNode, selectedId) {
    const wrapId = "topoNameWrap";
    const inputId = "topoNameInput";
    const listId = "topoNameList";

    const currentName = allNamesCache.find((n) => String(n.id) === String(selectedId));
    const displayVal = currentName
      ? `${currentName.first_name} ${currentName.middle_name} ${currentName.last_name}`.trim()
      : "";

    const wrap = document.createElement("div");
    wrap.id = wrapId;
    wrap.style.position = "relative";

    const input = document.createElement("input");
    input.id = inputId;
    input.type = "text";
    input.placeholder = "Type name to filter...";
    input.value = displayVal;
    input.autocomplete = "off";

    const list = document.createElement("div");
    list.id = listId;
    list.style.position = "absolute";
    list.style.top = "100%";
    list.style.left = "0";
    list.style.right = "0";
    list.style.maxHeight = "180px";
    list.style.overflowY = "auto";
    list.style.background = "#0f172a";
    list.style.border = "1px solid #334155";
    list.style.borderRadius = "6px";
    list.style.zIndex = "100";
    list.style.display = "none";
    list.style.marginTop = "2px";

    wrap.appendChild(input);
    wrap.appendChild(list);

    function renderList(filter) {
      list.innerHTML = "";
      const q = (filter || "").toLowerCase().trim();
      const filtered = allNamesCache.filter((n) => {
        if (!q) return true;
        const search = `${n.first_name} ${n.middle_name} ${n.last_name} ${n.email} ${n.ad_username}`.toLowerCase();
        return search.includes(q);
      });
      if (filtered.length === 0) {
        const empty = document.createElement("div");
        empty.className = "muted";
        empty.style.padding = "6px 8px";
        empty.style.fontSize = "12px";
        empty.textContent = q ? "No matching names" : "No names";
        list.appendChild(empty);
      }
      filtered.forEach((n) => {
        const opt = document.createElement("div");
        opt.style.padding = "6px 8px";
        opt.style.cursor = "pointer";
        opt.style.fontSize = "12px";
        opt.style.borderBottom = "1px solid #1e293b";
        opt.style.color = String(n.id) === String(selectedId) ? "#60a5fa" : "#cbd5e1";
        const fullName = `${n.first_name} ${n.middle_name} ${n.last_name}`.trim();
        const sub = [n.email, n.ad_username].filter(Boolean).join(" · ");
        opt.innerHTML = `<div>${escapeHtml(fullName)}</div>${sub ? `<div class="muted" style="font-size:10px;">${escapeHtml(sub)}</div>` : ""}`;
        opt.addEventListener("click", () => {
          input.value = fullName;
          list.style.display = "none";
          onNameSelect(targetNode, n.id);
        });
        opt.addEventListener("mouseenter", () => { opt.style.background = "#1e293b"; });
        opt.addEventListener("mouseleave", () => { opt.style.background = ""; });
        list.appendChild(opt);
      });
    }

    function showList() {
      list.style.display = "block";
      renderList(input.value);
    }

    function hideList() {
      list.style.display = "none";
    }

    input.addEventListener("focus", showList);
    input.addEventListener("input", () => {
      showList();
    });
    input.addEventListener("blur", () => {
      setTimeout(hideList, 150);
    });

    renderList(input.value);

    return { wrap, input, list, showList, hideList, renderList };
  }

  async function onNameSelect(targetNode, nameId) {
    const newId = String(nameId || "");
    targetNode.data("linked_name_id", newId);
    queueSave();
    await renderNameInfo(targetNode, newId);
  }

  async function renderNameInfo(node, nameId) {
    const infoDiv = document.getElementById("topoNameInfo");
    if (!infoDiv) return;

    if (!nameId) {
      infoDiv.innerHTML = '<div class="muted" style="margin-top:4px;">No name linked</div>';
      return;
    }

    const name = allNamesCache.find((n) => String(n.id) === String(nameId));
    if (!name) {
      infoDiv.innerHTML = '<div class="muted" style="margin-top:4px;">Name not found</div>';
      return;
    }

    const fullName = `${name.first_name} ${name.middle_name} ${name.last_name}`.trim();
    let html = `
      <div style="margin-top:4px; padding:8px; background:#0f172a; border-radius:8px; border:1px solid #2a3545;">
        <div style="font-weight:600; margin-bottom:4px;">${escapeHtml(fullName)}</div>
    `;
    if (name.email) html += `<div style="font-size:11px; margin-top:2px;">📧 ${escapeHtml(name.email)}</div>`;
    if (name.phone) html += `<div style="font-size:11px; margin-top:2px;">📞 ${escapeHtml(name.phone)}</div>`;
    if (name.ad_username) html += `<div style="font-size:11px; margin-top:2px;">🔑 ${escapeHtml(name.ad_username)}</div>`;
    html += `</div>`;
    infoDiv.innerHTML = html;
  }

  async function renderAssetInfo(node, assetId) {
    const infoDiv = document.getElementById("topoAssetInfo");
    if (!infoDiv) return;

    if (!assetId) {
      infoDiv.innerHTML = '<div class="muted" style="margin-top:4px;">No asset linked</div>';
      return;
    }

    infoDiv.innerHTML = '<div class="muted" style="margin-top:4px;">Loading asset info...</div>';

    try {
      const r = await fetch(`/api/host/${assetId}`);
      const j = await r.json();
      if (!j.ok) {
        infoDiv.innerHTML = '<div class="muted" style="margin-top:4px;">Asset not found</div>';
        return;
      }

      const host = j.host || {};
      const services = j.services || [];
      const notes = j.notes || [];

      let html = `
        <div style="margin-top:4px; padding:8px; background:#0f172a; border-radius:8px; border:1px solid #2a3545;">
          <div style="font-weight:600; margin-bottom:4px;">${escapeHtml(host.ip)} ${escapeHtml(host.hostname)}</div>
          ${host.os_guess ? `<div class="muted" style="font-size:11px;">${escapeHtml(host.os_guess)}</div>` : ""}
      `;

      if (services.length) {
        html += `<div style="margin-top:8px; font-size:12px; font-weight:600;">Ports (${services.length})</div>`;
        html += `<table style="width:100%; margin-top:4px; font-size:11px; border-collapse:collapse;">`;
        html += `<tr style="border-bottom:1px solid #2a3545;"><th style="text-align:left;padding:2px 4px;color:#94a3b8;">Port</th><th style="text-align:left;padding:2px 4px;color:#94a3b8;">Proto</th><th style="text-align:left;padding:2px 4px;color:#94a3b8;">State</th><th style="text-align:left;padding:2px 4px;color:#94a3b8;">Service</th></tr>`;
        services.forEach((s) => {
          const stateColor = s.state === "open" ? "#4ade80" : s.state === "filtered" ? "#fbbf24" : "#94a3b8";
          html += `<tr style="border-bottom:1px solid #1e293b;">`;
          html += `<td style="padding:2px 4px;"><code>${s.port}</code></td>`;
          html += `<td style="padding:2px 4px;">${escapeHtml(s.proto)}</td>`;
          html += `<td style="padding:2px 4px; color:${stateColor};">${escapeHtml(s.state)}</td>`;
          html += `<td style="padding:2px 4px;">${escapeHtml(s.service_name)}${s.product ? ` <span class="muted">${escapeHtml(s.product)}</span>` : ""}</td>`;
          html += `</tr>`;
        });
        html += `</table>`;
      }

      if (notes.length) {
        html += `<div style="margin-top:8px; font-size:12px; font-weight:600;">Notes (${notes.length})</div>`;
        notes.forEach((n) => {
          const sevColors = { info: "#60a5fa", low: "#a3e635", med: "#fbbf24", high: "#f87171" };
          const sevColor = sevColors[(n.severity || "info").toLowerCase()] || "#60a5fa";
          html += `<div style="margin-top:4px; padding:6px; background:#0b1220; border-radius:6px; border-left:3px solid ${sevColor};">`;
          html += `<div style="font-size:10px; color:${sevColor}; text-transform:uppercase; font-weight:600;">${escapeHtml(n.severity || "info")}</div>`;
          html += `<div style="font-size:11px; margin-top:2px; white-space:pre-wrap;">${escapeHtml(n.body)}</div>`;
          if (n.tags) {
            html += `<div style="font-size:10px; color:#64748b; margin-top:2px;">${escapeHtml(n.tags)}</div>`;
          }
          html += `</div>`;
        });
      }

      if (!services.length && !notes.length) {
        html += `<div class="muted" style="margin-top:6px; font-size:11px;">No ports or notes</div>`;
      }

      html += `</div>`;
      infoDiv.innerHTML = html;

    } catch (e) {
      infoDiv.innerHTML = '<div class="muted" style="margin-top:4px;">Failed to load asset info</div>';
    }
  }

  function renderInspector(node) {
    if (!node || !node.isNode()) {
      inspector.innerHTML = '<span class="muted">Click a node to edit label, notes, color, and compromise state.</span>';
      inspectorWrap.style.display = "none";
      currentAssetHosts = [];
      return;
    }
    inspectorWrap.style.display = "block";
    const d = node.data();
    const linkedAssetId = d.linked_asset_id || "";
    const linkedNameId = d.linked_name_id || "";

    const isDomain = d.type === "domain";
    const isUser = d.type === "user";
    const registrarSection = isDomain ? `
      <div style="margin-top:12px; padding-top:10px; border-top:1px solid #1e2630;">
        <label>ASN</label>
        <input id="topoAsn" value="${escapeHtml(d.asn || "")}" placeholder="e.g., AS15169" />
        <label style="margin-top:8px;">Registrar</label>
        <input id="topoRegistrar" value="${escapeHtml(d.registrar || "")}" placeholder="e.g., GoDaddy" />
        <label style="margin-top:8px;">Netblocks</label>
        <input id="topoNetblocks" value="${escapeHtml(d.netblocks || "")}" placeholder="192.0.2.0/24,198.51.100.0/24" />
        <label style="margin-top:8px;">Subdomains &amp; IPs</label>
        <textarea id="topoSubdomainIps" rows="5" style="resize:vertical;" placeholder="www.example.com 93.184.216.34">${escapeHtml(d.subdomain_ips || "")}</textarea>
      </div>
    ` : "";
    const userSection = isUser ? `
      <div style="margin-top:12px; padding-top:10px; border-top:1px solid #1e2630;">
        <label>Email</label>
        <input id="topoEmail" value="${escapeHtml(d.email || "")}" placeholder="user@example.com" />
        <label style="margin-top:8px;">Phone</label>
        <input id="topoPhone" value="${escapeHtml(d.phone || "")}" placeholder="+1 (555) 123-4567" />
      </div>
    ` : "";

    inspector.innerHTML = `
      <label>Label</label>
      <input id="topoLabel" value="${escapeHtml(d.label || "")}" />
      <label style="margin-top:8px;">Color</label>
      <input id="topoColor" type="color" value="${escapeHtml(d.color || "#1f6feb")}" />
      <label class="checkbox-label" style="margin-top:10px;">
        <input id="topoCompromised" type="checkbox" ${d.compromised ? "checked" : ""} />
        Mark as compromised
      </label>
      <br/>
      ${isUser
        ? `<label style="margin-top:8px;">Link Name</label>
           <div id="topoNameSelector"></div>
           <div id="topoNameInfo"></div>`
        : `<label style="margin-top:8px;">Link Asset</label>
           <div id="topoAssetSelector"></div>
           <div id="topoAssetInfo"></div>`}
      ${registrarSection}
      ${userSection}
      <label style="margin-top:8px;">Notes</label>
      <textarea id="topoNotes" rows="6" style="resize:vertical;">${escapeHtml(d.notes || "")}</textarea>
      <div class="muted" style="margin-top:8px;">Tip: Drag the small orange bubble on a node to another node to create a link.</div>
    `;

    const labelEl = document.getElementById("topoLabel");
    const colorEl = document.getElementById("topoColor");
    const notesEl = document.getElementById("topoNotes");
    const compEl = document.getElementById("topoCompromised");
    const selectorDiv = document.getElementById("topoAssetSelector");

    function applyDisplay() {
      const icon = ICONS[node.data("type")] || "📍";
      node.data("display", `${icon}\n${node.data("label") || "Node"}`);
    }

    labelEl && labelEl.addEventListener("input", () => {
      node.data("label", labelEl.value || "Node");
      applyDisplay();
      adjustNodeSize(node);
      queueSave();
    });
    colorEl && colorEl.addEventListener("input", () => {
      node.data("color", colorEl.value || "#1f6feb");
      queueSave();
    });
    notesEl && notesEl.addEventListener("input", () => {
      node.data("notes", notesEl.value || "");
      refreshNoteIndicator(node.id());
      queueSave();
    });
    compEl && compEl.addEventListener("change", () => {
      node.data("compromised", !!compEl.checked);
      updateNodeClass(node);
      queueSave();
    });

    const asnEl = document.getElementById("topoAsn");
    const registrarEl = document.getElementById("topoRegistrar");
    const netblocksEl = document.getElementById("topoNetblocks");
    const subdomainIpsEl = document.getElementById("topoSubdomainIps");

    asnEl && asnEl.addEventListener("input", () => {
      node.data("asn", asnEl.value || "");
      queueSave();
    });
    registrarEl && registrarEl.addEventListener("input", () => {
      node.data("registrar", registrarEl.value || "");
      queueSave();
    });
    netblocksEl && netblocksEl.addEventListener("input", () => {
      node.data("netblocks", netblocksEl.value || "");
      queueSave();
    });
    subdomainIpsEl && subdomainIpsEl.addEventListener("input", () => {
      node.data("subdomain_ips", subdomainIpsEl.value || "");
      queueSave();
    });

    const emailEl = document.getElementById("topoEmail");
    const phoneEl = document.getElementById("topoPhone");
    emailEl && emailEl.addEventListener("input", () => {
      node.data("email", emailEl.value || "");
      queueSave();
    });
    phoneEl && phoneEl.addEventListener("input", () => {
      node.data("phone", phoneEl.value || "");
      queueSave();
    });

    (async () => {
      if (isUser) {
        const names = await loadNames();
        allNamesCache = names;
        const nameSelectorDiv = document.getElementById("topoNameSelector");
        if (nameSelectorDiv) {
          const combo = buildNamesCombobox(node, linkedNameId);
          nameSelectorDiv.appendChild(combo.wrap);
          await renderNameInfo(node, linkedNameId);
        }
      } else {
        const hosts = await loadHosts();
        currentAssetHosts = hosts;
        if (selectorDiv) {
          const combo = buildAssetCombobox(node, linkedAssetId);
          selectorDiv.appendChild(combo.wrap);
          await renderAssetInfo(node, linkedAssetId);
        }
      }
    })();
  }

  function renderEdgeInspector(edge) {
    if (!edge || !edge.isEdge()) {
      inspector.innerHTML = '<span class="muted">Click a node to edit label, notes, color, and compromise state.</span>';
      inspectorWrap.style.display = "none";
      return;
    }
    inspectorWrap.style.display = "block";
    const d = edge.data();
    const currentArrow = d.arrowDirection || "target";
    const currentLine = d.lineStyle || "solid";

    inspector.innerHTML = `
      <label>Label</label>
      <input id="edgeLabel" value="${escapeHtml(d.label || "")}" />
      <label style="margin-top:10px;">Arrow Direction</label>
      <select id="edgeArrowDir">
        <option value="none" ${currentArrow === "none" ? "selected" : ""}>↔ No Arrow</option>
        <option value="source" ${currentArrow === "source" ? "selected" : ""}>← Source</option>
        <option value="target" ${currentArrow === "target" ? "selected" : ""}>Target →</option>
        <option value="both" ${currentArrow === "both" ? "selected" : ""}>↔ Both</option>
      </select>
      <label style="margin-top:10px;">Line Style</label>
      <select id="edgeLineStyle">
        <option value="solid" ${currentLine === "solid" ? "selected" : ""}>──── Solid</option>
        <option value="dashed" ${currentLine === "dashed" ? "selected" : ""}>- - - Dashed</option>
        <option value="dotted" ${currentLine === "dotted" ? "selected" : ""}>· · · Dotted</option>
      </select>
      <div class="muted" style="margin-top:12px;">${escapeHtml(edge.source().data("label") || edge.source().id())} → ${escapeHtml(edge.target().data("label") || edge.target().id())}</div>
      <div class="muted" style="margin-top:4px;">Right-click to delete this link.</div>
    `;

    const labelEl = document.getElementById("edgeLabel");
    const arrowEl = document.getElementById("edgeArrowDir");
    const lineEl = document.getElementById("edgeLineStyle");

    labelEl && labelEl.addEventListener("input", () => {
      edge.data("label", labelEl.value || "");
      queueSave();
    });
    arrowEl && arrowEl.addEventListener("change", () => {
      edge.data("arrowDirection", arrowEl.value);
      queueSave();
    });
    lineEl && lineEl.addEventListener("change", () => {
      edge.data("lineStyle", lineEl.value);
      queueSave();
    });
  }

  function escapeHtml(s) {
    return String(s || "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function measureLabelWidth(text) {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    ctx.font = "14px sans-serif";
    const lines = text.split("\n");
    let maxW = 0;
    lines.forEach((line) => {
      const m = ctx.measureText(line);
      if (m.width > maxW) maxW = m.width;
    });
    return maxW;
  }

  function adjustNodeSize(node) {
    const display = node.data("display") || "";
    const labelW = measureLabelWidth(display);
    const minW = 120;
    const padding = 24;
    const newW = Math.max(minW, Math.ceil(labelW + padding));
    node.style("width", String(newW));
    node.style("text-max-width", String(newW - 16));
  }

  cy.nodes().forEach(updateNodeClass);
  ensureAllHandles();
  ensureAllNoteIndicators();
  realNodes().forEach((n) => refreshFloatingNotes(n.id()));
  realNodes().filter((n) => n.data("type") !== "domain").forEach(adjustNodeSize);
  cy.on("tap", "node", (evt) => {
    let node = evt.target;
    if (isVirtualNode(node)) {
      const ownerId = node.data("owner");
      if (ownerId) {
        const owner = cy.getElementById(ownerId);
        if (owner && owner.length) node = owner;
        else return;
      } else {
        return;
      }
    }
    renderInspector(node);
  });

  cy.on("tap", "edge", (evt) => {
    const edge = evt.target;
    if (edge.hasClass("draft")) return;
    renderEdgeInspector(edge);
  });

  cy.on("tap", (evt) => {
    if (evt.target === cy) renderInspector(null);
  });

  cy.on("mouseover", 'node[type = "note_indicator"]', (evt) => {
    const ind = evt.target;
    const notes = ind.data("notes") || "";
    if (!notes.trim()) return;
    const oe = evt.originalEvent || {};
    showNotesTooltip(oe.clientX || 200, oe.clientY || 200, notes);
  });

  cy.on("mouseout", 'node[type = "note_indicator"]', () => {
    hideNotesTooltip();
  });

  cy.on("mousemove", 'node[type = "note_indicator"]', (evt) => {
    const oe = evt.originalEvent || {};
    notesTooltip.style.left = `${Math.min(oe.clientX + 14, window.innerWidth - 340)}px`;
    notesTooltip.style.top = `${Math.min(oe.clientY - 10, window.innerHeight - 260)}px`;
  });

  cy.on("dragfree", "node", (evt) => {
    const n = evt.target;
    if (!isVirtualNode(n)) {
      syncHandlePosition(n.id());
      syncBadgePosition(n.id());
      syncNoteIndicatorPosition(n.id());
      refreshFloatingNotes(n.id());
      saveNow();
    }
  });

  cy.on("drag", "node", (evt) => {
    const n = evt.target;
    if (!isVirtualNode(n)) {
      syncHandlePosition(n.id());
      syncBadgePosition(n.id());
      syncNoteIndicatorPosition(n.id());
      refreshFloatingNotes(n.id());
    }
  });

  cy.on("add", "node", (evt) => {
    const n = evt.target;
    if (!isVirtualNode(n)) {
      ensureHandle(n.id());
      ensureNoteIndicator(n.id());
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
      removeNoteIndicator(n.id());
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
        cy.add({
          group: "edges",
          data: {
            id: `e${nextEdgeId++}`,
            source: ownerId,
            target: target.id(),
            label: "",
            arrowDirection: "target",
            lineStyle: "solid",
          },
        });
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

  cy.on("mouseover", "node", (evt) => {
    const n = evt.target;
    if (isVirtualNode(n) || isHandle(n) || isBadge(n) || isNoteIndicator(n)) return;
    const h = cy.getElementById(handleIdFor(n.id()));
    if (h && h.length) h.style("opacity", 0.9);
    const ind = cy.getElementById(noteIndicatorIdFor(n.id()));
    if (ind && ind.length) {
      ind.style("opacity", 0.9);
      ind.style("z-index", 10003);
    }
  });
  cy.on("mouseout", "node", (evt) => {
    const n = evt.target;
    if (isVirtualNode(n) || isHandle(n) || isBadge(n) || isNoteIndicator(n)) return;
    const h = cy.getElementById(handleIdFor(n.id()));
    if (h && h.length) h.style("opacity", 0);
    const ind = cy.getElementById(noteIndicatorIdFor(n.id()));
    if (ind && ind.length) {
      ind.style("opacity", 0.5);
      ind.style("z-index", 10002);
    }
  });

  const fitBtn = document.getElementById("fitView");
  fitBtn && fitBtn.addEventListener("click", () => cy.fit(undefined, 40));

  const closeBtn = document.getElementById("topoCloseInspector");
  closeBtn && closeBtn.addEventListener("click", () => {
    inspectorWrap.style.display = "none";
    cy.elements().unselect();
  });

  if (cy.nodes().length) {
    cy.fit(undefined, 40);
    cy.nodes('node[type = "handle"]').forEach((h) => h.style("opacity", 0));
    cy.nodes('node[type = "note_indicator"]').forEach((ind) => ind.style("opacity", 0.5));
    realNodes().filter((n) => n.data("compromised")).forEach((n) => n.style("border-color", "#991b1b"));
  }

  // Smooth red pulse for compromised nodes (paused when tab is hidden)
  let pulsePhase = 0;
  let pulseRAF = null;
  function stepPulse() {
    pulsePhase += 0.035;
    const t = (Math.sin(pulsePhase) + 1) / 2;
    const r = Math.round(153 + t * 102);
    const g = Math.round(27 + t * 85);
    const b = Math.round(27 + t * 85);
    const color = `#${r.toString(16).padStart(2, "0")}${g.toString(16).padStart(2, "0")}${b.toString(16).padStart(2, "0")}`;
    realNodes().filter((n) => n.data("compromised")).forEach((n) => {
      n.style("border-color", color);
    });
    pulseRAF = requestAnimationFrame(stepPulse);
  }
  pulseRAF = requestAnimationFrame(stepPulse);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      cancelAnimationFrame(pulseRAF);
      pulseRAF = null;
    } else if (!pulseRAF) {
      pulseRAF = requestAnimationFrame(stepPulse);
    }
  });
})();
