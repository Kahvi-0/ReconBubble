(async function () {
  const canvas = document.getElementById("graph");
  const ctx = canvas.getContext("2d");
  const inspector = document.getElementById("inspector");
  const checkbox = document.getElementById("onlyInScope");

  function resizeCanvas() {
    const rect = canvas.getBoundingClientRect();
    canvas.width = Math.floor(rect.width * devicePixelRatio);
    canvas.height = Math.floor(rect.height * devicePixelRatio);
    ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
  }
  window.addEventListener("resize", resizeCanvas);
  resizeCanvas();

  const url = new URL(window.location.href);
  if (checkbox) checkbox.checked = url.searchParams.get("only_in_scope") === "true";
  if (checkbox) checkbox.addEventListener("change", () => {
    url.searchParams.set("only_in_scope", checkbox.checked ? "true" : "false");
    window.location.href = url.toString();
  });

  async function loadGraph() {
    const only = checkbox && checkbox.checked ? "true" : "false";
    const resp = await fetch("/api/graph?only_in_scope=" + only);
    return await resp.json();
  }

  const data = await loadGraph();
  
  const centerX = 450, centerY = 300;
  const nodes = data.nodes.map((n, i) => {
    const angle = (2 * Math.PI * i) / data.nodes.length;
    const radius = 120;
    return {
      ...n, 
      x: centerX + Math.cos(angle) * radius + (Math.random() - 0.5) * 40,
      y: centerY + Math.sin(angle) * radius + (Math.random() - 0.5) * 40,
      vx: 0, vy: 0,
      r: n.type === "domain" ? 16 : (n.type === "host" ? 14 : 11)
    };
  });
  
  const nodeById = new Map(nodes.map(n => [n.id, n]));
  const edges = data.edges.map(e => ({...e, a: nodeById.get(e.from), b: nodeById.get(e.to)})).filter(e => e.a && e.b);

  const colors = {
    domain_in: "#22c55e", domain_out: "#ef4444",
    subdomain_in: "#22c55e", subdomain_out: "#ef4444",
    host_in: "#22c55e", host_out: "#ef4444",
    service_in: "#22c55e", service_out: "#ef4444"
  };
  const baseColors = { domain: "#7bd", subdomain: "#9ad", host: "#f8b", service: "#9f9" };

  let scale = 1, panX = 0, panY = 0, draggingNode = null, draggingPan = false, lastMouse = null, selected = null;

  function worldToScreen(x, y) { return { x: x * scale + panX, y: y * scale + panY }; }
  function screenToWorld(x, y) { return { x: (x - panX) / scale, y: (y - panY) / scale }; }

  function centerView() {
    panX = canvas.width / devicePixelRatio / 2 - centerX * scale;
    panY = canvas.height / devicePixelRatio / 2 - centerY * scale;
    scale = 1;
  }
  centerView();

  canvas.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const d = Math.sign(ev.deltaY) * -0.1;
    scale = Math.min(2.5, Math.max(0.35, scale + d));
  }, { passive: false });

  canvas.addEventListener("mousedown", (ev) => {
    const r = canvas.getBoundingClientRect();
    const mx = ev.clientX - r.left, my = ev.clientY - r.top;
    lastMouse = { x: mx, y: my };
    const w = screenToWorld(mx, my);
    draggingNode = pick(w.x, w.y);
    if (!draggingNode) draggingPan = true;
  });

  window.addEventListener("mouseup", () => { draggingNode = null; draggingPan = false; lastMouse = null; });

  window.addEventListener("mousemove", (ev) => {
    if (!lastMouse) return;
    const r = canvas.getBoundingClientRect();
    const mx = ev.clientX - r.left, my = ev.clientY - r.top;
    const dx = mx - lastMouse.x, dy = my - lastMouse.y;
    if (draggingNode) {
      const w = screenToWorld(mx, my);
      draggingNode.x = w.x;
      draggingNode.y = w.y;
      draggingNode.vx = 0;
      draggingNode.vy = 0;
    } else if (draggingPan) {
      panX += dx;
      panY += dy;
    }
    lastMouse = { x: mx, y: my };
  });

  canvas.addEventListener("click", (ev) => {
    const r = canvas.getBoundingClientRect();
    const mx = ev.clientX - r.left, my = ev.clientY - r.top;
    const w = screenToWorld(mx, my);
    const n = pick(w.x, w.y);
    selected = n;
    if (n) {
      const scope = n.in_scope ? '<span class="pill inscope">IN</span>' : '<span class="pill outscope">OUT</span>';
      const openBtn = (n.type === "host" && n.host_id) ? `<button class="btn" id="openHost">Open asset</button>` :
                      (n.type === "service" && n.service_id) ? `<button class="btn" id="openSvc">Open service</button>` : "";
      inspector.innerHTML = `
        <div><b>Type:</b> ${esc(n.type)}</div>
        <div><b>Scope:</b> ${scope}</div>
        <div><b>Label:</b><br/><code>${esc(n.label)}</code></div>
        <div style="margin-top:10px;">${openBtn}</div>
      `;
      const oh = document.getElementById("openHost");
      if (oh) oh.addEventListener("click", () => window.ReconSidebar && window.ReconSidebar.openHost(n.host_id));
      const os = document.getElementById("openSvc");
      if (os) os.addEventListener("click", () => window.ReconSidebar && window.ReconSidebar.openService(n.service_id));
    } else inspector.textContent = "Click a node…";
  });

  function pick(x, y) {
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i], dx = x - n.x, dy = y - n.y;
      if (Math.sqrt(dx * dx + dy * dy) <= n.r) return n;
    }
    return null;
  }

  function esc(s) { return ("" + s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

  function step() {
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy + 0.01;
        let f = 80 / d2;
        a.vx += dx * f;
        a.vy += dy * f;
        b.vx -= dx * f;
        b.vy -= dy * f;
      }
    }
    for (const e of edges) {
      const a = e.a, b = e.b;
      const dx = b.x - a.x, dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) + 0.001;
      const desired = 80, k = 0.008;
      const f = k * (dist - desired);
      const fx = (dx / dist) * f, fy = (dy / dist) * f;
      a.vx += fx;
      a.vy += fy;
      b.vx -= fx;
      b.vy -= fy;
    }
    const cx = centerX, cy = centerY;
    for (const n of nodes) {
      n.vx += (cx - n.x) * 0.0003;
      n.vy += (cy - n.y) * 0.0003;
      n.vx *= 0.75;
      n.vy *= 0.75;
      n.x += n.vx;
      n.y += n.vy;
    }
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.globalAlpha = 0.6;
    ctx.lineWidth = 1;
    for (const e of edges) {
      const a = worldToScreen(e.a.x, e.a.y), b = worldToScreen(e.b.x, e.b.y);
      const inScope = e.a.in_scope && e.b.in_scope;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.strokeStyle = inScope ? "#1a3a2a" : "#2b1a1a";
      ctx.stroke();
    }
    ctx.globalAlpha = 1;
    for (const n of nodes) {
      const p = worldToScreen(n.x, n.y);
      const inScope = n.in_scope;
      const baseColor = colors[`${n.type}_${inScope ? 'in' : 'out'}`] || baseColors[n.type] || "#ddd";
      ctx.beginPath();
      ctx.arc(p.x, p.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = baseColor;
      ctx.fill();
      ctx.lineWidth = (selected && selected.id === n.id) ? 2.5 : 1.5;
      ctx.strokeStyle = (selected && selected.id === n.id) ? "#fff" : (inScope ? "#0b0d10" : "#3a1a1a");
      ctx.stroke();
      const label = (n.type === "service") ? n.label.split("\n")[0] : (n.label.split("\n")[0] || "");
      ctx.font = "11px ui-sans-serif, system-ui";
      ctx.fillStyle = inScope ? "#b8e8c8" : "#e8b8b8";
      ctx.fillText(label.slice(0, 22), p.x + n.r + 4, p.y + 4);
    }
  }

  function loop() { step(); draw(); requestAnimationFrame(loop); }
  loop();

  window.graphAPI = { centerView, zoomIn: () => scale = Math.min(2.5, scale + 0.2), zoomOut: () => scale = Math.max(0.35, scale - 0.2) };
})();
