/* v2 - fixed sidebar */
(function () {
  const overlay = document.getElementById("sidebarOverlay");
  const sidebar = document.getElementById("sidebar");
  const title = document.getElementById("sidebarTitle");
  const body = document.getElementById("sidebarBody");
  const closeBtn = document.getElementById("sidebarClose");
  const topoBtn = document.getElementById("sidebarTopologyBtn");
  let prevBodyOverflow = "";
  let prevHtmlOverflow = "";
  let scrollLockDepth = 0;

  function lockBackgroundScroll() {
    if (scrollLockDepth === 0) {
      prevBodyOverflow = document.body.style.overflow || "";
      prevHtmlOverflow = document.documentElement.style.overflow || "";
    }
    scrollLockDepth += 1;
    document.body.style.overflow = "hidden";
    document.documentElement.style.overflow = "hidden";
  }

  function unlockBackgroundScroll() {
    if (scrollLockDepth > 0) scrollLockDepth -= 1;
    if (scrollLockDepth > 0) return;
    document.body.style.overflow = prevBodyOverflow;
    document.documentElement.style.overflow = prevHtmlOverflow;
  }

  function resetBackgroundScroll() {
    scrollLockDepth = 0;
    document.body.style.overflow = prevBodyOverflow;
    document.documentElement.style.overflow = prevHtmlOverflow;
  }

  function show() {
    const wasHidden = overlay.classList.contains("hidden");
    overlay.classList.remove("hidden");
    sidebar.classList.remove("hidden");
    sidebar.setAttribute("aria-hidden", "false");
    if (wasHidden) lockBackgroundScroll();
  }
  function hide() {
    overlay.classList.add("hidden");
    sidebar.classList.add("hidden");
    sidebar.setAttribute("aria-hidden", "true");
    body.innerHTML = "";
    const existing = document.getElementById("sidebarBack");
    if (existing) existing.remove();
    if (topoBtn) {
      topoBtn.classList.add("hidden");
      topoBtn.onclick = null;
    }
    resetBackgroundScroll();
  }
  overlay && overlay.addEventListener("click", hide);
  closeBtn && closeBtn.addEventListener("click", hide);
  window.addEventListener("keydown", (e) => { if (e.key === "Escape") hide(); });

  const sidebarScreenshotPollers = new Set();
  const refreshSidebarScreenshotPollers = () => {
    if (document.hidden) return;
    sidebarScreenshotPollers.forEach((fn) => fn());
  };
  window.addEventListener("visibilitychange", () => {
    if (!document.hidden) refreshSidebarScreenshotPollers();
  });
  window.addEventListener("focus", refreshSidebarScreenshotPollers);

  function esc(s) { return (""+s).replace(/[&<>"']/g,c=>({ "&":"&amp;","<":"&gt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c])); }

  
function bindTagHandlers() {
  document.querySelectorAll("[data-tag-del]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const hostId = btn.getAttribute("data-host-id");
      const tag = btn.getAttribute("data-tag");
      if (!confirm(`Delete tag "${tag}"?`)) return;
      const fd = new FormData();
      fd.append("host_id", hostId);
      fd.append("tag", tag);
      const r = await fetch("/api/host/tag/delete", { method: "POST", body: fd });
      if (r.ok) {
        openHost(parseInt(hostId, 10));
      } else {
        alert("Failed to delete tag.");
      }
    });
  });
}

  function bindNoteHandlers() {
    const noteForm = document.getElementById("sidebarNoteAddForm");
    const noteMsg = document.getElementById("sidebarNoteAddMsg");
    if (noteForm) {
      noteForm.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        noteMsg.textContent = "Saving...";
        const fd = new FormData(noteForm);
        const r = await fetch("/api/note/add", { method: "POST", body: fd });
        const j = await r.json().catch(() => ({ ok: false }));
        if (j.ok) {
          noteMsg.textContent = "Saved.";
          noteForm.reset();
          const hostId = noteForm.querySelector('input[name="object_id"]').value;
          setTimeout(() => openHost(parseInt(hostId, 10)), 300);
        } else {
          noteMsg.textContent = j.error || "Failed to save note.";
        }
      });
    }

    document.querySelectorAll("[data-note-del]").forEach(btn => {
      btn.addEventListener("click", async () => {
        if (!confirm("Delete this note?")) return;
        const fd = new FormData();
        fd.append("note_id", btn.getAttribute("data-note-del"));
        await fetch("/api/note/delete", { method: "POST", body: fd });
        const hostId = document.querySelector('input[name="object_id"]');
        if (hostId) {
          openHost(parseInt(hostId.value, 10));
        }
      });
    });
  }

  async function openHostCreate() {
    const backBtnCreate = document.getElementById("sidebarBack");
    if (backBtnCreate) backBtnCreate.style.display = "none";
    title.textContent = "Create asset";
    body.innerHTML = `
      <div class="card">
        <h2>New asset</h2>
        <form id="hostCreateForm">
          <label>IP Address</label>
          <input name="ip" placeholder="192.168.1.1" required />
          <label style="margin-top:8px;">Hostname</label>
          <input name="hostname" placeholder="server.example.com"/>
          <label style="margin-top:8px;">Tag</label>
          <input name="tag" placeholder="e.g., pivot, critical, external"/>
          <label style="margin-top:8px;">Associate domains/subdomains (one per line)</label>
          <textarea name="domains_raw" rows="6" placeholder="app.example.com"></textarea>
          <button class="btn" type="submit" style="margin-top:12px;">Create</button>
          <div id="hostCreateMsg" class="muted" style="margin-top:8px;"></div>
        </form>
      </div>
    `;
    show();

    const form = document.getElementById("hostCreateForm");
    const msg = document.getElementById("hostCreateMsg");
    form && form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      msg.textContent = "Creating...";
      msg.style.color = "";
      const fd = new FormData(form);
      const r = await fetch("/api/host/create", { method: "POST", body: fd });
      const j = await r.json().catch(() => ({ ok: false }));
      if (j.ok) {
        msg.textContent = "Created. Refreshing…";
        setTimeout(() => location.reload(), 450);
      } else {
        msg.textContent = j.error || "Create failed.";
        msg.style.color = "#f87171";
      }
    });
  }

  async function openHost(hostId) {
    const resp = await fetch(`/api/host/${hostId}`, { cache: "no-store" });
    if (!resp.ok) return;
    const data = await resp.json();

    // Severity tint (based on highest note severity)
    try {
      sidebar.classList.remove("sev-info","sev-low","sev-med","sev-high");
      if (data && data.highest_severity) sidebar.classList.add("sev-" + data.highest_severity);
    } catch (e) {}
    if (!data.ok) return;

    const backBtnHost = document.getElementById("sidebarBack");
    if (backBtnHost) backBtnHost.style.display = "none";
    title.textContent = `Asset ${data.host.ip}`;
    body.innerHTML = `
      <div class="card">
        <h2>Edit asset</h2>
        <form id="sidebarHostUpdateForm">
          <input type="hidden" name="host_id" value="${data.host.id}"/>
          <label>IP</label>
          <input name="ip" value="${esc(data.host.ip)}" required />
          <label>Hostname</label>
          <input name="hostname" value="${esc(data.host.hostname || "")}" />
          <label>Tag</label>
          <input name="tag" value="${esc(data.host.tag || "")}" placeholder="e.g., pivot, critical, external"/>
          <label>OS Guess</label>
          <input name="os_guess" value="${esc(data.host.os_guess || "")}" />
          <label>Associate domains/subdomains (one per line)</label>
          <textarea name="domains_raw" rows="6" placeholder="app.example.com">${esc((data.domains||[]).join("\n"))}</textarea>
          <button class="btn" type="submit">Save</button>
          <div id="sidebarHostUpdateMsg" class="muted" style="margin-top:8px;"></div>
        </form>
      </div>

<div class="card">
  <h2>Notes</h2>
  <form id="sidebarNoteAddForm" method="post" action="/api/note/add">
    <input type="hidden" name="object_type" value="host"/>
    <input type="hidden" name="object_id" value="${data.host.id}"/>
    <label>Severity</label>
    <select name="severity">
      <option value="info">info</option>
      <option value="low">low</option>
      <option value="med">med</option>
      <option value="high">high</option>
    </select>
    <label style="margin-top:8px;">Tags</label>
    <input name="tags" placeholder="vpn, external, priority"/>
    <label style="margin-top:8px;">Note</label>
    <textarea name="body" rows="5" required></textarea>
    <button class="btn" type="submit" style="margin-top:10px;">Save note</button>
    <div id="sidebarNoteAddMsg" class="muted" style="margin-top:8px;"></div>
  </form>

  <div style="margin-top:14px;">
    ${(data.notes||[]).length ? (data.notes.map(n => `
      <div class="card" style="margin:10px 0;">
        <div class="muted">${esc(n.created_at)} · <b>${esc(n.severity)}</b> · ${esc(n.tags||"")}</div>
        <pre class="note">${esc(n.body||"")}</pre>
        <button class="btn btn-small" data-note-del="${n.id}" type="button" style="margin-top:8px;">Delete</button>
      </div>
    `).join("")) : `<p class="muted">No notes yet.</p>`}
  </div>
</div>

      <div class="card">
        <h2>Services</h2>
        <button class="btn" id="sidebarCreateServiceBtn" type="button" style="margin-bottom:10px;">Add service</button>
        ${ (data.services||[]).length ? `
          <table>
            <thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th></tr></thead>
            <tbody>
              ${(data.services||[]).map(s => `
                <tr>
                  <td><a href="#" data-open-service="${s.id}">${s.port}</a></td>
                  <td>${esc(s.proto)}</td>
                  <td>${esc(s.state)}</td>
                  <td>${esc(s.service_name || "")}</td>
                </tr>`).join("")}
            </tbody>
          </table>` : `<div class="muted">No services stored.</div>`}
      </div>
    `;
    show();
    bindNoteHandlers();

    /* ----- Add to Attack Topology ----- */
    const onAssetPage = window.location.pathname.startsWith("/assets");
    if (topoBtn && onAssetPage) {
      topoBtn.classList.remove("hidden");
      topoBtn.classList.remove("btn--disabled");
      const h = data.host;
      const alreadyInTopology = async () => {
        try {
          const r = await fetch("/api/topology", { cache: "no-store" });
          if (!r.ok) return false;
          const j = await r.json();
          if (!j.ok) return false;
          const nodes = (j.map && j.map.nodes) || [];
          return nodes.some((n) => n.linked_asset_id == h.id);
        } catch {
          return false;
        }
      };
      const setDisabled = (disabled) => {
        topoBtn.disabled = disabled;
        topoBtn.classList.toggle("btn--disabled", disabled);
      };
      const isDuplicate = await alreadyInTopology();
      if (isDuplicate) {
        topoBtn.textContent = "Already in Attack Topology";
        setDisabled(true);
        topoBtn.onclick = null;
      } else {
        setDisabled(false);
        topoBtn.textContent = "Add to Attack Topology";
        topoBtn.onclick = async () => {
          try {
            topoBtn.disabled = true;
            topoBtn.textContent = "Adding...";
            const r = await fetch("/api/topology/add-node", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                asset_id: h.id,
                hostname: h.hostname || "",
                ip: h.ip || "",
              }),
            });
            if (r.ok) {
              topoBtn.textContent = "Already in Attack Topology";
              setDisabled(true);
            } else {
              const err = await r.json().catch(() => ({}));
              alert(err.detail || "Failed to add node");
              topoBtn.textContent = "Add to Attack Topology";
              setDisabled(false);
            }
          } catch (e) {
            alert("Error: " + e.message);
            topoBtn.textContent = "Add to Attack Topology";
            setDisabled(false);
          }
        };
      }
    }

    const form = document.getElementById("sidebarHostUpdateForm");
    const msg = document.getElementById("sidebarHostUpdateMsg");
    form && form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      msg.textContent = "Saving...";
      msg.style.color = "";
      const fd = new FormData(form);
      const r = await fetch("/api/host/update", { method: "POST", body: fd });
      const j = await r.json().catch(()=>({ok:false}));
      if (j.ok) {
        msg.textContent = "Saved.";
        const savedHostId = data.host.id;
        openHost(savedHostId);
        refreshAssetServicesInline(savedHostId);
        const detailHostIdEl = document.getElementById("detailHostId");
        if (detailHostIdEl && parseInt(detailHostIdEl.value, 10) === savedHostId) {
          const ipInput = document.getElementById("detailIp");
          if (ipInput) ipInput.value = fd.get("ip");
          const hostnameInput = document.getElementById("detailHostname");
          if (hostnameInput) hostnameInput.value = fd.get("hostname");
          const tagInput = document.getElementById("detailTag");
          if (tagInput) tagInput.value = fd.get("tag");
          const osInput = document.getElementById("detailOsGuess");
          if (osInput) osInput.value = fd.get("os_guess");
          const titleEl = document.querySelector(".asset-detail-name");
          if (titleEl) titleEl.textContent = (fd.get("ip") || "").toString();
        }
      } else {
        msg.textContent = j.error || "Update failed.";
        msg.style.color = "#f87171";
      }
    });

    const createBtn = document.getElementById("sidebarCreateServiceBtn");
    createBtn && createBtn.addEventListener("click", () => {
      openServiceCreatePopup(data.host.id);
    });

    body.querySelectorAll("[data-open-service]").forEach(a => {
      a.addEventListener("click", (ev) => {
        ev.preventDefault();
        openService(parseInt(a.getAttribute("data-open-service"), 10));
      });
    });
  }

  async function openService(serviceId) {
    const resp = await fetch(`/api/service/${serviceId}`, { cache: "no-store" });
    if (!resp.ok) return;
    const data = await resp.json();
    if (!data.ok) return;
    const hostLabel = data.host ? `${data.host.ip}${data.host.hostname ? " ("+data.host.hostname+")" : ""}` : "";
    title.textContent = `Service ${data.service.port}/${data.service.proto}`;
    body.innerHTML = `
      <div class="card">
        <h2>Summary</h2>
        <div><b>Host:</b> ${esc(hostLabel)}</div>
        <div><b>State:</b> ${esc(data.service.state)}</div>
        <div><b>Name:</b> ${esc(data.service.service_name || "")}</div>
        <div><b>Product:</b> ${esc(data.service.product || "")}</div>
        <div><b>Version:</b> ${esc(data.service.version || "")}</div>
        <div><b>Extra:</b> ${esc(data.service.extra_info || "")}</div>
        <button class="btn" id="editServiceBtn" type="button" style="margin-top:10px;">Edit service</button>
      </div>

      <div class="card">
        <h2>Evidence</h2>
        ${(data.evidence||[]).length ? (data.evidence||[]).map(e => `
          <div class="card">
            <div class="muted">${esc(e.created_at)}${e.source ? ' · Source: ' + esc(e.source) : ''}</div>
            <pre class="evidence">${esc(e.raw_output||"")}</pre>
          </div>`).join("") : `<div class="muted">No evidence stored.</div>`}
      </div>
    `;
    show();
    const editBtn = document.getElementById("editServiceBtn");
    editBtn && editBtn.addEventListener("click", () => {
      openServiceEditPopup(data);
    });
    const header = sidebar.querySelector(".sidebarHeader");
    let backBtn = document.getElementById("sidebarBack");
    if (!backBtn) {
      backBtn = document.createElement("a");
      backBtn.id = "sidebarBack";
      backBtn.className = "btn";
      backBtn.style.marginRight = "8px";
      header.insertBefore(backBtn, header.lastElementChild);
    }
    backBtn.style.display = "none";
  }

  function openServiceEditPopup(serviceData) {
    const svc = serviceData.service || {};
    const hostId = (serviceData.host || {}).id;
    const modal = document.createElement("div");
    modal.style.position = "fixed";
    modal.style.inset = "0";
    modal.style.background = "rgba(0,0,0,0.55)";
    modal.style.zIndex = "1400";
    modal.style.display = "flex";
    modal.style.alignItems = "center";
    modal.style.justifyContent = "center";

    const proto = String(svc.proto || "tcp").toLowerCase();
    const state = String(svc.state || "open").toLowerCase();

    modal.innerHTML = `
      <div class="card" style="width:min(640px, 92vw); max-height:88vh; overflow:auto;">
        <h2>Edit service</h2>
        <form id="serviceEditPopupForm">
          <input type="hidden" name="service_id" value="${svc.id}"/>
          <label>Port</label>
          <input name="port" type="number" min="1" max="65535" value="${svc.port}" required />
          <label>Proto</label>
          <select name="proto">
            <option value="tcp" ${proto==='tcp'?'selected':''}>tcp</option>
            <option value="udp" ${proto==='udp'?'selected':''}>udp</option>
          </select>
          <label>State</label>
          <select name="state">
            <option value="open" ${state==='open'?'selected':''}>open</option>
            <option value="filtered" ${state==='filtered'?'selected':''}>filtered</option>
            <option value="closed" ${state==='closed'?'selected':''}>closed</option>
          </select>
          <label>Service name</label>
          <input name="service_name" value="${esc(svc.service_name||'')}" />
          <label>Product</label>
          <input name="product" value="${esc(svc.product||'')}" />
          <label>Version</label>
          <input name="version" value="${esc(svc.version||'')}" />
          <label>Extra info</label>
          <input name="extra_info" value="${esc(svc.extra_info||'')}" />
          <label>Additional script/output evidence</label>
          <textarea name="raw_output" rows="5" placeholder="Paste additional output to append as evidence..."></textarea>
          <div style="display:flex; gap:8px; margin-top:10px;">
            <button class="btn" type="submit">Save service</button>
            <button class="btn" type="button" id="serviceEditCancel">Cancel</button>
          </div>
          <div id="serviceEditPopupMsg" class="muted" style="margin-top:8px;"></div>
        </form>
      </div>
    `;

    function closePopup() { modal.remove(); }
    modal.addEventListener("click", (ev) => { if (ev.target === modal) closePopup(); });
    document.body.appendChild(modal);

    const cancelBtn = modal.querySelector("#serviceEditCancel");
    const form = modal.querySelector("#serviceEditPopupForm");
    const msg = modal.querySelector("#serviceEditPopupMsg");
    cancelBtn && cancelBtn.addEventListener("click", closePopup);

    form && form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      msg.textContent = "Saving...";
      const fd = new FormData(form);
      const r = await fetch("/api/service/update", { method: "POST", body: fd });
      const j = await r.json().catch(() => ({ ok: false }));
      if (j.ok) {
        msg.textContent = "Saved.";
        closePopup();
        openService(svc.id);
        if (hostId) refreshAssetServicesInline(hostId);
      } else {
        msg.textContent = j.error || "Update failed.";
      }
    });
  }

  function openServiceCreatePopup(hostId) {
    const modal = document.createElement("div");
    modal.style.position = "fixed";
    modal.style.inset = "0";
    modal.style.background = "rgba(0,0,0,0.55)";
    modal.style.zIndex = "1400";
    modal.style.display = "flex";
    modal.style.alignItems = "center";
    modal.style.justifyContent = "center";

    modal.innerHTML = `
      <div class="card" style="width:min(640px, 92vw); max-height:88vh; overflow:auto;">
        <h2>Add service</h2>
        <form id="serviceCreatePopupForm">
          <input type="hidden" name="host_id" value="${hostId}"/>
          <label>Port</label>
          <input name="port" type="number" min="1" max="65535" required placeholder="445" />
          <label>Proto</label>
          <select name="proto"><option value="tcp">tcp</option><option value="udp">udp</option></select>
          <label>State</label>
          <select name="state"><option value="open">open</option><option value="filtered">filtered</option><option value="closed">closed</option></select>
          <label>Service name</label>
          <input name="service_name" placeholder="microsoft-ds" />
          <label>Product</label>
          <input name="product" placeholder="Samba" />
          <label>Version</label>
          <input name="version" placeholder="4.15.0" />
          <label>Extra info</label>
          <input name="extra_info" placeholder="domain/workgroup info" />
          <label>Script/output evidence</label>
          <textarea name="raw_output" rows="6" placeholder="Paste nmap script output, banners, manual checks..."></textarea>
          <div style="display:flex; gap:8px; margin-top:10px;">
            <button class="btn" type="submit">Create service</button>
            <button class="btn" type="button" id="serviceCreateCancel">Cancel</button>
          </div>
          <div id="serviceCreatePopupMsg" class="muted" style="margin-top:8px;"></div>
        </form>
      </div>
    `;

    function closePopup() {
      modal.remove();
    }

    modal.addEventListener("click", (ev) => {
      if (ev.target === modal) closePopup();
    });

    document.body.appendChild(modal);

    const cancelBtn = modal.querySelector("#serviceCreateCancel");
    const form = modal.querySelector("#serviceCreatePopupForm");
    const msg = modal.querySelector("#serviceCreatePopupMsg");

    cancelBtn && cancelBtn.addEventListener("click", closePopup);

    form && form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      msg.textContent = "Saving...";
      const fd = new FormData(form);
      const r = await fetch("/api/service/create", { method: "POST", body: fd });
      const j = await r.json().catch(() => ({ ok: false }));
      if (j.ok) {
        msg.textContent = "Saved.";
        closePopup();
        refreshAssetServicesInline(hostId);
      } else {
        msg.textContent = j.error || "Create failed.";
      }
    });
  }

  function refreshAssetServicesInline(hostId) {
    fetch("/api/host/" + hostId, { cache: "no-store" })
      .then(function(resp) { return resp.json(); })
      .then(function(data) {
        if (!data.ok || !data.services) return;
        var servicesList = document.getElementById("assetServicesList");
        if (!servicesList) return;
        if (data.services.length) {
          var escFn = function(t) { return (t||"").replace(/</g, "&lt;"); };
          var rows = data.services.map(function(s) {
            return "<tr><td><a href='#' data-open-service='" + s.id + "'>" + s.port + "</a></td><td>" + escFn(s.proto) + "</td><td>" + escFn(s.state) + "</td><td>" + escFn(s.service_name) + "</td></tr>";
          }).join("");
          servicesList.innerHTML = "<table><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th></tr></thead><tbody>" + rows + "</tbody></table>";
        } else {
          servicesList.innerHTML = "<div class='muted'>No services stored.</div>";
        }
        if (typeof window._bindAssetServiceLinks === "function") window._bindAssetServiceLinks();
        var svcCountTd = document.querySelector(".asset-row[data-id='" + hostId + "'] td:nth-child(6)");
        if (svcCountTd) svcCountTd.textContent = data.services.length;
      }).catch(function() {});
  }

  async function openSubdomain(fqdn) {
    const resp = await fetch(`/api/subdomain?fqdn=${encodeURIComponent(fqdn)}`, { cache: "no-store" });
    if (!resp.ok) return;
    const data = await resp.json();
    if (!data.ok) return;
    const backBtnSub = document.getElementById("sidebarBack");
    if (backBtnSub) backBtnSub.style.display = "none";
    title.textContent = `Subdomain ${data.fqdn}`;
    body.innerHTML = `
      <div class="card">
        <h2>Resolution</h2>
        <div><b>Scope:</b> ${data.in_scope ? '<span class="pill inscope">IN</span>' : '<span class="pill outscope">OUT</span>'}</div>
        <div><b>IPs:</b> ${(data.ips||[]).length ? (data.ips||[]).map(ip=>`<code>${esc(ip)}</code>`).join(" ") : '<span class="muted">none</span>'}</div>
      </div>
      <div class="card">
        <h2>Linked assets</h2>
        ${(data.hosts||[]).length ? `
          <ul class="miniList">
            ${(data.hosts||[]).map(h=>`<li><a href="#" data-open-host="${h.id}">${esc(h.ip)}</a> <span class="muted">${esc(h.hostname||"")}</span></li>`).join("")}
          </ul>` : `<div class="muted">No linked assets yet.</div>`}
      </div>
      <div class="card" id="sidebarScreenshotsCard">
        <h2>Screenshots &amp; HTTP Info</h2>
        <div class="muted">Loading...</div>
      </div>
    `;
    show();
    body.querySelectorAll("[data-open-host]").forEach(a => {
      a.addEventListener("click", (ev) => {
        ev.preventDefault();
        openHost(parseInt(a.getAttribute("data-open-host"), 10));
      });
    });

    const subdomainPorts = data.ports || {};
    const inScopeIps = new Set(data.in_scope_ips || []);
    function getPortsList() {
      const allPorts = [...new Set(Object.values(subdomainPorts).flat())];
      return allPorts.filter(p => typeof p === "number");
    }
    function captureTargetsViaJob(targets, { setBusy, onDone }) {
      let pollTimer = null;
      let pollInFlight = false;
      let pollJobId = null;

      const stopPolling = () => {
        if (pollTimer) {
          clearTimeout(pollTimer);
          pollTimer = null;
        }
      };

      const pollNow = () => {
        if (pollJobId) poll(pollJobId);
      };

      const registerPolling = (jobId) => {
        pollJobId = jobId;
        sidebarScreenshotPollers.add(pollNow);
      };

      const unregisterPolling = () => {
        pollJobId = null;
        sidebarScreenshotPollers.delete(pollNow);
      };

      const poll = async (jobId) => {
        if (pollInFlight) return;
        pollInFlight = true;
        try {
          const resp = await fetch(`/api/screenshot/jobs/${encodeURIComponent(jobId)}`, { cache: "no-store" });
          const data = await resp.json();
          if (!data.ok || !data.job) {
            throw new Error(data.error || "Screenshot job not found");
          }
          if (data.job.status === "pending" || data.job.status === "running") {
            stopPolling();
            setBusy(true, data.job.status);
            pollTimer = setTimeout(() => poll(jobId), 700);
          } else {
            stopPolling();
            unregisterPolling();
            setBusy(false);
            onDone(data.job);
          }
        } catch (e) {
          stopPolling();
          unregisterPolling();
          setBusy(false);
          onDone({ status: "failed", error: e.message, results: [] });
        } finally {
          pollInFlight = false;
        }
      };

      fetch("/api/screenshot/jobs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targets }),
      })
        .then(r => r.json().then(data => ({ status: r.status, data })))
        .then(({ status, data }) => {
          if (status === 409 && data.active_job) {
            registerPolling(data.active_job.id);
            poll(data.active_job.id);
            return;
          }
          if (!data.ok || !data.job) {
            throw new Error(data.error || "Could not queue screenshot job");
          }
          registerPolling(data.job.id);
          poll(data.job.id);
        })
        .catch(e => {
          stopPolling();
          unregisterPolling();
          setBusy(false);
          onDone({ status: "failed", error: e.message, results: [] });
        });
    }

    function captureForFqdn(fqdn, card, btn) {
      const ports = getPortsList();
      if (ports.length === 0) {
        btn.textContent = "📸 Capture";
        btn.disabled = false;
        return;
      }
      btn.disabled = true;
      btn.textContent = "Queued...";
      const targets = ports.map(port => ({ fqdn, port }));
      const forcedSeen = new Set();
      Object.entries(subdomainPorts).forEach(([ip, ipPorts]) => {
        if (!inScopeIps.has(ip)) return;
        (ipPorts || []).forEach(port => {
          if (typeof port !== "number") return;
          const key = `${fqdn}:${port}:${ip}`;
          if (forcedSeen.has(key)) return;
          forcedSeen.add(key);
          targets.push({ fqdn, port, ip });
        });
      });
      captureTargetsViaJob(targets, {
        setBusy: (busy, status) => {
          btn.textContent = busy
            ? (status === "pending" ? "Queued..." : "Capturing...")
            : "📸 Capture";
          btn.disabled = busy;
        },
        onDone: () => renderScreenshotGrid(fqdn, card),
      });
    }

    function renderScreenshotGrid(fqdn, card) {
      fetch(`/api/screenshot/by-fqdn/${encodeURIComponent(fqdn)}`, { cache: "no-store" })
        .then(r => r.json())
        .then(sdata => {
          if (!card) return;
          const screenshots = (sdata.screenshots || []).filter(s => s.screenshot_path);
          const ports = getPortsList();
          let html = `<div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
            <h2 style="margin:0;">Screenshots &amp; HTTP Info</h2>
            <button class="btn btn-sm sidebar-capture-btn" id="sidebarCaptureBtn" ${!ports.length ? "disabled" : ""}>📸 Capture</button>
          </div>`;

          if (screenshots.length === 0) {
            html += `<p class="muted">No screenshots captured yet.</p>`;
          } else {
            html += `<div class="screenshot-grid">`;
            screenshots.forEach(s => {
              const statusColor = s.http_status >= 400 ? "#ff3333" : "#00ff00";
              const isForced = s.capture_mode === "forced" && s.target_ip;
              const urlLabel = isForced
                ? `${esc(s.scheme)}://${esc(fqdn)}:${s.port} → ${esc(s.target_ip)}`
                : `${esc(s.scheme)}://${esc(fqdn)}:${s.port}`;
              html += `
                <div class="screenshot-item">
                  <div class="screenshot-thumb-wrapper">
                    <a href="/screenshots/${esc(s.screenshot_path)}" target="_blank"><img src="/screenshots/${esc(s.screenshot_path)}" alt="Screenshot" class="screenshot-thumb"/></a>
                    <button class="screenshot-recapture" title="Re-capture this target" data-fqdn="${esc(fqdn)}" data-port="${s.port}" data-ip="${esc(s.target_ip || "")}" data-mode="${esc(s.capture_mode || "dns")}">↻</button>
                  </div>
                  <div class="screenshot-info">
                    <span class="port-badge">${urlLabel}</span>
                    ${isForced ? '<span class="status-pill" style="color:#00ccff;">forced IP</span>' : '<span class="status-pill" style="color:#888888;">dns</span>'}
                    <span class="status-pill" style="color:${statusColor};">Status: ${s.http_status}</span>
                    ${s.http_title ? `<div class="screenshot-title">${esc(s.http_title)}</div>` : ""}
                    ${s.http_content_length > 0 ? `<span class="muted">${s.http_content_length} bytes</span>` : ""}
                    <div class="muted" style="font-size:10px;">${s.created_at ? new Date(s.created_at).toLocaleString() : ""}</div>
                  </div>
                </div>
              `;
            });
            html += `</div>`;
          }
          card.innerHTML = html;

          const captureBtn = card.querySelector("#sidebarCaptureBtn");
          if (captureBtn) {
            captureBtn.addEventListener("click", () => captureForFqdn(fqdn, card, captureBtn));
          }
          card.querySelectorAll(".screenshot-recapture").forEach(btn => {
            btn.addEventListener("click", (ev) => {
              ev.preventDefault();
              const sfqdn = btn.getAttribute("data-fqdn");
              const sport = btn.getAttribute("data-port");
              const sip = btn.getAttribute("data-ip") || "";
              const smode = btn.getAttribute("data-mode") || "dns";
              const recaptureTarget = { fqdn: sfqdn, port: parseInt(sport, 10) };
              if (smode === "forced" && sip) {
                recaptureTarget.ip = sip;
              }
              btn.textContent = "…";
              btn.disabled = true;
              captureTargetsViaJob([recaptureTarget], {
                setBusy: (busy) => {
                  btn.textContent = busy ? "…" : "↻";
                  btn.disabled = busy;
                },
                onDone: () => renderScreenshotGrid(fqdn, card),
              });
            });
          });
        })
        .catch(() => {
          if (card) {
            card.innerHTML = `<h2>Screenshots &amp; HTTP Info</h2><p class="muted" style="color:#ff3333;">Failed to load screenshots.</p>`;
          }
        });
    }
    renderScreenshotGrid(fqdn, body.querySelector("#sidebarScreenshotsCard"));
  }

async function openCloudCreate() {
  const backBtnCloudCreate = document.getElementById("sidebarBack");
  if (backBtnCloudCreate) backBtnCloudCreate.style.display = "none";
  title.textContent = "Create cloud item";
  body.innerHTML = `
    <div class="card">
      <h2>New cloud item</h2>
      <form id="cloudCreateForm">
        <label>Provider</label>
        <select name="provider" id="cloudProvider">
          <option value="Azure">Azure</option>
          <option value="Digital Ocean">Digital Ocean</option>
          <option value="AWS">AWS</option>
          <option value="O365">O365</option>
          <option value="Microsoft">Microsoft</option>
        </select>

        <label style="margin-top:10px;">Name</label>
        <input name="name" placeholder="e.g., client prod tenant"/>

        <div id="cloudFields" style="margin-top:10px;"></div>

        <label style="margin-top:10px;">Notes</label>
        <textarea name="notes" rows="5" placeholder="Findings, creds, URLs, links, next steps..."></textarea>

        <div style="display:flex; gap:10px; margin-top:12px;">
          <button class="btn" type="submit">Create</button>
          <button class="btn" type="button" id="cloudCancelBtn">Cancel</button>
        </div>
      </form>
    </div>
  `;
  show();

  function renderFields(provider) {
    const el = body.querySelector("#cloudFields");
    const p = (provider||"").toLowerCase();
    if (p === "aws") {
      el.innerHTML = `
        <label>AWS Account ID</label>
        <input name="account_id" placeholder="123456789012"/>
        <label style="margin-top:8px;">Regions (one per line)</label>
        <textarea name="regions" rows="3" placeholder="us-east-1\nus-west-2"></textarea>
        <label style="margin-top:8px;">S3 bucket URLs / names (one per line)</label>
        <textarea name="buckets" rows="4" placeholder="s3://bucket\nhttps://bucket.s3.amazonaws.com"></textarea>
      `;
    } else if (p === "azure") {
      el.innerHTML = `
        <label>Tenant ID</label>
        <input name="tenant_id" placeholder="GUID"/>
        <label style="margin-top:8px;">Subscription IDs (one per line)</label>
        <textarea name="subscriptions" rows="4" placeholder="GUID\nGUID"></textarea>
        <label style="margin-top:8px;">Regions / Locations (one per line)</label>
        <textarea name="regions" rows="3" placeholder="eastus\ncanadacentral"></textarea>
      `;
    } else if (p === "digital ocean") {
      el.innerHTML = `
        <label>Projects (one per line)</label>
        <textarea name="projects" rows="3" placeholder="client-prod\nclient-dev"></textarea>
        <label style="margin-top:8px;">Spaces (bucket URLs/names) (one per line)</label>
        <textarea name="buckets" rows="4" placeholder="https://nyc3.digitaloceanspaces.com/bucket"></textarea>
        <label style="margin-top:8px;">Regions (one per line)</label>
        <textarea name="regions" rows="3" placeholder="nyc3\nams3"></textarea>
      `;
    } else if (p === "o365") {
      el.innerHTML = `
        <label>Tenant ID</label>
        <input name="tenant_id" placeholder="GUID"/>
        <label style="margin-top:8px;">Primary domain</label>
        <input name="primary_domain" placeholder="example.com"/>
        <label style="margin-top:8px;">Email domains (one per line)</label>
        <textarea name="subscriptions" rows="4" placeholder="example.com\nexample.onmicrosoft.com"></textarea>
      `;
    } else { // Microsoft generic
      el.innerHTML = `
        <label>Tenant ID</label>
        <input name="tenant_id" placeholder="GUID"/>
        <label style="margin-top:8px;">Primary domain</label>
        <input name="primary_domain" placeholder="example.com"/>
        <label style="margin-top:8px;">App IDs / Client IDs (one per line)</label>
        <textarea name="app_ids" rows="4" placeholder="GUID\nGUID"></textarea>
        <label style="margin-top:8px;">Domains (one per line)</label>
        <textarea name="subscriptions" rows="3" placeholder="example.com\nexample.onmicrosoft.com"></textarea>
      `;
    }
  }

  const providerSel = body.querySelector("#cloudProvider");
  renderFields(providerSel.value);
  providerSel.addEventListener("change", () => renderFields(providerSel.value));

  body.querySelector("#cloudCancelBtn").addEventListener("click", hide);

  body.querySelector("#cloudCreateForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const resp = await fetch("/api/cloud/create", { method: "POST", body: fd });
    if (!resp.ok) {
      body.querySelector("h2").textContent = "Create cloud item (error)";
      return;
    }
    const data = await resp.json();
    window.location.href = "/cloud";
  });
}

async function openCloud(id) {
  const resp = await fetch("/api/cloud/" + id, { cache: "no-store" });
  if (!resp.ok) return;
  const data = await resp.json();
  const backBtnCloud = document.getElementById("sidebarBack");
  if (backBtnCloud) backBtnCloud.style.display = "none";
  title.textContent = (data.provider || "Cloud") + " • " + (data.name || ("#" + id));
  const d = data.data || {};

  function fieldRow(k,v){
    if (v === undefined || v === null) return "";
    if (Array.isArray(v)) return v.length ? `<div><b>${esc(k)}:</b><br/><pre>${esc(v.join("\n"))}</pre></div>` : "";
    if ((""+v).trim()==="") return "";
    return `<div><b>${esc(k)}:</b> ${esc(v)}</div>`;
  }

  body.innerHTML = `
    <div class="card">
      <h2>Details</h2>
      <form id="cloudUpdateForm">
        <input type="hidden" name="cloud_id" value="${esc(id)}"/>
        <label>Provider</label>
        <select name="provider" id="cloudProvider2">
          <option ${data.provider==="Azure"?"selected":""} value="Azure">Azure</option>
          <option ${data.provider==="Digital Ocean"?"selected":""} value="Digital Ocean">Digital Ocean</option>
          <option ${data.provider==="AWS"?"selected":""} value="AWS">AWS</option>
          <option ${data.provider==="O365"?"selected":""} value="O365">O365</option>
          <option ${data.provider==="Microsoft"?"selected":""} value="Microsoft">Microsoft</option>
        </select>

        <label style="margin-top:10px;">Name</label>
        <input name="name" value="${esc(data.name||"")}" />

        <div id="cloudFields2" style="margin-top:10px;"></div>

        <label style="margin-top:10px;">Notes</label>
        <textarea name="notes" rows="6">${esc(data.notes||"")}</textarea>

        <div style="display:flex; gap:10px; margin-top:12px;">
          <button class="btn" type="submit">Save</button>
          <button class="btn" type="button" id="cloudDeleteBtn">Delete</button>
        </div>
      </form>
    </div>
  `;
  show();

  function renderFields(provider, d) {
    const el = body.querySelector("#cloudFields2");
    const p = (provider||"").toLowerCase();
    if (p === "aws") {
      el.innerHTML = `
        <label>AWS Account ID</label>
        <input name="account_id" value="${esc(d.account_id||"")}" placeholder="123456789012"/>
        <label style="margin-top:8px;">Regions (one per line)</label>
        <textarea name="regions" rows="3">${esc((d.regions||[]).join("\n"))}</textarea>
        <label style="margin-top:8px;">S3 bucket URLs / names (one per line)</label>
        <textarea name="buckets" rows="4">${esc((d.buckets||[]).join("\n"))}</textarea>
      `;
    } else if (p === "azure") {
      el.innerHTML = `
        <label>Tenant ID</label>
        <input name="tenant_id" value="${esc(d.tenant_id||"")}" placeholder="GUID"/>
        <label style="margin-top:8px;">Subscription IDs (one per line)</label>
        <textarea name="subscriptions" rows="4">${esc((d.subscriptions||[]).join("\n"))}</textarea>
        <label style="margin-top:8px;">Regions / Locations (one per line)</label>
        <textarea name="regions" rows="3">${esc((d.regions||[]).join("\n"))}</textarea>
      `;
    } else if (p === "digital ocean") {
      el.innerHTML = `
        <label>Projects (one per line)</label>
        <textarea name="projects" rows="3">${esc((d.projects||[]).join("\n"))}</textarea>
        <label style="margin-top:8px;">Spaces (one per line)</label>
        <textarea name="buckets" rows="4">${esc((d.spaces||[]).join("\n"))}</textarea>
        <label style="margin-top:8px;">Regions (one per line)</label>
        <textarea name="regions" rows="3">${esc((d.regions||[]).join("\n"))}</textarea>
      `;
    } else if (p === "o365") {
      el.innerHTML = `
        <label>Tenant ID</label>
        <input name="tenant_id" value="${esc(d.tenant_id||"")}" placeholder="GUID"/>
        <label style="margin-top:8px;">Primary domain</label>
        <input name="primary_domain" value="${esc(d.primary_domain||"")}" placeholder="example.com"/>
        <label style="margin-top:8px;">Email domains (one per line)</label>
        <textarea name="subscriptions" rows="4">${esc((d.email_domains||[]).join("\n"))}</textarea>
      `;
    } else {
      el.innerHTML = `
        <label>Tenant ID</label>
        <input name="tenant_id" value="${esc(d.tenant_id||"")}" placeholder="GUID"/>
        <label style="margin-top:8px;">Primary domain</label>
        <input name="primary_domain" value="${esc(d.primary_domain||"")}" placeholder="example.com"/>
        <label style="margin-top:8px;">App IDs / Client IDs (one per line)</label>
        <textarea name="app_ids" rows="4">${esc((d.app_ids||[]).join("\n"))}</textarea>
        <label style="margin-top:8px;">Domains (one per line)</label>
        <textarea name="subscriptions" rows="3">${esc((d.domains||[]).join("\n"))}</textarea>
      `;
    }
  }

  const sel = body.querySelector("#cloudProvider2");
  renderFields(sel.value, d);
  sel.addEventListener("change", () => renderFields(sel.value, d));

  body.querySelector("#cloudUpdateForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const resp2 = await fetch("/api/cloud/update", { method: "POST", body: fd });
    if (resp2.ok) window.location.href = "/cloud";
  });

  body.querySelector("#cloudDeleteBtn").addEventListener("click", async () => {
    if (!confirm("Delete this cloud item?")) return;
    const fd = new FormData();
    fd.append("cloud_id", id);
    const resp3 = await fetch("/api/cloud/delete", { method: "POST", body: fd });
    if (resp3.ok) window.location.href = "/cloud";
  });
}

async function openRegistrarEdit(rootDomain) {
    const resp = await fetch(`/api/registrar?domain=${encodeURIComponent(rootDomain)}`, { cache: "no-store" });
  if (!resp.ok) return;
  const data = await resp.json();
  const item = data.item || {};
  const hasExisting = !!item.id;
  const subdomainText = data.subdomain_ips || '';

  const backBtn = document.getElementById("sidebarBack");
  if (backBtn) backBtn.style.display = "none";
  title.textContent = `Registrar: ${esc(rootDomain)}`;

  body.innerHTML = `
    <div class="card">
      <h2>Edit registrar info</h2>
      <form id="registrarEditForm">
        <input type="hidden" name="has_existing" value="${hasExisting ? '1' : '0'}" />
        ${hasExisting ? `<input type="hidden" name="registrar_id" value="${item.id}" />` : ""}
        <label>Root Domain</label>
        <input name="domain" value="${esc(item.domain || rootDomain)}" required />
        <label>ASN</label>
        <input name="asn" value="${esc(item.asn || '')}" placeholder="e.g., AS15169" />
        <label>Registrar</label>
        <input name="registrar" value="${esc(item.registrar || '')}" />
        <label>Netblocks (comma-separated)</label>
        <textarea name="netblocks" rows="2" placeholder="192.0.2.0/24,198.51.100.0/24">${esc(item.netblocks || '')}</textarea>
        <label>Subdomains &amp; IPs (one per line: subdomain ip1 ip2 ...)</label>
        <textarea name="subdomain_ips" rows="8" placeholder="www.example.com 93.184.216.34&#10;mail.example.com 93.184.216.35">${esc(subdomainText)}</textarea>
        <div style="display:flex; gap:8px; margin-top:10px;">
          <button class="btn" type="submit">Save</button>
          ${hasExisting ? `<button class="btn" type="button" id="registrarDeleteBtn">Delete</button>` : ""}
        </div>
        <div id="registrarEditMsg" class="muted" style="margin-top:8px;"></div>
      </form>
    </div>
  `;
  show();

  const form = document.getElementById("registrarEditForm");
  const msg = document.getElementById("registrarEditMsg");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    msg.textContent = "Saving...";
    const fd = new FormData(form);
    const existing = fd.get("has_existing") === "1";
    const endpoint = existing ? "/api/registrar/update" : "/api/registrar/create";
    const r = await fetch(endpoint, { method: "POST", body: fd });
    const j = await r.json().catch(() => ({ ok: false }));
    if (j.ok) {
      msg.textContent = "Saved.";
      setTimeout(() => location.reload(), 300);
    } else {
      msg.textContent = j.error || "Save failed.";
    }
  });

  const deleteBtn = document.getElementById("registrarDeleteBtn");
  if (deleteBtn) {
    deleteBtn.addEventListener("click", async () => {
      if (!confirm("Delete this registrar entry?")) return;
      const fd = new FormData(form);
      const r = await fetch("/api/registrar/delete", { method: "POST", body: fd });
      if (r.ok) location.reload();
    });
  }
}

async function openRegistrarCreate() {
  const backBtn = document.getElementById("sidebarBack");
  if (backBtn) backBtn.style.display = "none";
  title.textContent = "New Registrar Entry";
  body.innerHTML = `
    <div class="card">
      <h2>Add registrar info</h2>
      <form id="registrarCreateForm">
        <label>Root Domain</label>
        <input name="domain" placeholder="example.com" required />
        <label>ASN</label>
        <input name="asn" placeholder="e.g., AS15169" />
        <label>Registrar</label>
        <input name="registrar" />
        <label>Netblocks (comma-separated)</label>
        <textarea name="netblocks" rows="2" placeholder="192.0.2.0/24,198.51.100.0/24"></textarea>
        <label>Subdomains &amp; IPs (one per line: subdomain ip1 ip2 ...)</label>
        <textarea name="subdomain_ips" rows="8" placeholder="www.example.com 93.184.216.34&#10;mail.example.com 93.184.216.35"></textarea>
        <div style="display:flex; gap:8px; margin-top:10px;">
          <button class="btn" type="submit">Create</button>
          <button class="btn" type="button" id="registrarCancelBtn">Cancel</button>
        </div>
        <div id="registrarCreateMsg" class="muted" style="margin-top:8px;"></div>
      </form>
    </div>
  `;
  show();

  const form = document.getElementById("registrarCreateForm");
  const msg = document.getElementById("registrarCreateMsg");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    msg.textContent = "Creating...";
    const fd = new FormData(form);
    const r = await fetch("/api/registrar/create", { method: "POST", body: fd });
    const j = await r.json().catch(() => ({ ok: false }));
    if (j.ok) {
      msg.textContent = "Created.";
      setTimeout(() => location.reload(), 300);
    } else {
      msg.textContent = j.error || "Create failed.";
    }
  });

  document.getElementById("registrarCancelBtn").addEventListener("click", hide);
}

window.ReconSidebar = { openHost, openService, openSubdomain, openHostCreate, openCloud, openCloudCreate, openRegistrarEdit, openRegistrarCreate, openServiceCreatePopup, hide };

})();
