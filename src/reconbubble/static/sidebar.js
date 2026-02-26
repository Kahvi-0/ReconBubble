/* v2 - fixed sidebar */
(function () {
  const overlay = document.getElementById("sidebarOverlay");
  const sidebar = document.getElementById("sidebar");
  const title = document.getElementById("sidebarTitle");
  const body = document.getElementById("sidebarBody");
  const closeBtn = document.getElementById("sidebarClose");

  function show() {
    overlay.classList.remove("hidden");
    sidebar.classList.remove("hidden");
    sidebar.setAttribute("aria-hidden", "false");
  }
  function hide() {
    overlay.classList.add("hidden");
    sidebar.classList.add("hidden");
    sidebar.setAttribute("aria-hidden", "true");
    body.innerHTML = "";
  }
  overlay && overlay.addEventListener("click", hide);
  closeBtn && closeBtn.addEventListener("click", hide);
  window.addEventListener("keydown", (e) => { if (e.key === "Escape") hide(); });

  function esc(s) { return (""+s).replace(/[&<>"']/g,c=>({ "&":"&amp;","<":"&gt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c])); }

  
function bindNoteHandlers() {
  const noteForm = document.getElementById("noteAddForm");
  const noteMsg = document.getElementById("noteAddMsg");
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
    title.textContent = "Create asset";
    body.innerHTML = `
      <div class="card">
        <h2>New asset</h2>
        <form id="hostCreateForm">
          <label>IP Address</label>
          <input name="ip" placeholder="192.168.1.1" required />
          <label style="margin-top:8px;">Hostname</label>
          <input name="hostname" placeholder="server.example.com"/>
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
      const fd = new FormData(form);
      const r = await fetch("/api/host/create", { method: "POST", body: fd });
      const j = await r.json().catch(() => ({ ok: false }));
      if (j.ok) {
        msg.textContent = "Created. Refreshing…";
        setTimeout(() => location.reload(), 450);
      } else {
        msg.textContent = j.error || "Create failed.";
      }
    });
  }

  async function openHost(hostId) {
    const resp = await fetch(`/api/host/${hostId}`);
    if (!resp.ok) return;
    const data = await resp.json();

    // Severity tint (based on highest note severity)
    try {
      sidebar.classList.remove("sev-info","sev-low","sev-med","sev-high");
      if (data && data.highest_severity) sidebar.classList.add("sev-" + data.highest_severity);
    } catch (e) {}
    if (!data.ok) return;

    title.textContent = `Asset ${data.host.ip}`;
    body.innerHTML = `
      <div class="card">
        <h2>Edit asset</h2>
        <form id="hostUpdateForm">
          <input type="hidden" name="host_id" value="${data.host.id}"/>
          <label>IP</label>
          <input name="ip" value="${esc(data.host.ip)}" required />
          <label>Hostname</label>
          <input name="hostname" value="${esc(data.host.hostname || "")}" />
          <label>OS Guess</label>
          <input name="os_guess" value="${esc(data.host.os_guess || "")}" />
          <label>Associate domains/subdomains (one per line)</label>
          <textarea name="domains_raw" rows="6" placeholder="app.example.com">${esc((data.domains||[]).join("\n"))}</textarea>
          <button class="btn" type="submit">Save</button>
          <div id="hostUpdateMsg" class="muted" style="margin-top:8px;"></div>
        </form>
      </div>

<div class="card">
  <h2>Notes</h2>
  <form id="noteAddForm" method="post" action="/api/note/add">
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
    <div id="noteAddMsg" class="muted" style="margin-top:8px;"></div>
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

    const form = document.getElementById("hostUpdateForm");
    const msg = document.getElementById("hostUpdateMsg");
    form && form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      msg.textContent = "Saving...";
      const fd = new FormData(form);
      const r = await fetch("/api/host/update", { method: "POST", body: fd });
      const j = await r.json().catch(()=>({ok:false}));
      if (j.ok) {
        msg.textContent = "Saved. Refreshing…";
        setTimeout(() => location.reload(), 450);
      } else {
        msg.textContent = j.error || "Update failed.";
      }
    });

    body.querySelectorAll("[data-open-service]").forEach(a => {
      a.addEventListener("click", (ev) => {
        ev.preventDefault();
        openService(parseInt(a.getAttribute("data-open-service"), 10));
      });
    });
  }

  async function openService(serviceId) {
    const resp = await fetch(`/api/service/${serviceId}`);
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
        ${data.host ? `<div class="muted"><a href="#" id="backToHost">Back to asset</a></div>` : ""}
      </div>

      <div class="card">
        <h2>Evidence</h2>
        ${(data.evidence||[]).length ? (data.evidence||[]).map(e => `
          <div class="card">
            <div class="muted">${esc(e.created_at)}</div>
            <pre class="evidence">${esc(e.raw_output||"")}</pre>
          </div>`).join("") : `<div class="muted">No evidence stored.</div>`}
      </div>
    `;
    show();
    const back = document.getElementById("backToHost");
    back && back.addEventListener("click", (ev) => {
      ev.preventDefault();
      if (data.host) openHost(data.host.id);
    });
  }

  async function openSubdomain(fqdn) {
    const resp = await fetch(`/api/subdomain?fqdn=${encodeURIComponent(fqdn)}`);
    if (!resp.ok) return;
    const data = await resp.json();
    if (!data.ok) return;
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
    `;
    show();
    body.querySelectorAll("[data-open-host]").forEach(a => {
      a.addEventListener("click", (ev) => {
        ev.preventDefault();
        openHost(parseInt(a.getAttribute("data-open-host"), 10));
      });
    });
  }

async function openCloudCreate() {
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
  const resp = await fetch("/api/cloud/" + id);
  if (!resp.ok) return;
  const data = await resp.json();
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

window.ReconSidebar = { openHost, openService, openSubdomain, openHostCreate, openCloud, openCloudCreate, hide };

})();
