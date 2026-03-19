(function () {
  const mapData = window.CHECKLIST_MAP_DATA || { nodes: [], vuln_branches: [] };
  const mapName = window.CHECKLIST_MAP_NAME || '';
  const rowsEl = document.getElementById('checklistRows');
  const canvasEl = document.getElementById('checklistCanvas');
  const linksEl = document.getElementById('checklistLinks');
  const stickyScrollEl = document.getElementById('stickyHScroll');
  const stickyScrollInnerEl = document.getElementById('stickyHScrollInner');
  if (!rowsEl || !canvasEl || !linksEl || !stickyScrollEl || !stickyScrollInnerEl) return;

  function toSlug(s) {
    return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  }

  const nodes = (mapData.nodes || []).map((n, i) => ({
    key: n.key || `node_${i}`,
    label: n.label || n.key || `Node ${i}`,
    color_start: n.color_start || '#4a4a4a',
    color_end: n.color_end || '#2f2f2f',
    initial: n.initial === 1 || n.initial === true,
    exploit_text: n.exploit_text || 'Exploitation notes',
    static_text: n.static_text || '',
  }));

  const explicitEdges = (mapData.edges || []).map((e) => [
    `card-n-${e.from || ''}`,
    `card-n-${e.to || ''}`,
  ]).filter((p) => p[0] !== 'card-n-' && p[1] !== 'card-n-');

  const branches = (mapData.vuln_branches || []).map((b, i) => ({
    id: b.id || b.option_key || toSlug(b.label) || `branch_${i}`,
    parent_id: b.parent_id || b.parent_key || '',
    label: b.label || b.option_key || b.id || `Branch ${i}`,
    title: b.title || b.label || b.id || `Branch ${i}`,
    text: b.text || '',
  }));

  const state = { status: {}, branch: {}, notes: {} };
  let pendingLinks = [];

  function gradient(c1, c2) {
    return `linear-gradient(135deg, ${c1}, ${c2})`;
  }

  function saveKey(key, payload) {
    const fd = new FormData();
    Object.keys(payload).forEach((k) => fd.append(k, payload[k]));
    return fetch(`/api/checklist/${key}`, { method: 'POST', body: fd });
  }

  function saveNote(key, note) {
    const fd = new FormData();
    fd.append('note', note || '');
    return fetch(`/api/checklist-note/${key}`, { method: 'POST', body: fd });
  }

  function applyTextareaSizing(ta, noteKey, card) {
    const sizeKey = `size_${noteKey}`;
    ta.style.resize = 'both';
    ta.style.overflow = 'auto';
    if (card) card.style.maxWidth = 'none';

    const raw = String(state.notes[sizeKey] || '');
    const m = raw.match(/^(\d+)x(\d+)$/);
    if (m) {
      const w = Math.max(220, parseInt(m[1], 10) || 0);
      const h = Math.max(70, parseInt(m[2], 10) || 0);
      ta.style.width = `${w}px`;
      ta.style.height = `${h}px`;
      if (card) {
        card.style.maxWidth = 'none';
        card.style.minWidth = `${Math.max(240, w + 24)}px`;
      }
    }

    const persist = async () => {
      const w = Math.max(220, Math.round(ta.offsetWidth));
      const h = Math.max(70, Math.round(ta.offsetHeight));
      const packed = `${w}x${h}`;
      if (state.notes[sizeKey] === packed) return;
      state.notes[sizeKey] = packed;
      if (card) {
        card.style.maxWidth = 'none';
        card.style.minWidth = `${Math.max(240, w + 24)}px`;
      }
      await saveNote(sizeKey, packed);
    };

    ta.addEventListener('mouseup', () => { persist(); });
    ta.addEventListener('touchend', () => { persist(); });
  }

  function branchChildren(parentId) {
    return branches.filter((b) => b.parent_id === parentId);
  }

  function isBranchVisible(branchId) {
    const b = branches.find((x) => x.id === branchId);
    if (!b || !state.branch[b.id]) return false;
    const parentBranch = branches.find((x) => x.id === b.parent_id);
    if (parentBranch) return isBranchVisible(parentBranch.id);
    return state.status[`${b.parent_id}_vuln`] === 'vuln';
  }

  async function clearDescendants(parentBranchId) {
    const kids = branchChildren(parentBranchId);
    for (const child of kids) {
      state.branch[child.id] = false;
      await saveKey(`branch_${child.id}`, { done: 0 });
      await clearDescendants(child.id);
    }
  }

  function makeCard(title, bg, id) {
    const card = document.createElement('div');
    card.className = 'card';
    card.style.background = bg;
    if (id) card.id = id;
    const t = document.createElement('div');
    t.className = 'card-title';
    t.textContent = title;
    card.appendChild(t);
    return card;
  }

  function renderBranchSubtree(parentId, bg, parentCardId, context) {
    const visibleKids = branchChildren(parentId).filter((b) => {
      if (context && context.nodeKey === 'ldap_security' && b.id === 'ldap_relay') return false;
      return isBranchVisible(b.id);
    });
    if (!visibleKids.length) return null;

    const stack = document.createElement('div');
    stack.className = 'branch-stack';

    for (const child of visibleKids) {
      const line = document.createElement('div');
      line.className = 'branch-line';

      const cardId = `card-b-${child.id}`;
      const card = makeCard(child.title, bg, cardId);
      if (parentCardId) pendingLinks.push([parentCardId, cardId]);
      if (child.text) {
        const tx = document.createElement('div');
        tx.textContent = child.text;
        tx.style.fontSize = '13px';
        tx.style.marginBottom = '6px';
        card.appendChild(tx);
      }

      if (child.parent_id === 'sccm_unauth') {
        const exploitKey = `${child.id}_exploitable`;
        const isExploitable = !!state.status[exploitKey];

        const exploitWrap = document.createElement('label');
        exploitWrap.style.position = 'absolute';
        exploitWrap.style.top = '8px';
        exploitWrap.style.right = '10px';
        exploitWrap.style.display = 'flex';
        exploitWrap.style.alignItems = 'center';
        exploitWrap.style.gap = '5px';
        exploitWrap.style.fontSize = '11px';
        exploitWrap.style.fontWeight = '700';
        exploitWrap.style.cursor = 'pointer';
        const exploitCb = document.createElement('input');
        exploitCb.type = 'checkbox';
        exploitCb.checked = isExploitable;
        exploitCb.onchange = async () => {
          state.status[exploitKey] = exploitCb.checked;
          await saveKey(exploitKey, { done: exploitCb.checked ? 1 : 0 });
          render();
        };
        exploitWrap.appendChild(exploitCb);
        exploitWrap.appendChild(document.createTextNode('Exploitable'));
        card.appendChild(exploitWrap);

        if (isExploitable) {
          const badge = document.createElement('span');
          badge.className = 'exploit-badge';
          badge.textContent = 'PWNED';
          card.appendChild(badge);
        }

        const noteKey = `note_${child.id}_details`;
        const ta = document.createElement('textarea');
        ta.value = state.notes[noteKey] || '';
        ta.placeholder = 'Notes...';
        ta.style.width = '100%';
        ta.style.minHeight = '80px';
        ta.style.borderRadius = '6px';
        ta.style.border = '1px solid rgba(255,255,255,0.35)';
        ta.style.background = 'rgba(0,0,0,0.25)';
        ta.style.color = '#fff';
        ta.style.padding = '6px';
        ta.style.fontSize = '12px';
        ta.onchange = async () => {
          state.notes[noteKey] = ta.value;
          await saveNote(noteKey, ta.value);
        };
        applyTextareaSizing(ta, noteKey, card);
        card.appendChild(ta);
      }

      if (
        child.id === 'endpoint_edr' ||
        child.id === 'endpoint_antivirus' ||
        child.id === 'ntlmv1_hosts' ||
        child.id === 'ntlmv1_downgrade' ||
        child.id === 'ntlmv1_crack'
      ) {
        const noteKey = `note_${child.id}`;
        const ta = document.createElement('textarea');
        ta.value = state.notes[noteKey] || '';
        ta.placeholder = 'Add notes...';
        ta.style.width = '100%';
        ta.style.minHeight = '70px';
        ta.style.borderRadius = '6px';
        ta.style.border = '1px solid rgba(255,255,255,0.35)';
        ta.style.background = 'rgba(0,0,0,0.25)';
        ta.style.color = '#fff';
        ta.style.padding = '6px';
        ta.style.fontSize = '12px';
        ta.onchange = async () => {
          state.notes[noteKey] = ta.value;
          await saveNote(noteKey, ta.value);
        };
        applyTextareaSizing(ta, noteKey, card);
        card.appendChild(ta);
      }

      const childOpts = branchChildren(child.id);
      if (childOpts.length) {
        const opts = document.createElement('div');
        opts.className = 'child-options';
        for (const o of childOpts) {
          const row = document.createElement('label');
          const c = document.createElement('input');
          c.type = 'checkbox';
          c.checked = !!state.branch[o.id];
          c.onchange = async () => {
            state.branch[o.id] = c.checked;
            if (!c.checked) await clearDescendants(o.id);
            await saveKey(`branch_${o.id}`, { done: c.checked ? 1 : 0 });
            render();
          };
          row.appendChild(c);
          row.appendChild(document.createTextNode(' ' + o.label));
          opts.appendChild(row);
        }
        card.appendChild(opts);
      }

      if (child.id === 'webapp_exploit') {
        const addBtn = document.createElement('button');
        addBtn.className = 'vbtn';
        addBtn.type = 'button';
        addBtn.style.marginTop = '8px';
        addBtn.textContent = 'Add exploit note bubble';
        addBtn.onclick = async () => {
          const extrasMetaKey = 'note_webapp_exploit_extras_count';
          const current = parseInt(state.notes[extrasMetaKey] || '0', 10);
          const next = (Number.isFinite(current) ? current : 0) + 1;
          state.notes[extrasMetaKey] = String(next);
          await saveNote(extrasMetaKey, String(next));
          render();
        };
        card.appendChild(addBtn);
      }

      line.appendChild(card);
      if (context && context.nodeKey === 'ldap_security' && (child.id === 'ldap_signing_off' || child.id === 'ldap_binding_off')) {
        const key = child.id === 'ldap_signing_off' ? 'ldap_webdav_signing' : 'ldap_webdav_binding';
        const row = document.createElement('label');
        row.style.fontSize = '13px';
        const c = document.createElement('input');
        c.type = 'checkbox';
        c.checked = !!state.status[key];
        c.onchange = async () => {
          state.status[key] = c.checked;
          await saveKey(key, { done: c.checked ? 1 : 0 });
          render();
        };
        row.appendChild(c);
        row.appendChild(document.createTextNode(' Are hosts in network running WebDAV?'));
        card.appendChild(row);
      }

      const deeper = renderBranchSubtree(child.id, bg, cardId, context);
      if (deeper) line.appendChild(deeper);
      stack.appendChild(line);

      if (context) {
        context.branchCardById = context.branchCardById || {};
        context.branchCardById[child.id] = cardId;
      }
    }

    return stack;
  }

  function render() {
    rowsEl.innerHTML = '';
    pendingLinks = [];
    for (const n of nodes) {
      const row = document.createElement('div');
      row.className = 'chain-row';

      const nodeBg = gradient(n.color_start, n.color_end);
      const nodeCardId = `card-n-${n.key}`;
      const nodeCard = makeCard(n.label, nodeBg, nodeCardId);
      const vulnState = state.status[`${n.key}_vuln`] || 'unchecked';
      if (n.initial && vulnState === 'notvuln') nodeCard.classList.add('is-greyed');

      if (n.initial) {
        const btns = document.createElement('div');
        btns.className = 'vuln-buttons';

        const bUnchecked = document.createElement('button');
        bUnchecked.className = 'vbtn ' + (vulnState === 'unchecked' ? 'active-unchecked' : '');
        bUnchecked.textContent = 'Unchecked';
        bUnchecked.onclick = async () => {
          state.status[`${n.key}_vuln`] = 'unchecked';
          for (const r of branchChildren(n.key)) {
            state.branch[r.id] = false;
            await saveKey(`branch_${r.id}`, { done: 0 });
            await clearDescendants(r.id);
          }
          await saveKey(`${n.key}_vuln`, { vuln: 'unchecked' });
          render();
        };

        const bV = document.createElement('button');
        bV.className = 'vbtn ' + (vulnState === 'vuln' ? 'active-vuln' : '');
        bV.textContent = 'Vulnerable';
        bV.onclick = async () => {
          state.status[`${n.key}_vuln`] = 'vuln';
          await saveKey(`${n.key}_vuln`, { vuln: 'vuln' });
          render();
        };

        const bN = document.createElement('button');
        bN.className = 'vbtn ' + (vulnState === 'notvuln' ? 'active-notvuln' : '');
        bN.textContent = 'Not Vulnerable';
        bN.onclick = async () => {
          state.status[`${n.key}_vuln`] = 'notvuln';
          for (const r of branchChildren(n.key)) {
            state.branch[r.id] = false;
            await saveKey(`branch_${r.id}`, { done: 0 });
            await clearDescendants(r.id);
          }
          await saveKey(`${n.key}_vuln`, { vuln: 'notvuln' });
          render();
        };

        btns.appendChild(bUnchecked);
        btns.appendChild(bV);
        btns.appendChild(bN);
        nodeCard.appendChild(btns);
      }

      row.appendChild(nodeCard);

      if (n.initial && vulnState === 'vuln') {
        const exploitId = `card-v-${n.key}`;
        const exploit = makeCard('Exploitation Notes', nodeBg, exploitId);
        pendingLinks.push([nodeCardId, exploitId]);
        const tx = document.createElement('div');
        tx.textContent = n.exploit_text;
        tx.style.fontSize = '13px';
        tx.style.marginBottom = '6px';
        exploit.appendChild(tx);

        if (n.key === 'ldap_security') {
          const noteKey = 'note_ldap_security_exploit';
          const ta = document.createElement('textarea');
          ta.value = state.notes[noteKey] || '';
          ta.placeholder = 'LDAP signing/channel binding exploitation notes...';
          ta.style.width = '100%';
          ta.style.minHeight = '70px';
          ta.style.borderRadius = '6px';
          ta.style.border = '1px solid rgba(255,255,255,0.35)';
          ta.style.background = 'rgba(0,0,0,0.25)';
          ta.style.color = '#fff';
          ta.style.padding = '6px';
          ta.style.fontSize = '12px';
          ta.onchange = async () => {
            state.notes[noteKey] = ta.value;
            await saveNote(noteKey, ta.value);
          };
          applyTextareaSizing(ta, noteKey, exploit);
          exploit.appendChild(ta);
        }

        if (n.key === 'sccm_unauth') {
          const sccmServerKey = 'note_sccm_unauth_servers';
          const sccmTa = document.createElement('textarea');
          sccmTa.value = state.notes[sccmServerKey] || '';
          sccmTa.placeholder = 'SCCM servers / MPs / DPs...';
          sccmTa.style.width = '100%';
          sccmTa.style.minHeight = '80px';
          sccmTa.style.borderRadius = '6px';
          sccmTa.style.border = '1px solid rgba(255,255,255,0.35)';
          sccmTa.style.background = 'rgba(0,0,0,0.25)';
          sccmTa.style.color = '#fff';
          sccmTa.style.padding = '6px';
          sccmTa.style.fontSize = '12px';
          sccmTa.onchange = async () => {
            state.notes[sccmServerKey] = sccmTa.value;
            await saveNote(sccmServerKey, sccmTa.value);
          };
          applyTextareaSizing(sccmTa, sccmServerKey, exploit);
          exploit.appendChild(sccmTa);
        }

        let rootOpts = branchChildren(n.key);
        if (n.key === 'ldap_security') {
          rootOpts = rootOpts.filter((o) => o.id !== 'ldap_relay');
        }
        if (rootOpts.length) {
          const opts = document.createElement('div');
          opts.className = 'child-options';
          for (const o of rootOpts) {
            const line = document.createElement('label');
            const c = document.createElement('input');
            c.type = 'checkbox';
            c.checked = !!state.branch[o.id];
            c.onchange = async () => {
              state.branch[o.id] = c.checked;
              if (!c.checked) await clearDescendants(o.id);
              await saveKey(`branch_${o.id}`, { done: c.checked ? 1 : 0 });
              render();
            };
            line.appendChild(c);
            line.appendChild(document.createTextNode(' ' + o.label));
            opts.appendChild(line);
          }
          exploit.appendChild(opts);
        }

        row.appendChild(exploit);

        const context = { nodeKey: n.key, branchCardById: {} };
        const tree = renderBranchSubtree(n.key, nodeBg, exploitId, context);
        if (tree) row.appendChild(tree);

        if (n.key === 'ldap_security') {
          const showWebdav = !!state.status['ldap_webdav_signing'] || !!state.status['ldap_webdav_binding'];
          if (showWebdav) {
            const sharedId = 'card-b-ldap_webdav_shared';
            const shared = makeCard('WebDAV Present', nodeBg, sharedId);
            const tx2 = document.createElement('div');
            tx2.style.fontSize = '13px';
            tx2.textContent = 'At least one LDAP path indicates hosts with WebDAV running. Validate coercion/relay opportunities.';
            shared.appendChild(tx2);

            const noteKey = 'note_ldap_webdav_shared';
            const ta = document.createElement('textarea');
            ta.value = state.notes[noteKey] || '';
            ta.placeholder = 'WebDAV notes...';
            ta.style.width = '100%';
            ta.style.minHeight = '70px';
            ta.style.borderRadius = '6px';
            ta.style.border = '1px solid rgba(255,255,255,0.35)';
            ta.style.background = 'rgba(0,0,0,0.25)';
            ta.style.color = '#fff';
            ta.style.padding = '6px';
            ta.style.fontSize = '12px';
            ta.onchange = async () => {
              state.notes[noteKey] = ta.value;
              await saveNote(noteKey, ta.value);
            };
            applyTextareaSizing(ta, noteKey, shared);
            shared.appendChild(ta);

            const successRow = document.createElement('label');
            successRow.style.fontSize = '13px';
            successRow.style.marginTop = '8px';
            const successCb = document.createElement('input');
            successCb.type = 'checkbox';
            successCb.checked = !!state.status['ldap_webdav_success'];
            successCb.onchange = async () => {
              state.status['ldap_webdav_success'] = successCb.checked;
              await saveKey('ldap_webdav_success', { done: successCb.checked ? 1 : 0 });
              render();
            };
            successRow.appendChild(successCb);
            successRow.appendChild(document.createTextNode(' Successful relay/coerce exploited'));
            shared.appendChild(successRow);

            row.appendChild(shared);
            if (state.status['ldap_webdav_signing'] && context.branchCardById['ldap_signing_off']) {
              pendingLinks.push([context.branchCardById['ldap_signing_off'], sharedId]);
            }
            if (state.status['ldap_webdav_binding'] && context.branchCardById['ldap_binding_off']) {
              pendingLinks.push([context.branchCardById['ldap_binding_off'], sharedId]);
            }

            if (state.status['ldap_webdav_success']) {
              const successId = 'card-b-ldap_webdav_success';
              const success = makeCard('Successful Relay/Coerce', nodeBg, successId);
              const badge = document.createElement('span');
              badge.className = 'exploit-badge';
              badge.textContent = 'PWNED';
              success.appendChild(badge);

              const tx3 = document.createElement('div');
              tx3.style.fontSize = '13px';
              tx3.style.marginBottom = '6px';
              tx3.textContent = 'Record hosts where relay/coerce exploitation succeeded.';
              success.appendChild(tx3);

              const successNoteKey = 'note_ldap_webdav_success_hosts';
              const ta2 = document.createElement('textarea');
              ta2.value = state.notes[successNoteKey] || '';
              ta2.placeholder = 'Successfully exploited hosts...';
              ta2.style.width = '100%';
              ta2.style.minHeight = '80px';
              ta2.style.borderRadius = '6px';
              ta2.style.border = '1px solid rgba(255,255,255,0.35)';
              ta2.style.background = 'rgba(0,0,0,0.25)';
              ta2.style.color = '#fff';
              ta2.style.padding = '6px';
              ta2.style.fontSize = '12px';
              ta2.onchange = async () => {
                state.notes[successNoteKey] = ta2.value;
                await saveNote(successNoteKey, ta2.value);
              };
              applyTextareaSizing(ta2, successNoteKey, success);
              success.appendChild(ta2);

              row.appendChild(success);
              pendingLinks.push([sharedId, successId]);
            }
          }
        }

        if (n.key === 'web_applications') {
          let webAppNotesStack = null;
          const ensureWebAppNotesStack = () => {
            if (!webAppNotesStack) {
              webAppNotesStack = document.createElement('div');
              webAppNotesStack.className = 'branch-stack';
            }
            return webAppNotesStack;
          };

          if (state.branch['webapp_default_creds']) {
            const credsNoteId = 'card-b-webapp_default_creds_notes';
            const credsBg = 'linear-gradient(135deg, #7c3aed, #5b21b6)';
            const credsCard = makeCard('Default Creds', credsBg, credsNoteId);

            const credsNoteKey = 'note_webapp_default_creds';
            const credsTa = document.createElement('textarea');
            credsTa.value = state.notes[credsNoteKey] || '';
            credsTa.placeholder = 'Notes...';
            credsTa.style.width = '100%';
            credsTa.style.minHeight = '90px';
            credsTa.style.borderRadius = '6px';
            credsTa.style.border = '1px solid rgba(255,255,255,0.35)';
            credsTa.style.background = 'rgba(0,0,0,0.25)';
            credsTa.style.color = '#fff';
            credsTa.style.padding = '6px';
            credsTa.style.fontSize = '12px';
            credsTa.onchange = async () => {
              state.notes[credsNoteKey] = credsTa.value;
              await saveNote(credsNoteKey, credsTa.value);
            };
            applyTextareaSizing(credsTa, credsNoteKey, credsCard);
            credsCard.appendChild(credsTa);
            const credsBadge = document.createElement('span');
            credsBadge.className = 'exploit-badge';
            credsBadge.textContent = 'PWNED';
            credsCard.appendChild(credsBadge);
            ensureWebAppNotesStack().appendChild(credsCard);
            if (context.branchCardById['webapp_default_creds']) {
              pendingLinks.push([context.branchCardById['webapp_default_creds'], credsNoteId]);
            }
          }

          if (state.branch['webapp_exploit']) {
            const exploitNoteId = 'card-b-webapp_exploit_notes';
            const exploitCard = makeCard('Exploit', nodeBg, exploitNoteId);
            const exploitBadgeKey = 'webapp_exploit_badge_main';
            const exploited = !!state.status[exploitBadgeKey];

            const toggleWrap = document.createElement('label');
            toggleWrap.style.position = 'absolute';
            toggleWrap.style.top = '8px';
            toggleWrap.style.right = '10px';
            toggleWrap.style.display = 'flex';
            toggleWrap.style.alignItems = 'center';
            toggleWrap.style.gap = '5px';
            toggleWrap.style.fontSize = '11px';
            toggleWrap.style.fontWeight = '700';
            toggleWrap.style.cursor = 'pointer';
            const toggle = document.createElement('input');
            toggle.type = 'checkbox';
            toggle.checked = exploited;
            toggle.onchange = async () => {
              state.status[exploitBadgeKey] = toggle.checked;
              await saveKey(exploitBadgeKey, { done: toggle.checked ? 1 : 0 });
              render();
            };
            toggleWrap.appendChild(toggle);
            toggleWrap.appendChild(document.createTextNode('Exploited'));
            exploitCard.appendChild(toggleWrap);

            if (exploited) {
              const badge = document.createElement('span');
              badge.className = 'exploit-badge';
              badge.textContent = 'PWNED';
              exploitCard.appendChild(badge);
            }

            const exploitNoteKey = 'note_webapp_exploit';
            const exploitTa = document.createElement('textarea');
            exploitTa.value = state.notes[exploitNoteKey] || '';
            exploitTa.placeholder = 'Notes...';
            exploitTa.style.width = '100%';
            exploitTa.style.minHeight = '90px';
            exploitTa.style.borderRadius = '6px';
            exploitTa.style.border = '1px solid rgba(255,255,255,0.35)';
            exploitTa.style.background = 'rgba(0,0,0,0.25)';
            exploitTa.style.color = '#fff';
            exploitTa.style.padding = '6px';
            exploitTa.style.fontSize = '12px';
            exploitTa.onchange = async () => {
              state.notes[exploitNoteKey] = exploitTa.value;
              await saveNote(exploitNoteKey, exploitTa.value);
            };
            applyTextareaSizing(exploitTa, exploitNoteKey, exploitCard);
            exploitCard.appendChild(exploitTa);

            const extrasMetaKey = 'note_webapp_exploit_extras_count';
            const extrasRaw = parseInt(state.notes[extrasMetaKey] || '0', 10);
            const extrasCount = Number.isFinite(extrasRaw) && extrasRaw > 0 ? extrasRaw : 0;

            ensureWebAppNotesStack().appendChild(exploitCard);
            if (context.branchCardById['webapp_exploit']) {
              pendingLinks.push([context.branchCardById['webapp_exploit'], exploitNoteId]);
            }

            for (let i = 1; i <= extrasCount; i++) {
              const extraId = `card-b-webapp_exploit_notes_extra_${i}`;
              const extraCard = makeCard(`Exploit Note ${i + 1}`, nodeBg, extraId);
              const extraKey = `note_webapp_exploit_extra_${i}`;
              const extraBadgeKey = `webapp_exploit_badge_extra_${i}`;
              const extraExploited = !!state.status[extraBadgeKey];

              const extraToggleWrap = document.createElement('label');
              extraToggleWrap.style.position = 'absolute';
              extraToggleWrap.style.top = '8px';
              extraToggleWrap.style.right = '10px';
              extraToggleWrap.style.display = 'flex';
              extraToggleWrap.style.alignItems = 'center';
              extraToggleWrap.style.gap = '5px';
              extraToggleWrap.style.fontSize = '11px';
              extraToggleWrap.style.fontWeight = '700';
              extraToggleWrap.style.cursor = 'pointer';
              const extraToggle = document.createElement('input');
              extraToggle.type = 'checkbox';
              extraToggle.checked = extraExploited;
              extraToggle.onchange = async () => {
                state.status[extraBadgeKey] = extraToggle.checked;
                await saveKey(extraBadgeKey, { done: extraToggle.checked ? 1 : 0 });
                render();
              };
              extraToggleWrap.appendChild(extraToggle);
              extraToggleWrap.appendChild(document.createTextNode('Exploited'));
              extraCard.appendChild(extraToggleWrap);

              if (extraExploited) {
                const extraBadge = document.createElement('span');
                extraBadge.className = 'exploit-badge';
                extraBadge.textContent = 'PWNED';
                extraCard.appendChild(extraBadge);
              }

              const extraTa = document.createElement('textarea');
              extraTa.value = state.notes[extraKey] || '';
              extraTa.placeholder = 'Notes...';
              extraTa.style.width = '100%';
              extraTa.style.minHeight = '90px';
              extraTa.style.borderRadius = '6px';
              extraTa.style.border = '1px solid rgba(255,255,255,0.35)';
              extraTa.style.background = 'rgba(0,0,0,0.25)';
              extraTa.style.color = '#fff';
              extraTa.style.padding = '6px';
              extraTa.style.fontSize = '12px';
              extraTa.onchange = async () => {
                state.notes[extraKey] = extraTa.value;
                await saveNote(extraKey, extraTa.value);
              };
              applyTextareaSizing(extraTa, extraKey, extraCard);
              extraCard.appendChild(extraTa);
              ensureWebAppNotesStack().appendChild(extraCard);
              if (context.branchCardById['webapp_exploit']) {
                pendingLinks.push([context.branchCardById['webapp_exploit'], extraId]);
              }
            }
          }

          if (webAppNotesStack) {
            row.appendChild(webAppNotesStack);
          }
        }
      }

      if (!n.initial && n.static_text) {
        const tx = document.createElement('div');
        tx.textContent = n.static_text;
        tx.style.fontSize = '13px';
        tx.style.marginTop = '6px';
        tx.style.opacity = '0.95';
        nodeCard.appendChild(tx);
      }

      rowsEl.appendChild(row);
    }
    if (mapName === 'attack_path') {
      for (const e of explicitEdges) pendingLinks.push(e);
    }
    syncStickyScrollbar();
    drawLinks();
  }

  function syncStickyScrollbar() {
    const innerWidth = Math.max(rowsEl.scrollWidth + 24, canvasEl.clientWidth);
    stickyScrollInnerEl.style.width = `${innerWidth}px`;
    stickyScrollEl.scrollLeft = canvasEl.scrollLeft;
  }

  function drawLinks() {
    linksEl.innerHTML = '<defs><marker id="cbArrow" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#808080"></polygon></marker></defs>';
    const c = canvasEl.getBoundingClientRect();
    const width = Math.max(rowsEl.scrollWidth + 24, canvasEl.clientWidth);
    const height = Math.max(rowsEl.scrollHeight + 24, canvasEl.clientHeight);
    linksEl.setAttribute('width', String(width));
    linksEl.setAttribute('height', String(height));

    for (const pair of pendingLinks) {
      const from = document.getElementById(pair[0]);
      const to = document.getElementById(pair[1]);
      if (!from || !to) continue;
      const a = from.getBoundingClientRect();
      const b = to.getBoundingClientRect();

      const ax = a.left + a.width / 2;
      const ay = a.top + a.height / 2;
      const bx = b.left + b.width / 2;
      const by = b.top + b.height / 2;
      const dx = bx - ax;
      const dy = by - ay;

      let x1;
      let y1;
      let x2;
      let y2;

      if (Math.abs(dy) > Math.abs(dx) * 1.15) {
        // Mostly vertical relationship: connect bottom->top or top->bottom.
        x1 = a.left + a.width / 2;
        y1 = dy >= 0 ? a.bottom : a.top;
        x2 = b.left + b.width / 2;
        y2 = dy >= 0 ? b.top : b.bottom;
      } else {
        // Mostly horizontal relationship: connect nearest side centers.
        x1 = dx >= 0 ? a.right : a.left;
        y1 = a.top + a.height / 2;
        x2 = dx >= 0 ? b.left : b.right;
        y2 = b.top + b.height / 2;
      }

      x1 = x1 - c.left + canvasEl.scrollLeft;
      y1 = y1 - c.top + canvasEl.scrollTop;
      x2 = x2 - c.left + canvasEl.scrollLeft;
      y2 = y2 - c.top + canvasEl.scrollTop;

      const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      p.setAttribute('d', `M ${x1} ${y1} L ${x2} ${y2}`);
      p.setAttribute('stroke', '#808080');
      p.setAttribute('stroke-width', '2');
      p.setAttribute('fill', 'none');
      p.setAttribute('marker-end', 'url(#cbArrow)');
      linksEl.appendChild(p);
    }
  }

  Promise.all([
    fetch('/api/checklist').then((r) => r.json()).catch(() => ({})),
    fetch('/api/checklist-notes').then((r) => r.json()).catch(() => ({})),
  ]).then(([data, notes]) => {
    state.status = data || {};
    state.notes = notes || {};
    for (const b of branches) state.branch[b.id] = !!state.status[`branch_${b.id}`];
    render();
  }).catch(() => {
    state.status = {};
    state.notes = {};
    render();
  });

  canvasEl.addEventListener('scroll', drawLinks);
  canvasEl.addEventListener('scroll', () => { stickyScrollEl.scrollLeft = canvasEl.scrollLeft; });
  stickyScrollEl.addEventListener('scroll', () => { canvasEl.scrollLeft = stickyScrollEl.scrollLeft; drawLinks(); });

  let isDragging = false;
  let dragStartX = 0;
  let dragStartLeft = 0;
  canvasEl.addEventListener('mousedown', (ev) => {
    const t = ev.target;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'BUTTON' || t.closest('label'))) return;
    isDragging = true;
    canvasEl.classList.add('dragging');
    dragStartX = ev.clientX;
    dragStartLeft = canvasEl.scrollLeft;
  });
  window.addEventListener('mousemove', (ev) => {
    if (!isDragging) return;
    const dx = ev.clientX - dragStartX;
    canvasEl.scrollLeft = dragStartLeft - dx;
    drawLinks();
  });
  window.addEventListener('mouseup', () => {
    isDragging = false;
    canvasEl.classList.remove('dragging');
  });

  window.addEventListener('resize', () => { syncStickyScrollbar(); drawLinks(); });
})();
