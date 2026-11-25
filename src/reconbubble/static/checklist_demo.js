(function () {
  const DEMO_MAPS = window.DEMO_MAPS || {};
  const toggleEl = document.getElementById('demoVulnOnly');

  const chunks = [
    {
      id: 'unauth',
      sectionLabel: 'UNAUTH',
      gridId: 'demoUnauthGrid',
      detailsId: 'demoUnauthDetails',
      map: DEMO_MAPS.unauth || { nodes: [], vuln_branches: [] },
    },
    {
      id: 'auth',
      sectionLabel: 'AUTH',
      gridId: 'demoAuthGrid',
      detailsId: 'demoAuthDetails',
      map: DEMO_MAPS.auth || { nodes: [], vuln_branches: [] },
    },
  ].map((c) => {
    const nodes = (c.map.nodes || []).map((n, i) => ({
      key: n.key || `node_${i}`,
      label: n.label || n.key || `Node ${i}`,
      color_start: n.color_start || '#4a4a4a',
      initial: n.initial === 1 || n.initial === true,
      exploit_text: n.exploit_text || 'Exploitation notes',
      static_text: n.static_text || '',
      note: n.note || '',
      commands: Array.isArray(n.commands) ? n.commands : [],
      sources: Array.isArray(n.sources) ? n.sources : [],
    }));
    const branches = (c.map.vuln_branches || []).map((b, i) => ({
      id: b.id || `branch_${i}`,
      parent_id: b.parent_id || b.parent_key || '',
      label: b.label || b.id || `Branch ${i}`,
      title: b.title || b.label || b.id || `Branch ${i}`,
      text: b.text || '',
      note: b.note || '',
      commands: Array.isArray(b.commands) ? b.commands : [],
      sources: Array.isArray(b.sources) ? b.sources : [],
    }));
    const branchesById = {};
    for (const b of branches) branchesById[b.id] = b;
    return Object.assign({}, c, { nodes, branches, branchesById });
  });

  const state = { status: {}, branch: {}, notes: {} };
  const expanded = { unauth: null, auth: null };
  let vulnOnly = false;

  const ROOT_NOTE_PLACEHOLDERS = {
    ldap_security: 'LDAP signing/channel binding exploitation notes...',
    adcs: 'ADCS servers/templates/ESC notes...',
    sccm: 'SCCM servers / MPs / DPs...',
    wsus: 'WSUS server/trust path notes...',
    accounts_no_password: 'Accounts that do not require passwords...',
    constrained_delegation: 'Constrained delegation notes...',
    unconstrained_delegation: 'Unconstrained delegation notes...',
    insecure_domain_priv_dacl: 'Insecure privileges / DACL notes...',
  };

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

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function makeHowTo(item) {
    const note = String(item.note || '').trim();
    const commands = (item.commands || []).filter((c) => String(c).trim());
    const sources = (item.sources || []).filter((s) => String(s).trim());
    if (!note && !commands.length && !sources.length) return null;
    const wrap = el('div', 'demo-howto');
    wrap.appendChild(el('div', 'demo-howto-label', 'How to check'));
    if (note) wrap.appendChild(el('div', 'demo-howto-note', note));
    if (commands.length) {
      const cmds = el('div', 'demo-commands');
      for (const cmd of commands) cmds.appendChild(el('div', 'demo-command', cmd));
      wrap.appendChild(cmds);
    }
    if (sources.length) {
      const srcs = el('div', 'demo-sources');
      sources.forEach((s, i) => {
        if (i > 0) srcs.appendChild(el('span', 'demo-source-sep', '\u00b7'));
        if (/^https?:\/\//.test(s)) {
          const a = document.createElement('a');
          a.className = 'demo-source';
          a.href = s;
          a.target = '_blank';
          a.rel = 'noreferrer';
          a.textContent = s;
          srcs.appendChild(a);
        } else {
          srcs.appendChild(el('span', 'demo-source', s));
        }
      });
      wrap.appendChild(srcs);
    }
    return wrap;
  }

  function branchChildren(ch, parentId) {
    return ch.branches.filter((b) => b.parent_id === parentId);
  }

  function vulnStateOf(key) {
    return state.status[`${key}_vuln`] || 'unchecked';
  }

  function isBranchVisible(ch, branchId) {
    const b = ch.branchesById[branchId];
    if (!b || !state.branch[b.id]) return false;
    const parent = ch.branchesById[b.parent_id];
    if (parent) return isBranchVisible(ch, parent.id);
    return state.status[`${b.parent_id}_vuln`] === 'vuln';
  }

  async function clearDescendants(ch, parentBranchId) {
    for (const child of branchChildren(ch, parentBranchId)) {
      state.branch[child.id] = false;
      await saveKey(`branch_${child.id}`, { done: 0 });
      await clearDescendants(ch, child.id);
    }
  }

  function extrasCount(metaKey) {
    const raw = parseInt(state.notes[metaKey] || '0', 10);
    return Number.isFinite(raw) && raw > 0 ? raw : 0;
  }

  function nodePwned(ch, key) {
    if (key === 'sccm_unauth') {
      return branchChildren(ch, 'sccm_unauth').some(
        (b) => !!state.status[`${b.id}_exploitable`]
      );
    }
    if (key === 'web_applications') {
      if (state.status['webapp_exploit_badge_main']) return true;
      for (let i = 1; i <= extrasCount('note_webapp_exploit_extras_count'); i++) {
        if (state.status[`webapp_exploit_badge_extra_${i}`]) return true;
      }
      return false;
    }
    if (key === 'ldap_security') {
      return !!state.status['ldap_webdav_success'];
    }
    return false;
  }

  function makeNote(noteKey, placeholder, minHeightPx, card) {
    const ta = el('textarea', 'demo-note');
    ta.value = state.notes[noteKey] || '';
    ta.placeholder = placeholder;
    ta.style.minHeight = `${minHeightPx}px`;
    ta.onchange = async () => {
      state.notes[noteKey] = ta.value;
      await saveNote(noteKey, ta.value);
    };
    applyTextareaSizing(ta, noteKey, card);
    return ta;
  }

  function pwnedBadge(small) {
    const badge = el('span', 'demo-pwned' + (small ? ' demo-pwned-sm' : ''), 'PWNED');
    return badge;
  }

  function makeCard(title) {
    const card = el('div', 'demo-branch-card');
    const head = el('div', 'demo-branch-head');
    head.appendChild(el('div', 'demo-branch-title', title));
    card.appendChild(head);
    return { card, head };
  }

  function exploitCheckboxRow(key, label) {
    const row = el('label', 'demo-exploit-row');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = !!state.status[key];
    cb.onchange = async () => {
      state.status[key] = cb.checked;
      await saveKey(key, { done: cb.checked ? 1 : 0 });
      render();
    };
    row.appendChild(cb);
    row.appendChild(document.createTextNode(label));
    return row;
  }

  function webdavQuestionRow(key) {
    const row = el('label', 'demo-note-row');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = !!state.status[key];
    cb.onchange = async () => {
      state.status[key] = cb.checked;
      await saveKey(key, { done: cb.checked ? 1 : 0 });
      render();
    };
    row.appendChild(cb);
    row.appendChild(document.createTextNode('Are hosts in network running WebDAV?'));
    return row;
  }

  function branchOptionRow(ch, o) {
    const row = document.createElement('label');
    const c = document.createElement('input');
    c.type = 'checkbox';
    c.checked = !!state.branch[o.id];
    c.onchange = async () => {
      state.branch[o.id] = c.checked;
      if (!c.checked) await clearDescendants(ch, o.id);
      await saveKey(`branch_${o.id}`, { done: c.checked ? 1 : 0 });
      render();
    };
    row.appendChild(c);
    row.appendChild(document.createTextNode(' ' + o.label));
    return row;
  }

  function makeBranchCard(ch, b, ctx) {
    const { card, head } = makeCard(b.title);

    if (b.parent_id === 'sccm_unauth') {
      const exploitKey = `${b.id}_exploitable`;
      if (state.status[exploitKey]) head.appendChild(pwnedBadge(true));
      card.appendChild(exploitCheckboxRow(exploitKey, 'Exploitable'));
      card.appendChild(makeNote(`note_${b.id}_details`, 'Notes...', 80, card));
    }

    if (b.parent_id === 'guest_null_sessions') {
      card.appendChild(makeNote(`note_${b.id}_details`, 'Notes...', 80, card));
    }

    if (
      b.id === 'endpoint_edr' ||
      b.id === 'endpoint_antivirus' ||
      b.id === 'ntlmv1_hosts' ||
      b.id === 'ntlmv1_downgrade' ||
      b.id === 'ntlmv1_crack'
    ) {
      card.appendChild(makeNote(`note_${b.id}`, 'Add notes...', 70, card));
    }

    if (b.text) {
      card.appendChild(el('div', 'demo-branch-text', b.text));
    }

    const howto = makeHowTo(b);
    if (howto) card.appendChild(howto);

    const childOpts = branchChildren(ch, b.id);
    if (childOpts.length) {
      const opts = el('div', 'demo-child-opts');
      for (const o of childOpts) opts.appendChild(branchOptionRow(ch, o));
      card.appendChild(opts);
    }

    if (b.id === 'webapp_exploit') {
      const addBtn = el('button', 'dvbtn demo-add-btn', 'Add exploit note bubble');
      addBtn.type = 'button';
      addBtn.onclick = async () => {
        const extrasMetaKey = 'note_webapp_exploit_extras_count';
        const next = extrasCount(extrasMetaKey) + 1;
        state.notes[extrasMetaKey] = String(next);
        await saveNote(extrasMetaKey, String(next));
        render();
      };
      card.appendChild(addBtn);
    }

    if (
      ctx.nodeKey === 'ldap_security' &&
      (b.id === 'ldap_signing_off' || b.id === 'ldap_binding_off')
    ) {
      const key = b.id === 'ldap_signing_off' ? 'ldap_webdav_signing' : 'ldap_webdav_binding';
      card.appendChild(webdavQuestionRow(key));
    }

    return card;
  }

  function renderBranchSubtree(ch, parentId, ctx) {
    const visibleKids = branchChildren(ch, parentId).filter((b) => {
      if (ctx.nodeKey === 'ldap_security' && b.id === 'ldap_relay') return false;
      return isBranchVisible(ch, b.id);
    });
    if (!visibleKids.length) return null;

    const stack = el('div', 'demo-branch-tree');
    for (const child of visibleKids) {
      const wrap = el('div', 'demo-branch');
      wrap.appendChild(makeBranchCard(ch, child, ctx));
      const deeper = renderBranchSubtree(ch, child.id, ctx);
      if (deeper) wrap.appendChild(deeper);
      stack.appendChild(wrap);
    }
    return stack;
  }

  function vulnButton(label, value, ch, n) {
    const vs = vulnStateOf(n.key);
    const btn = el('button', 'dvbtn' + (vs === value ? ` active-${value}` : ''), label);
    btn.type = 'button';
    btn.onclick = async () => {
      if (value === 'vuln') {
        state.status[`${n.key}_vuln`] = 'vuln';
        await saveKey(`${n.key}_vuln`, { vuln: 'vuln' });
      } else {
        state.status[`${n.key}_vuln`] = value;
        for (const r of branchChildren(ch, n.key)) {
          state.branch[r.id] = false;
          await saveKey(`branch_${r.id}`, { done: 0 });
          await clearDescendants(ch, r.id);
        }
        await saveKey(`${n.key}_vuln`, { vuln: value });
      }
      render();
    };
    return btn;
  }

  function renderNodeDetail(ch, n) {
    const vs = vulnStateOf(n.key);
    const detail = el('div', 'demo-detail');
    detail.style.borderLeftColor = n.color_start;

    const head = el('div', 'demo-detail-head');
    head.appendChild(el('span', 'demo-detail-tag', `${ch.sectionLabel} / ${n.key}`));
    head.appendChild(el('span', 'demo-detail-title', n.label));
    if (nodePwned(ch, n.key)) head.appendChild(pwnedBadge(true));
    detail.appendChild(head);

    detail.appendChild(el('div', 'demo-detail-desc', n.exploit_text));

    const howto = makeHowTo(n);
    if (howto) detail.appendChild(howto);

    const btns = el('div', 'demo-vuln-btns');
    btns.appendChild(vulnButton('Unchecked', 'unchecked', ch, n));
    btns.appendChild(vulnButton('Vulnerable', 'vuln', ch, n));
    btns.appendChild(vulnButton('Not Vulnerable', 'notvuln', ch, n));
    detail.appendChild(btns);

    if (vs === 'vuln') {
      if (n.static_text) {
        detail.appendChild(el('div', 'demo-detail-desc', n.static_text));
      }

      if (ROOT_NOTE_PLACEHOLDERS[n.key]) {
        detail.appendChild(
          makeNote(`note_${n.key}_exploit`, ROOT_NOTE_PLACEHOLDERS[n.key], 70, detail)
        );
      }

      if (n.key === 'sccm_unauth') {
        detail.appendChild(
          makeNote('note_sccm_unauth_servers', 'SCCM servers / MPs / DPs...', 80, detail)
        );
      }

      let rootOpts = branchChildren(ch, n.key);
      if (n.key === 'ldap_security') {
        rootOpts = rootOpts.filter((o) => o.id !== 'ldap_relay');
      }
      if (rootOpts.length) {
        const opts = el('div', 'demo-opts');
        for (const o of rootOpts) opts.appendChild(branchOptionRow(ch, o));
        detail.appendChild(opts);
      }

      const tree = renderBranchSubtree(ch, n.key, { nodeKey: n.key });
      if (tree) detail.appendChild(tree);

      if (n.key === 'ldap_security') {
        const showWebdav =
          !!state.status['ldap_webdav_signing'] ||
          !!state.status['ldap_webdav_binding'];
        if (showWebdav) {
          const shared = makeCard('WebDAV Present');
          shared.card.appendChild(
            el(
              'div',
              'demo-branch-text',
              'At least one LDAP path indicates hosts with WebDAV running. Validate coercion/relay opportunities.'
            )
          );
          shared.card.appendChild(
            makeNote('note_ldap_webdav_shared', 'WebDAV notes...', 70, shared.card)
          );
          shared.card.appendChild(
            exploitCheckboxRow('ldap_webdav_success', 'Successful relay/coerce exploited')
          );
          detail.appendChild(shared.card);

          if (state.status['ldap_webdav_success']) {
            const success = makeCard('Successful Relay/Coerce');
            success.head.appendChild(pwnedBadge(true));
            success.card.appendChild(
              el('div', 'demo-branch-text', 'Record hosts where relay/coerce exploitation succeeded.')
            );
            success.card.appendChild(
              makeNote('note_ldap_webdav_success_hosts', 'Successfully exploited hosts...', 80, success.card)
            );
            detail.appendChild(success.card);
          }
        }
      }

      if (n.key === 'web_applications') {
        if (state.branch['webapp_default_creds']) {
          const creds = makeCard('Default Creds');
          creds.head.appendChild(pwnedBadge(true));
          creds.card.appendChild(
            makeNote('note_webapp_default_creds', 'Notes...', 90, creds.card)
          );
          detail.appendChild(creds.card);
        }

        if (state.branch['webapp_exploit']) {
          const exploitCard = makeCard('Exploit');
          const exploitBadgeKey = 'webapp_exploit_badge_main';
          if (state.status[exploitBadgeKey]) exploitCard.head.appendChild(pwnedBadge(true));
          exploitCard.card.appendChild(exploitCheckboxRow(exploitBadgeKey, 'Exploited'));
          exploitCard.card.appendChild(
            makeNote('note_webapp_exploit', 'Notes...', 90, exploitCard.card)
          );
          detail.appendChild(exploitCard.card);

          const extras = extrasCount('note_webapp_exploit_extras_count');
          for (let i = 1; i <= extras; i++) {
            const extraCard = makeCard(`Exploit Note ${i + 1}`);
            const extraBadgeKey = `webapp_exploit_badge_extra_${i}`;
            if (state.status[extraBadgeKey]) extraCard.head.appendChild(pwnedBadge(true));
            extraCard.card.appendChild(exploitCheckboxRow(extraBadgeKey, 'Exploited'));
            extraCard.card.appendChild(
              makeNote(`note_webapp_exploit_extra_${i}`, 'Notes...', 90, extraCard.card)
            );
            detail.appendChild(extraCard.card);
          }
        }
      }

      if (n.key === 'insecure_domain_priv_dacl') {
        const extrasMetaKey = 'note_insecure_domain_priv_dacl_extras_count';
        const count = extrasCount(extrasMetaKey);
        for (let i = 1; i <= count; i++) {
          const extra = makeCard(`Privilege/DACL Note ${i + 1}`);
          extra.card.appendChild(
            makeNote(`note_insecure_domain_priv_dacl_extra_${i}`, 'Notes...', 90, extra.card)
          );
          const wrap = el('div', 'demo-branch');
          wrap.appendChild(extra.card);
          detail.appendChild(wrap);
        }

        const addBtn = el('button', 'dvbtn demo-add-btn', 'Add privilege/DACL note bubble');
        addBtn.type = 'button';
        addBtn.onclick = async () => {
          const next = extrasCount(extrasMetaKey) + 1;
          state.notes[extrasMetaKey] = String(next);
          await saveNote(extrasMetaKey, String(next));
          render();
        };
        detail.appendChild(addBtn);
      }
    }

    return detail;
  }

  function makeBubble(ch, n) {
    const vs = vulnStateOf(n.key);
    const stateCls =
      vs === 'vuln' ? 'st-vuln' : vs === 'notvuln' ? 'st-notvuln' : 'st-unchecked';
    const dotCls =
      vs === 'vuln' ? 'demo-dot-vuln' : vs === 'notvuln' ? 'demo-dot-notvuln' : 'demo-dot-unchecked';
    const bubble = el('div', `demo-bubble ${stateCls}`);

    const top = el('div', 'demo-bubble-top');
    top.appendChild(el('span', `demo-dot ${dotCls}`));
    top.appendChild(el('div', 'demo-bubble-title', n.label));
    if (nodePwned(ch, n.key)) top.appendChild(pwnedBadge(true));
    bubble.appendChild(top);

    bubble.appendChild(el('div', 'demo-bubble-sub', n.exploit_text));

    if (vulnOnly) {
      bubble.style.cursor = 'default';
    } else {
      bubble.onclick = () => {
        expanded[ch.id] = expanded[ch.id] === n.key ? null : n.key;
        render();
      };
    }
    return bubble;
  }

  function renderGrid(ch) {
    const grid = document.getElementById(ch.gridId);
    grid.innerHTML = '';
    const shown = vulnOnly
      ? ch.nodes.filter((n) => vulnStateOf(n.key) === 'vuln')
      : ch.nodes.filter((n) => n.initial);
    if (!shown.length) {
      grid.appendChild(
        el('div', 'demo-empty', vulnOnly ? 'No vulnerable bubbles in this section yet.' : 'No bubbles.')
      );
      return;
    }
    for (const n of shown) grid.appendChild(makeBubble(ch, n));
  }

  function renderDetails(ch) {
    const box = document.getElementById(ch.detailsId);
    box.innerHTML = '';
    const targets = vulnOnly
      ? ch.nodes.filter((n) => vulnStateOf(n.key) === 'vuln')
      : ch.nodes.filter((n) => n.initial && expanded[ch.id] === n.key);
    for (const n of targets) box.appendChild(renderNodeDetail(ch, n));
  }

  function render() {
    for (const ch of chunks) {
      renderGrid(ch);
      renderDetails(ch);
    }
  }

  if (toggleEl) {
    toggleEl.addEventListener('change', () => {
      vulnOnly = !!toggleEl.checked;
      render();
    });
  }

  Promise.all([
    fetch('/api/checklist').then((r) => r.json()).catch(() => ({})),
    fetch('/api/checklist-notes').then((r) => r.json()).catch(() => ({})),
  ])
    .then(([data, notes]) => {
      state.status = data || {};
      state.notes = notes || {};
      for (const ch of chunks) {
        for (const b of ch.branches) {
          state.branch[b.id] = !!state.status[`branch_${b.id}`];
        }
      }
      render();
    })
    .catch(() => {
      state.status = {};
      state.notes = {};
      render();
    });
})();
