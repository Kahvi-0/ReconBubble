(function () {
  const mapData = window.CHECKLIST_MAP_DATA || { nodes: [], edges: [], vuln_branches: [] };
  const initialMapName = window.CHECKLIST_MAP_NAME || 'authenticated';
  const container = document.getElementById('mindmap-editor');
  if (!container || !window.cytoscape) return;

  function toSlug(s) {
    return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  }

  const state = {
    mapName: initialMapName,
    title: mapData.title || '',
    phase_label: mapData.phase_label || 'Enumeration',
    selected: null,
    nodes: (mapData.nodes || []).map((n, i) => ({
      kind: 'base',
      key: n.key || `node_${i}`,
      label: n.label || n.key || `Node ${i}`,
      color_start: n.color_start || '#4a4a4a',
      color_end: n.color_end || '#2f2f2f',
      initial: n.initial === 1 || n.initial === true,
      exploit_text: n.exploit_text || 'Exploitation notes',
      position: n.position || null,
    })),
    branches: (mapData.vuln_branches || []).map((b, i) => ({
      kind: 'branch',
      id: b.id || b.option_key || toSlug(b.label) || `branch_${i}`,
      parent_id: b.parent_id || b.parent_key || '',
      label: b.label || b.option_key || b.id || `Branch ${i}`,
      title: b.title || b.label || b.id || `Branch ${i}`,
      text: b.text || '',
      position: b.position || null,
    })),
    edges: (mapData.edges || []).map((e) => ({ from: e.from, to: e.to, label: e.label || '' })),
  };

  const refs = {
    mapName: document.getElementById('mapName'),
    mapTitle: document.getElementById('mapTitle'),
    phaseLabel: document.getElementById('phaseLabel'),
    fType: document.getElementById('fType'),
    fId: document.getElementById('fId'),
    fLabel: document.getElementById('fLabel'),
    fParent: document.getElementById('fParent'),
    fColorStart: document.getElementById('fColorStart'),
    fColorEnd: document.getElementById('fColorEnd'),
    fInitial: document.getElementById('fInitial'),
    fText: document.getElementById('fText'),
    edgeFrom: document.getElementById('edgeFrom'),
    edgeTo: document.getElementById('edgeTo'),
    edgeLabel: document.getElementById('edgeLabel'),
    addNodeBtn: document.getElementById('addNodeBtn'),
    addBranchBtn: document.getElementById('addBranchBtn'),
    addEdgeBtn: document.getElementById('addEdgeBtn'),
    deleteBtn: document.getElementById('deleteBtn'),
    saveBtn: document.getElementById('saveBtn'),
  };

  const cy = cytoscape({
    container,
    elements: [],
    style: [
      { selector: 'node', style: { label: 'data(label)', color: '#fff', 'text-wrap': 'wrap', 'text-max-width': 220, 'text-valign': 'center', 'text-halign': 'center', 'font-size': 11, width: 'label', 'padding': 18, height: 'label', shape: 'round-rectangle', 'background-color': '#4a4a4a', 'border-width': 1, 'border-color': '#777' } },
      { selector: 'node[kind = "base"]', style: { 'background-color': 'data(color_start)' } },
      { selector: 'node[kind = "branch"]', style: { 'background-color': '#546e7a' } },
      { selector: 'node[initial = 1]', style: { 'border-color': '#ffd166', 'border-width': 3 } },
      { selector: 'edge', style: { width: 2, 'curve-style': 'bezier', 'target-arrow-shape': 'triangle', 'line-color': '#888', 'target-arrow-color': '#888', label: 'data(label)', 'font-size': 10, color: '#ddd' } },
    ],
    wheelSensitivity: 0.25,
  });

  function graphElements() {
    const els = [];
    for (const n of state.nodes) {
      els.push({ data: { id: `n:${n.key}`, kind: 'base', key: n.key, label: n.label, color_start: n.color_start, initial: n.initial ? 1 : 0 }, position: n.position || undefined });
    }
    for (const b of state.branches) {
      els.push({ data: { id: `b:${b.id}`, kind: 'branch', idkey: b.id, label: b.title }, position: b.position || undefined });
      const parentBranch = state.branches.find((x) => x.id === b.parent_id);
      const source = parentBranch ? `b:${parentBranch.id}` : `n:${b.parent_id}`;
      if (b.parent_id) els.push({ data: { id: `auto:${source}:${b.id}`, source, target: `b:${b.id}`, label: '' } });
    }
    for (const e of state.edges) {
      els.push({ data: { id: `m:${e.from}:${e.to}:${e.label || ''}`, source: `n:${e.from}`, target: `n:${e.to}`, label: e.label || '' } });
    }
    return els;
  }

  function rebuild() {
    const prev = {};
    cy.nodes().forEach((n) => { prev[n.id()] = n.position(); });
    state.nodes.forEach((n) => {
      if (!n.position && prev[`n:${n.key}`]) n.position = prev[`n:${n.key}`];
    });
    state.branches.forEach((b) => {
      if (!b.position && prev[`b:${b.id}`]) b.position = prev[`b:${b.id}`];
    });
    cy.elements().remove();
    cy.add(graphElements());
    if (!state.nodes.some((n) => n.position) && !state.branches.some((b) => b.position)) {
      cy.layout({ name: 'breadthfirst', directed: true, spacingFactor: 1.4, padding: 40 }).run();
    }
  }

  function fillForm(sel) {
    refs.fType.value = '';
    refs.fId.value = '';
    refs.fLabel.value = '';
    refs.fParent.value = '';
    refs.fColorStart.value = '';
    refs.fColorEnd.value = '';
    refs.fInitial.checked = false;
    refs.fText.value = '';
    if (!sel) return;
    if (sel.kind === 'base') {
      refs.fType.value = 'base';
      refs.fId.value = sel.key;
      refs.fLabel.value = sel.label;
      refs.fColorStart.value = sel.color_start;
      refs.fColorEnd.value = sel.color_end;
      refs.fInitial.checked = !!sel.initial;
      refs.fText.value = sel.exploit_text || '';
    } else {
      refs.fType.value = 'branch';
      refs.fId.value = sel.id;
      refs.fLabel.value = sel.label;
      refs.fParent.value = sel.parent_id;
      refs.fText.value = sel.text || '';
    }
  }

  function selectedModel() {
    if (!state.selected) return null;
    if (state.selected.kind === 'base') return state.nodes.find((n) => n.key === state.selected.key) || null;
    return state.branches.find((b) => b.id === state.selected.id) || null;
  }

  function bindUI() {
    refs.mapName.onchange = (ev) => { window.location.href = `/checklist/edit?map_name=${ev.target.value}`; };
    refs.mapTitle.oninput = (ev) => { state.title = ev.target.value; };
    refs.phaseLabel.oninput = (ev) => { state.phase_label = ev.target.value; };

    refs.addNodeBtn.onclick = () => {
      const key = `node_${Date.now()}`;
      state.nodes.push({ kind: 'base', key, label: key, color_start: '#4a4a4a', color_end: '#2f2f2f', initial: false, exploit_text: 'Exploitation notes', position: { x: 80, y: 80 } });
      rebuild();
    };

    refs.addBranchBtn.onclick = () => {
      const id = `branch_${Date.now()}`;
      state.branches.push({ kind: 'branch', id, parent_id: '', label: id, title: id, text: '', position: { x: 520, y: 80 } });
      rebuild();
    };

    refs.addEdgeBtn.onclick = () => {
      const from = (refs.edgeFrom.value || '').trim();
      const to = (refs.edgeTo.value || '').trim();
      const label = refs.edgeLabel.value || '';
      if (!from || !to) return;
      state.edges.push({ from, to, label });
      rebuild();
    };

    refs.deleteBtn.onclick = () => {
      const sel = selectedModel();
      if (!sel) return;
      if (sel.kind === 'base') {
        state.nodes = state.nodes.filter((n) => n.key !== sel.key);
        state.edges = state.edges.filter((e) => e.from !== sel.key && e.to !== sel.key);
        state.branches = state.branches.filter((b) => b.parent_id !== sel.key);
      } else {
        state.branches = state.branches.filter((b) => b.id !== sel.id && b.parent_id !== sel.id);
      }
      state.selected = null;
      fillForm(null);
      rebuild();
    };

    refs.saveBtn.onclick = async () => {
      const payload = {
        title: state.title,
        phase_label: state.phase_label,
        nodes: state.nodes.map((n) => {
          const node = cy.getElementById(`n:${n.key}`);
          return {
            key: n.key,
            label: n.label,
            color_start: n.color_start,
            color_end: n.color_end,
            initial: n.initial ? 1 : 0,
            exploit_text: n.exploit_text || 'Exploitation notes',
            position: node.nonempty() ? node.position() : n.position,
          };
        }),
        edges: state.edges,
        vuln_branches: state.branches.map((b) => {
          const node = cy.getElementById(`b:${b.id}`);
          return {
            id: b.id,
            parent_id: b.parent_id,
            label: b.label,
            title: b.title,
            text: b.text,
            position: node.nonempty() ? node.position() : b.position,
          };
        }),
      };
      const r = await fetch(`/api/checklist-map/${state.mapName}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if (r.ok) window.location.href = state.mapName === 'authenticated' ? '/checklist' : '/checklist-unauthenticated';
    };

    const applySelected = () => {
      const sel = selectedModel();
      if (!sel) return;
      if (sel.kind === 'base') {
        sel.key = (refs.fId.value || '').trim() || sel.key;
        sel.label = refs.fLabel.value || sel.label;
        sel.color_start = refs.fColorStart.value || sel.color_start;
        sel.color_end = refs.fColorEnd.value || sel.color_end;
        sel.initial = !!refs.fInitial.checked;
        sel.exploit_text = refs.fText.value || '';
      } else {
        sel.id = (refs.fId.value || '').trim() || sel.id;
        sel.label = refs.fLabel.value || sel.label;
        sel.title = refs.fLabel.value || sel.title;
        sel.parent_id = (refs.fParent.value || '').trim();
        sel.text = refs.fText.value || '';
      }
      rebuild();
    };

    [refs.fId, refs.fLabel, refs.fParent, refs.fColorStart, refs.fColorEnd, refs.fText].forEach((el) => {
      el.oninput = applySelected;
    });
    refs.fInitial.onchange = applySelected;
  }

  cy.on('tap', 'node', (evt) => {
    const data = evt.target.data();
    if (String(data.id || '').startsWith('n:')) {
      const key = String(data.id).slice(2);
      state.selected = { kind: 'base', key };
    } else if (String(data.id || '').startsWith('b:')) {
      const id = String(data.id).slice(2);
      state.selected = { kind: 'branch', id };
    } else {
      state.selected = null;
    }
    fillForm(selectedModel());
  });

  cy.on('tap', (evt) => {
    if (evt.target === cy) {
      state.selected = null;
      fillForm(null);
    }
  });

  bindUI();
  rebuild();
  fillForm(null);
})();
