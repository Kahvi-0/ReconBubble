(function () {
  const ReactLib = window.React;
  const ReactDOMLib = window.ReactDOM;
  const RF = window.ReactFlow;
  if (!ReactLib || !ReactDOMLib || !RF) return;

  const e = ReactLib.createElement;
  const mapData = window.CHECKLIST_MAP_DATA || { nodes: [], edges: [], vuln_branches: [] };

  function toSlug(s) {
    return String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  }

  function gradient(node) {
    return "linear-gradient(135deg, " + (node.color_start || "#4a4a4a") + ", " + (node.color_end || "#2f2f2f") + ")";
  }

  const baseNodes = (mapData.nodes || []).map(function (n, i) {
    return {
      key: n.key || ("node_" + i),
      label: n.label || n.key || ("Node " + i),
      color_start: n.color_start || "#4a4a4a",
      color_end: n.color_end || "#2f2f2f",
      initial: n.initial === 1 || n.initial === true,
      exploit_text: n.exploit_text || "Exploitation notes",
      position: n.position || null,
    };
  });

  const branches = (mapData.vuln_branches || []).map(function (b, i) {
    const id = b.id || b.option_key || toSlug(b.label) || ("branch_" + i);
    return {
      id: id,
      parent_id: b.parent_id || b.parent_key || "",
      label: b.label || b.option_key || id,
      title: b.title || b.label || id,
      text: b.text || "",
      position: b.position || null,
    };
  });

  function branchChildren(parentId) {
    return branches.filter(function (b) { return b.parent_id === parentId; });
  }

  function saveChecklistKey(key, payload) {
    const fd = new FormData();
    Object.keys(payload).forEach(function (k) { fd.append(k, payload[k]); });
    return fetch("/api/checklist/" + key, { method: "POST", body: fd });
  }

  function saveVulnState(nodeKey, state) {
    return saveChecklistKey(nodeKey + "_vuln", { vuln: state });
  }

  function MainNode(props) {
    const d = props.data;
    const style = {
      background: d.bg,
      filter: d.greyed ? "grayscale(0.9) brightness(0.65)" : "none",
    };
    return e("div", { className: "rf-node", style: style },
      e("div", { className: "rf-node-header" }, d.label),
      d.initial ? e("div", { className: "rf-node-body" },
        e("div", { className: "rf-vuln-options" },
          e("button", { className: "rf-chip nodrag nopan " + (d.vulnState === "unchecked" ? "active-unchecked" : ""), onClick: function (ev) { ev.stopPropagation(); d.onSetVuln("unchecked"); } }, "Unchecked"),
          e("button", { className: "rf-chip nodrag nopan " + (d.vulnState === "vuln" ? "active-vuln" : ""), onClick: function (ev) { ev.stopPropagation(); d.onSetVuln("vuln"); } }, "Vulnerable"),
          e("button", { className: "rf-chip nodrag nopan " + (d.vulnState === "notvuln" ? "active-notvuln" : ""), onClick: function (ev) { ev.stopPropagation(); d.onSetVuln("notvuln"); } }, "Not Vulnerable")
        )
      ) : null
    );
  }

  function InfoNode(props) {
    const d = props.data;
    return e("div", { className: "rf-node", style: { background: d.bg } },
      e("div", { className: "rf-node-header" }, d.title),
      e("div", { className: "rf-node-body" },
        d.text ? e("div", null, d.text) : null,
        (d.branchOptions || []).length ? e("div", { className: "vuln-checks" },
          d.branchOptions.map(function (b) {
            return e("label", { key: b.id, className: "rf-branch" },
              e("input", {
                type: "checkbox",
                className: "nodrag nopan",
                checked: !!d.branchState[b.id],
                onClick: function (ev) { ev.stopPropagation(); },
                onChange: function (ev) { ev.stopPropagation(); d.onToggleBranch(b.id, ev.target.checked); }
              }),
              b.label
            );
          })
        ) : null
      )
    );
  }

  function App() {
    const useState = ReactLib.useState;
    const useMemo = ReactLib.useMemo;
    const useEffect = ReactLib.useEffect;

    const [status, setStatus] = useState({});
    const [branchState, setBranchState] = useState({});

    useEffect(function () {
      fetch('/api/checklist').then(function (r) { return r.json(); }).then(function (data) {
        const s = data || {};
        const bs = {};
        branches.forEach(function (b) { bs[b.id] = !!s["branch_" + b.id]; });
        setStatus(s);
        setBranchState(bs);
      });
    }, []);

    function isInitialVulnVisible(nodeKey) {
      return status[nodeKey + "_vuln"] === "vuln";
    }

    function isBranchVisible(branchId) {
      const b = branches.find(function (x) { return x.id === branchId; });
      if (!b) return false;
      if (!branchState[b.id]) return false;
      const parentBranch = branches.find(function (x) { return x.id === b.parent_id; });
      if (parentBranch) return isBranchVisible(parentBranch.id);
      return isInitialVulnVisible(b.parent_id);
    }

    async function clearDescendants(parentBranchId, nextBranchState) {
      const kids = branchChildren(parentBranchId);
      for (let i = 0; i < kids.length; i += 1) {
        const child = kids[i];
        nextBranchState[child.id] = false;
        await saveChecklistKey("branch_" + child.id, { done: 0 });
        await clearDescendants(child.id, nextBranchState);
      }
    }

    function layoutPositions() {
      const pos = {};
      let y = 40;
      baseNodes.forEach(function (n) {
        pos[n.key] = n.position || { x: 40, y: y };
        y += 170;
      });

      function placeChildren(parentId, parentPos) {
        const kids = branchChildren(parentId);
        let localY = parentPos.y;
        kids.forEach(function (b) {
          pos["branch__" + b.id] = b.position || { x: parentPos.x + 340, y: localY };
          placeChildren(b.id, pos["branch__" + b.id]);
          localY += 150;
        });
      }

      baseNodes.forEach(function (n) {
        pos["vuln__" + n.key] = { x: pos[n.key].x + 300, y: pos[n.key].y };
        placeChildren(n.key, pos["vuln__" + n.key]);
      });
      return pos;
    }

    const positions = useMemo(layoutPositions, []);

    const nodes = useMemo(function () {
      const out = [];

      baseNodes.forEach(function (n) {
        const vulnState = status[n.key + "_vuln"] || "unchecked";
        out.push({
          id: n.key,
          type: "mainNode",
          position: positions[n.key] || { x: 40, y: 40 },
          data: {
            label: n.label,
            initial: !!n.initial,
            vulnState: vulnState,
            greyed: !!n.initial && vulnState === "notvuln",
            bg: gradient(n),
            onSetVuln: async function (v) {
              const nextStatus = Object.assign({}, status, { [n.key + "_vuln"]: v });
              const nextBranch = Object.assign({}, branchState);
              if (v !== "vuln") {
                const roots = branchChildren(n.key);
                for (let i = 0; i < roots.length; i += 1) {
                  const r = roots[i];
                  nextBranch[r.id] = false;
                  await saveChecklistKey("branch_" + r.id, { done: 0 });
                  await clearDescendants(r.id, nextBranch);
                }
              }
              setStatus(nextStatus);
              setBranchState(nextBranch);
              await saveVulnState(n.key, v);
            },
          },
          draggable: false,
        });

        if (n.initial && vulnState === "vuln") {
          out.push({
            id: "vuln__" + n.key,
            type: "infoNode",
            position: positions["vuln__" + n.key] || { x: 340, y: 40 },
            data: {
              title: "Exploitation Notes",
              text: n.exploit_text || "Exploitation notes",
              branchOptions: branchChildren(n.key),
              branchState: branchState,
              bg: gradient(n),
              onToggleBranch: async function (id, checked) {
                const next = Object.assign({}, branchState, { [id]: !!checked });
                if (!checked) {
                  await clearDescendants(id, next);
                }
                setBranchState(next);
                await saveChecklistKey("branch_" + id, { done: checked ? 1 : 0 });
              },
            },
            draggable: false,
          });
        }
      });

      branches.forEach(function (b) {
        if (!isBranchVisible(b.id)) return;
        const parentBase = baseNodes.find(function (n) { return n.key === b.parent_id; });
        const parentBranch = branches.find(function (x) { return x.id === b.parent_id; });
        const colorRef = parentBase || (parentBranch && baseNodes.find(function (n) { return b.parent_id.indexOf(n.key) >= 0; })) || baseNodes[0] || {};
        out.push({
          id: "branch__" + b.id,
          type: "infoNode",
          position: positions["branch__" + b.id] || { x: 680, y: 40 },
          data: {
            title: b.title,
            text: b.text,
            branchOptions: branchChildren(b.id),
            branchState: branchState,
            bg: gradient(colorRef),
            onToggleBranch: async function (id, checked) {
              const next = Object.assign({}, branchState, { [id]: !!checked });
              if (!checked) {
                await clearDescendants(id, next);
              }
              setBranchState(next);
              await saveChecklistKey("branch_" + id, { done: checked ? 1 : 0 });
            },
          },
          draggable: false,
        });
      });

      return out;
    }, [status, branchState]);

    const edges = useMemo(function () {
      const out = [];

      (mapData.edges || []).forEach(function (ed, i) {
        out.push({ id: "map-" + i, source: ed.from, target: ed.to, label: ed.label || "" });
      });

      baseNodes.forEach(function (n) {
        if (n.initial && isInitialVulnVisible(n.key)) {
          out.push({ id: "vx-" + n.key, source: n.key, target: "vuln__" + n.key });
        }
      });

      branches.forEach(function (b) {
        if (!isBranchVisible(b.id)) return;
        const parentBranch = branches.find(function (x) { return x.id === b.parent_id; });
        const source = parentBranch ? ("branch__" + parentBranch.id) : ("vuln__" + b.parent_id);
        out.push({ id: "be-" + source + "-" + b.id, source: source, target: "branch__" + b.id });
      });

      return out;
    }, [status, branchState]);

    return e(RF.ReactFlow,
      {
        nodes: nodes,
        edges: edges,
        nodeTypes: { mainNode: MainNode, infoNode: InfoNode },
        fitView: true,
        minZoom: 0.3,
        maxZoom: 1.8,
        defaultEdgeOptions: { type: "smoothstep", markerEnd: { type: RF.MarkerType.ArrowClosed } },
        nodesDraggable: false,
        nodesConnectable: false,
        elementsSelectable: false,
      },
      e(RF.Background, { gap: 18, color: "#242424" }),
      e(RF.Controls, null),
      e(RF.MiniMap, null)
    );
  }

  ReactDOMLib.render(e(App), document.getElementById("mindmap-view"));
})();
