(function () {
  const ReactLib = window.React;
  const ReactDOMLib = window.ReactDOM;
  const RF = window.ReactFlow;
  if (!ReactLib || !ReactDOMLib || !RF) return;

  const e = ReactLib.createElement;
  const mapData = window.CHECKLIST_MAP_DATA || { nodes: [], edges: [], vuln_branches: [] };
  const initialMapName = window.CHECKLIST_MAP_NAME || "authenticated";

  function toSlug(s) {
    return String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  }

  function stopEv(ev) {
    if (!ev) return;
    ev.stopPropagation();
  }

  function grad(start, end) {
    return "linear-gradient(135deg, " + (start || "#4a4a4a") + ", " + (end || "#2f2f2f") + ")";
  }

  function BaseNodeEditor(props) {
    const d = props.data;
    return e("div", { className: "rf-edit-node", style: { background: grad(d.color_start, d.color_end) } },
      e("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
        e("strong", null, "Node"),
        e("label", { style: { fontSize: "11px", display: "flex", gap: "6px", alignItems: "center" } },
          e("input", { className: "nodrag nopan", type: "checkbox", checked: !!d.initial, onPointerDown: stopEv, onMouseDown: stopEv, onClick: stopEv, onChange: function (ev) { stopEv(ev); d.onChange("initial", ev.target.checked); } }),
          "Initial"
        )
      ),
      e("input", { className: "nodrag nopan", value: d.key || "", placeholder: "key", onPointerDown: stopEv, onMouseDown: stopEv, onClick: stopEv, onChange: function (ev) { stopEv(ev); d.onChange("key", ev.target.value); } }),
      e("input", { className: "nodrag nopan", value: d.label || "", placeholder: "label", onPointerDown: stopEv, onMouseDown: stopEv, onClick: stopEv, onChange: function (ev) { stopEv(ev); d.onChange("label", ev.target.value); } }),
      e("input", { className: "nodrag nopan", value: d.color_start || "", placeholder: "#start", onPointerDown: stopEv, onMouseDown: stopEv, onClick: stopEv, onChange: function (ev) { stopEv(ev); d.onChange("color_start", ev.target.value); } }),
      e("input", { className: "nodrag nopan", value: d.color_end || "", placeholder: "#end", onPointerDown: stopEv, onMouseDown: stopEv, onClick: stopEv, onChange: function (ev) { stopEv(ev); d.onChange("color_end", ev.target.value); } }),
      e("input", { className: "nodrag nopan", value: d.exploit_text || "", placeholder: "initial vuln text", onPointerDown: stopEv, onMouseDown: stopEv, onClick: stopEv, onChange: function (ev) { stopEv(ev); d.onChange("exploit_text", ev.target.value); } }),
      e("button", { className: "btn nodrag nopan", onPointerDown: stopEv, onMouseDown: stopEv, onClick: function (ev) { stopEv(ev); d.onDelete(); } }, "Delete")
    );
  }

  function BranchNodeEditor(props) {
    const d = props.data;
    return e("div", { className: "rf-edit-node", style: { background: "linear-gradient(135deg,#475569,#334155)" } },
      e("strong", null, "Vulnerable Branch"),
      e("input", { className: "nodrag nopan", value: d.id || "", placeholder: "branch id", onPointerDown: stopEv, onMouseDown: stopEv, onClick: stopEv, onChange: function (ev) { stopEv(ev); d.onChange("id", ev.target.value); } }),
      e("input", { className: "nodrag nopan", value: d.parent_id || "", placeholder: "parent id (node key or branch id)", onPointerDown: stopEv, onMouseDown: stopEv, onClick: stopEv, onChange: function (ev) { stopEv(ev); d.onChange("parent_id", ev.target.value); } }),
      e("input", { className: "nodrag nopan", value: d.label || "", placeholder: "checkbox label", onPointerDown: stopEv, onMouseDown: stopEv, onClick: stopEv, onChange: function (ev) { stopEv(ev); d.onChange("label", ev.target.value); } }),
      e("input", { className: "nodrag nopan", value: d.title || "", placeholder: "child title", onPointerDown: stopEv, onMouseDown: stopEv, onClick: stopEv, onChange: function (ev) { stopEv(ev); d.onChange("title", ev.target.value); } }),
      e("input", { className: "nodrag nopan", value: d.text || "", placeholder: "child text", onPointerDown: stopEv, onMouseDown: stopEv, onClick: stopEv, onChange: function (ev) { stopEv(ev); d.onChange("text", ev.target.value); } }),
      e("button", { className: "btn nodrag nopan", onPointerDown: stopEv, onMouseDown: stopEv, onClick: function (ev) { stopEv(ev); d.onDelete(); } }, "Delete")
    );
  }

  function App() {
    const useState = ReactLib.useState;
    const useMemo = ReactLib.useMemo;

    const [mapName, setMapName] = useState(initialMapName);
    const [title, setTitle] = useState(mapData.title || "");
    const [phaseLabel, setPhaseLabel] = useState(mapData.phase_label || "Enumeration");

    const baseInitial = (mapData.nodes || []).map(function (n, i) {
      const id = "node__" + (n.key || ("node_" + i));
      return {
        id: id,
        type: "baseEdit",
        position: n.position || { x: 80, y: 80 + i * 170 },
        data: {
          key: n.key || "",
          label: n.label || "",
          color_start: n.color_start || "#4a4a4a",
          color_end: n.color_end || "#2f2f2f",
          initial: n.initial === 1 || n.initial === true,
          exploit_text: n.exploit_text || "Exploitation notes",
        },
      };
    });

    const branchInitial = (mapData.vuln_branches || []).map(function (b, i) {
      const idVal = b.id || b.option_key || toSlug(b.label) || ("branch_" + i);
      return {
        id: "branch__" + idVal,
        type: "branchEdit",
        position: b.position || { x: 560, y: 80 + i * 150 },
        data: {
          id: idVal,
          parent_id: b.parent_id || b.parent_key || "",
          label: b.label || "",
          title: b.title || "",
          text: b.text || "",
        },
      };
    });

    const [nodes, setNodes, onNodesChange] = RF.useNodesState(baseInitial.concat(branchInitial));

    const mapEdges = (mapData.edges || []).map(function (ed, i) {
      return {
        id: "map_" + i,
        source: "node__" + ed.from,
        target: "node__" + ed.to,
        label: ed.label || "",
        data: { kind: "map" },
        markerEnd: { type: RF.MarkerType.ArrowClosed },
      };
    });
    const [edges, setEdges, onEdgesChange] = RF.useEdgesState(mapEdges);

    function updateNodeData(nodeId, field, value) {
      setNodes(function (nds) {
        return nds.map(function (n) {
          if (n.id !== nodeId) return n;
          return Object.assign({}, n, { data: Object.assign({}, n.data, { [field]: value }) });
        });
      });
    }

    function deleteNode(nodeId) {
      setNodes(function (nds) { return nds.filter(function (n) { return n.id !== nodeId; }); });
      setEdges(function (eds) { return eds.filter(function (ed) { return ed.source !== nodeId && ed.target !== nodeId; }); });
    }

    const nodeTypes = useMemo(function () {
      return {
        baseEdit: function (props) {
          return e(BaseNodeEditor, {
            data: Object.assign({}, props.data, {
              onChange: function (field, value) { updateNodeData(props.id, field, value); },
              onDelete: function () { deleteNode(props.id); },
            })
          });
        },
        branchEdit: function (props) {
          return e(BranchNodeEditor, {
            data: Object.assign({}, props.data, {
              onChange: function (field, value) { updateNodeData(props.id, field, value); },
              onDelete: function () { deleteNode(props.id); },
            })
          });
        }
      };
    }, [nodes]);

    const autoBranchEdges = useMemo(function () {
      const out = [];
      nodes.filter(function (n) { return n.type === "branchEdit"; }).forEach(function (bn) {
        const p = bn.data.parent_id;
        if (!p) return;
        const parentBranch = nodes.find(function (n) { return n.type === "branchEdit" && n.data.id === p; });
        const source = parentBranch ? parentBranch.id : "node__" + p;
        out.push({
          id: "auto_" + source + "_" + bn.id,
          source: source,
          target: bn.id,
          data: { kind: "auto" },
          style: { strokeDasharray: "4 4" },
          markerEnd: { type: RF.MarkerType.ArrowClosed },
        });
      });
      return out;
    }, [nodes]);

    const allEdges = useMemo(function () {
      const manual = edges.filter(function (ed) { return !ed.data || ed.data.kind !== "auto"; });
      return manual.concat(autoBranchEdges);
    }, [edges, autoBranchEdges]);

    function addNode() {
      const id = "node__new_" + Date.now();
      setNodes(function (nds) {
        return nds.concat([{ id: id, type: "baseEdit", position: { x: 120, y: 120 }, data: { key: "", label: "", color_start: "#4a4a4a", color_end: "#2f2f2f", initial: false, exploit_text: "Exploitation notes" } }]);
      });
    }

    function addBranch() {
      const idVal = "branch_" + Date.now();
      setNodes(function (nds) {
        return nds.concat([{ id: "branch__" + idVal, type: "branchEdit", position: { x: 560, y: 120 }, data: { id: idVal, parent_id: "", label: "", title: "", text: "" } }]);
      });
    }

    function onConnect(params) {
      if (!String(params.source || "").startsWith("node__") || !String(params.target || "").startsWith("node__")) {
        return;
      }
      setEdges(function (eds) {
        return RF.addEdge(Object.assign({}, params, { markerEnd: { type: RF.MarkerType.ArrowClosed }, data: { kind: "map" } }), eds);
      });
    }

    async function saveMap() {
      const baseNodes = nodes.filter(function (n) { return n.type === "baseEdit"; }).map(function (n) {
        const key = n.data.key || n.id.replace(/^node__/, "");
        return {
          key: key,
          label: n.data.label || key,
          color_start: n.data.color_start || "#4a4a4a",
          color_end: n.data.color_end || "#2f2f2f",
          initial: n.data.initial ? 1 : 0,
          exploit_text: n.data.exploit_text || "Exploitation notes",
          position: n.position,
        };
      });

      const branchNodes = nodes.filter(function (n) { return n.type === "branchEdit"; }).map(function (n, i) {
        const idVal = n.data.id || toSlug(n.data.label) || ("branch_" + i);
        return {
          id: idVal,
          parent_id: n.data.parent_id || "",
          label: n.data.label || idVal,
          title: n.data.title || n.data.label || idVal,
          text: n.data.text || "",
          position: n.position,
        };
      });

      const keyByNodeId = {};
      baseNodes.forEach(function (n) { keyByNodeId["node__" + n.key] = n.key; });

      const manualEdges = edges
        .filter(function (ed) { return (!ed.data || ed.data.kind === "map") && String(ed.source).startsWith("node__") && String(ed.target).startsWith("node__"); })
        .map(function (ed) {
          const from = keyByNodeId[ed.source] || String(ed.source).replace(/^node__/, "");
          const to = keyByNodeId[ed.target] || String(ed.target).replace(/^node__/, "");
          return { from: from, to: to, label: ed.label || "" };
        });

      const payload = {
        title: title,
        phase_label: phaseLabel,
        nodes: baseNodes,
        edges: manualEdges,
        vuln_branches: branchNodes,
      };

      const r = await fetch("/api/checklist-map/" + mapName, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (r.ok) {
        window.location.href = mapName === "authenticated" ? "/checklist" : "/checklist-unauthenticated";
      }
    }

    ReactLib.useEffect(function () {
      const addNodeBtn = document.getElementById("addNodeBtn");
      const addBranchBtn = document.getElementById("addBranchBtn");
      const saveBtn = document.getElementById("saveBtn");
      const mapNameSelect = document.getElementById("mapName");
      const mapTitle = document.getElementById("mapTitle");
      const phase = document.getElementById("phaseLabel");
      if (addNodeBtn) addNodeBtn.onclick = addNode;
      if (addBranchBtn) addBranchBtn.onclick = addBranch;
      if (saveBtn) saveBtn.onclick = saveMap;
      if (mapTitle) mapTitle.oninput = function (ev) { setTitle(ev.target.value); };
      if (phase) phase.oninput = function (ev) { setPhaseLabel(ev.target.value); };
      if (mapNameSelect) {
        mapNameSelect.onchange = function (ev) {
          const n = ev.target.value;
          setMapName(n);
          window.location.href = "/checklist/edit?map_name=" + n;
        };
      }
    });

    return e(RF.ReactFlow,
      {
        nodes: nodes,
        edges: allEdges,
        nodeTypes: nodeTypes,
        onNodesChange: onNodesChange,
        onEdgesChange: onEdgesChange,
        onConnect: onConnect,
        fitView: true,
        minZoom: 0.25,
        maxZoom: 2,
        defaultEdgeOptions: { type: "smoothstep", markerEnd: { type: RF.MarkerType.ArrowClosed } },
        nodesDraggable: false,
        panOnDrag: false,
        elementsSelectable: true,
      },
      e(RF.Background, { gap: 18, color: "#242424" }),
      e(RF.Controls, null),
      e(RF.MiniMap, null)
    );
  }

  ReactDOMLib.render(e(App), document.getElementById("mindmap-editor"));
})();
