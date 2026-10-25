import { useMemo } from "react";
import {
  Background,
  Controls,
  ReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import "./RepositoryMap.css";

function cleanPath(value) {
  return String(value || "")
    .replaceAll("\\", "/")
    .split("/")
    .filter((part) => part && part !== "." && part !== "..")
    .join("/");
}

function makeTree(paths) {
  const root = { name: "Repository", type: "directory", children: new Map() };
  for (const path of paths) {
    const parts = path.split("/");
    let cursor = root;
    parts.forEach((part, index) => {
      const isFile = index === parts.length - 1;
      const key = `${isFile ? "file" : "directory"}:${part}`;
      if (!cursor.children.has(key)) {
        cursor.children.set(key, {
          name: part,
          type: isFile ? "file" : "directory",
          children: new Map(),
        });
      }
      cursor = cursor.children.get(key);
    });
  }
  return root;
}

function makeGraph(root) {
  const nodes = [];
  const edges = [];
  let row = 0;

  function visit(treeNode, parentId, depth) {
    const nodeId = depth === 0 ? "repository-root" : `${parentId}/${treeNode.type}:${treeNode.name}`;
    const y = row++ * 105;
    nodes.push({
      id: nodeId,
      type: "default",
      position: { x: depth * 270, y },
      data: { label: treeNode.name, mapType: treeNode.type },
      className: `repository-map-node ${treeNode.type}`,
      sourcePosition: "right",
      targetPosition: "left",
    });
    if (parentId) {
      edges.push({
        id: `${parentId}->${nodeId}`,
        source: parentId,
        target: nodeId,
        type: "smoothstep",
        style: { stroke: "var(--edge-observed)", strokeWidth: 1.5 },
      });
    }
    [...treeNode.children.values()]
      .sort((a, b) => a.type.localeCompare(b.type) || a.name.localeCompare(b.name))
      .forEach((child) => visit(child, nodeId, depth + 1));
  }

  visit(root, "", 0);
  return { nodes, edges };
}

function TreeItems({ node }) {
  const children = [...node.children.values()]
    .sort((a, b) => a.type.localeCompare(b.type) || a.name.localeCompare(b.name));
  return (
    <li>
      <span className={`repository-tree-label ${node.type}`}>
        <span aria-hidden="true">{node.type === "directory" ? "▸" : "·"}</span>
        {node.name}
      </span>
      {children.length > 0 && <ul>{children.map((child) => <TreeItems key={`${child.type}:${child.name}`} node={child} />)}</ul>}
    </li>
  );
}

export default function RepositoryMap({ findings = [] }) {
  const paths = useMemo(() => [...new Set(
    findings.map((finding) => cleanPath(finding.file_path)).filter((path) => path && path !== "unknown")
  )].sort(), [findings]);
  const tree = useMemo(() => makeTree(paths), [paths]);
  const graph = useMemo(() => makeGraph(tree), [tree]);

  if (!paths.length) {
    return <div className="empty-state repository-map-empty"><strong>No file paths were returned with this scan</strong><p>The backend currently reports the number of analyzed files but does not expose their complete inventory. This view only maps file paths attached to actual findings.</p></div>;
  }

  return (
    <section className="repository-map-page">
      <div className="repository-map-notice" role="note">
        <strong>Finding-linked paths only</strong>
        <span>This is a partial view from real finding locations. It does not represent every file in the repository or infer code dependencies.</span>
      </div>
      <div className="repository-map-stats"><span><strong>{paths.length}</strong> unique files with findings</span><span><strong>{graph.nodes.length - paths.length - 1}</strong> parent directories shown</span></div>
      <div className="repository-map-layout">
        <section className="repository-map-panel repository-map-graph-panel">
          <div className="repository-map-heading"><div><p className="eyebrow">VISUAL STRUCTURE</p><h2>Path graph</h2></div><span>Directory → file</span></div>
          <div className="repository-map-canvas" role="region" aria-label="Graph of repository paths associated with findings">
            <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView fitViewOptions={{ padding: 0.18 }} minZoom={0.15} maxZoom={1.5} nodesDraggable={false} nodesConnectable={false} elementsSelectable={false} proOptions={{ hideAttribution: true }}>
              <Background color="var(--graph-grid)" gap={20} />
              <Controls showZoom showFitView position="bottom-left" />
            </ReactFlow>
          </div>
        </section>
        <section className="repository-map-panel repository-map-tree-panel">
          <div className="repository-map-heading"><div><p className="eyebrow">SIMPLE FORMAT</p><h2>Folder tree</h2></div><span>{paths.length} files</span></div>
          <div className="repository-tree-scroll"><ul className="repository-tree"><TreeItems node={tree} /></ul></div>
        </section>
      </div>
    </section>
  );
}
