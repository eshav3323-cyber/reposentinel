import { useMemo, useState } from "react";
import {
  Background,
  BaseEdge,
  Controls,
  EdgeLabelRenderer,
  getBezierPath,
  MarkerType,
  ReactFlow,
  Handle,
  Position,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import "./AttackGraph.css";

const NODE_COLORS = {
  entry_point: "var(--node-neutral)",
  component: "var(--node-forest)",
  dependency: "var(--node-sage)",
  finding: "var(--severity-medium)",
  asset: "var(--forest)",
};

const SEVERITY_COLORS = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
  info: "var(--node-neutral)",
  unknown: "var(--node-neutral)",
};

const TYPE_ORDER = {
  entry_point: 0,
  component: 1,
  dependency: 2,
  finding: 3,
  asset: 4,
};

function formatLabel(value) {
  return String(value || "Unknown")
    .replaceAll("_", " ")
    .replaceAll("-", " ");
}

function GraphNode({ data, selected }) {
  const nodeColor = NODE_COLORS[data.nodeType] || "var(--node-neutral)";
  const riskColor =
    data.nodeType === "finding"
      ? SEVERITY_COLORS[data.riskLevel] || SEVERITY_COLORS.unknown
      : nodeColor;

  async function copyNodeDetails(event) {
    event.preventDefault();
    event.stopPropagation();

    const lines = [
      `${formatLabel(data.nodeType)}: ${data.label}`,
      `Severity: ${formatLabel(data.riskLevel)}`,
      `Evidence: ${formatLabel(data.evidenceType)}`,
      data.fileLocation ? `Location: ${data.fileLocation}` : null,
      data.description ? `Why it matters: ${data.description}` : null,
      data.remediation ? `Suggested review: ${data.remediation}` : null,
      data.sourceScanner ? `Detected by: ${data.sourceScanner}` : null,
    ].filter(Boolean);

    const payload = lines.join("\n");

    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(payload);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = payload;
        textarea.setAttribute("readonly", "");
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      event.currentTarget.textContent = "Copied";
      window.setTimeout(() => {
        event.currentTarget.textContent = "Copy bug";
      }, 1200);
    } catch (error) {
      console.error("Failed to copy graph node details", error);
    }
  }

  return (
    <div
      className={`attack-graph-node ${
        selected ? "selected" : ""
      }`}
      style={{
        "--node-color": nodeColor,
        "--risk-color": riskColor,
      }}
      tabIndex={0}
      role="group"
      aria-label={`${formatLabel(data.nodeType)}: ${data.label}. ${formatLabel(data.riskLevel)} severity. Focus or hover for details.`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="attack-graph-handle"
      />

      <div className="attack-graph-node-type">
        {formatLabel(data.nodeType)}
      </div>

      <div className="attack-graph-node-label">
        {data.label}
      </div>

      <div className="attack-graph-node-meta">
        <span className="node-risk">
          {formatLabel(data.riskLevel)}
        </span>
        <span>{formatLabel(data.evidenceType)}</span>
      </div>

      <div className={`attack-graph-node-tooltip ${data.nodeType === "finding" || data.nodeType === "asset" ? "left" : "right"}`} role="note">
        <strong>{data.nodeType === "finding" ? "Vulnerability details" : formatLabel(data.nodeType)}</strong>
        <span className="attack-graph-tooltip-title">{data.label}</span>
        {data.fileLocation && <span className="attack-graph-tooltip-location">{data.fileLocation}</span>}
        <span className="attack-graph-tooltip-section">Why it matters</span>
        <p>{data.description || "No additional explanation was returned for this graph node."}</p>
        {data.remediation && <><span className="attack-graph-tooltip-section">Suggested review</span><p>{data.remediation}</p></>}
        <div className="attack-graph-tooltip-meta">
          <span>{formatLabel(data.riskLevel)} severity</span>
          <span>{formatLabel(data.evidenceType)} evidence</span>
          {data.sourceScanner && <span>Detected by {data.sourceScanner}</span>}
        </div>
        {(data.nodeType === "finding" || data.description || data.remediation || data.fileLocation) && (
          <button type="button" className="attack-graph-copy-button" onClick={copyNodeDetails}>Copy bug</button>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="attack-graph-handle"
      />
    </div>
  );
}

const nodeTypes = {
  attackNode: GraphNode,
};

function RelationshipEdge({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, style, data }) {
  const [path] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, curvature: 0.24 });
  const coordinates = path.match(/[-+]?(?:\d*\.\d+|\d+\.?\d*)(?:[eE][-+]?\d+)?/g)?.map(Number) || [];
  // Keep the relationship badge beside the destination node, not halfway
  // along long edges where it can read like a detached heading.
  const t = 0.96;
  const inverseT = 1 - t;
  const labelX = coordinates.length >= 8
    ? inverseT ** 3 * coordinates[0] + 3 * inverseT ** 2 * t * coordinates[2] + 3 * inverseT * t ** 2 * coordinates[4] + t ** 3 * coordinates[6]
    : sourceX + (targetX - sourceX) * t;
  const labelY = coordinates.length >= 8
    ? inverseT ** 3 * coordinates[1] + 3 * inverseT ** 2 * t * coordinates[3] + 3 * inverseT * t ** 2 * coordinates[5] + t ** 3 * coordinates[7]
    : sourceY + (targetY - sourceY) * t;
  const relationship = data?.edgeType || "contains";
  if (!data?.showLabel) {
    return <BaseEdge id={id} path={path} markerEnd={markerEnd} style={style} />;
  }
  return <>
    <BaseEdge id={id} path={path} markerEnd={markerEnd} style={style} />
    <EdgeLabelRenderer>
      <div
        className={`attack-graph-edge-label ${relationship}`}
        style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
        aria-label={`${formatLabel(relationship)} relationship: ${data?.description || "No additional details"}`}
      >
        {formatLabel(relationship).toUpperCase()}
      </div>
    </EdgeLabelRenderer>
  </>;
}

const edgeTypes = { relationship: RelationshipEdge };

function getGroupedPosition(node, index, counts) {
  const type = node.node_type || "component";

  // Put each type in a dedicated vertical band.
  // Findings are spread across multiple columns to avoid one
  // extremely tall column when scanner results are numerous.
  if (type === "entry_point") {
    return {
      x: 40 + (index % 2) * 260,
      y: 30 + Math.floor(index / 2) * 155,
    };
  }

  if (type === "component" || type === "dependency") {
    const componentIndex = counts.componentIndex++;
    return {
      x: 390 + (componentIndex % 3) * 270,
      y: 30 + Math.floor(componentIndex / 3) * 155,
    };
  }

  if (type === "finding") {
    const findingIndex = counts.findingIndex++;
    return {
      x: 1210 + (findingIndex % 4) * 270,
      y: 30 + Math.floor(findingIndex / 4) * 155,
    };
  }

  const assetIndex = counts.assetIndex++;
  return {
    x: 2350 + (assetIndex % 2) * 270,
    y: 30 + Math.floor(assetIndex / 2) * 155,
  };
}

function getEdgeColor(edge) {
  return edge.evidence_type === "observed"
    ? "var(--edge-observed)"
    : "var(--edge-modeled)";
}

export default function AttackGraph({
  graph,
  findings = [],
  loading = false,
  error = "",
}) {
  const [selectedPathId, setSelectedPathId] = useState("all");
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [copiedPathId, setCopiedPathId] = useState(null);
  const [copiedNodeId, setCopiedNodeId] = useState(null);

  const { nodes, edges, paths } = useMemo(() => {
    const rawNodes = graph?.nodes || [];
    const rawEdges = graph?.edges || [];
    const rawPaths = graph?.attack_paths || [];

    const sortedNodes = [...rawNodes].sort((a, b) => {
      const orderA = TYPE_ORDER[a.node_type] ?? 99;
      const orderB = TYPE_ORDER[b.node_type] ?? 99;

      return orderA - orderB || a.label.localeCompare(b.label);
    });

    const counts = {
      componentIndex: 0,
      findingIndex: 0,
      assetIndex: 0,
    };
    const findingsByNodeId = new Map(findings.map((finding) => [`finding-${finding.id}`, finding]));

    const mappedNodes = sortedNodes.map((node, index) => ({
      id: node.id,
      type: "attackNode",
      position: getGroupedPosition(node, index, counts),
      data: {
        label: node.label,
        nodeType: node.node_type,
        riskLevel: node.risk_level,
        evidenceType: node.evidence_type,
        description: node.description,
        ...(findingsByNodeId.has(node.id) ? {
          fileLocation: `${findingsByNodeId.get(node.id).file_path || "Unknown file"}${findingsByNodeId.get(node.id).line_number ? `:${findingsByNodeId.get(node.id).line_number}` : ""}`,
          sourceScanner: findingsByNodeId.get(node.id).source_scanner,
          remediation: findingsByNodeId.get(node.id).remediation,
        } : {}),
      },
    }));

    const knownIds = new Set(rawNodes.map((node) => node.id));
    const labeledRelationshipTargets = new Set();

    const mappedEdges = rawEdges
      .filter(
        (edge) =>
          knownIds.has(edge.source) && knownIds.has(edge.target)
      )
      .map((edge, index) => {
        const labelKey = `${edge.target}:${edge.edge_type}`;
        // Keep dense structural links visible as edges, but label only the
        // relationships that add useful security context. Repeated labels
        // are collapsed when several findings converge on one target.
        const showLabel = ["exposes", "may_reach", "depends_on"].includes(edge.edge_type)
          && !labeledRelationshipTargets.has(labelKey);
        if (showLabel) labeledRelationshipTargets.add(labelKey);
        return {
        id: `${edge.source}-${edge.edge_type}-${edge.target}-${index}`,
        source: edge.source,
        target: edge.target,
        type: "relationship",
        data: { edgeType: edge.edge_type, showLabel, description: `${edge.description || "Repository relationship"} (${formatLabel(edge.evidence_type)} evidence)` },
        markerEnd: { type: MarkerType.ArrowClosed, color: getEdgeColor(edge), width: 16, height: 16 },
        animated: edge.evidence_type === "modeled",
        style: {
          stroke: getEdgeColor(edge),
          strokeWidth: edge.evidence_type === "observed" ? 1.8 : 1.4,
          opacity: edge.evidence_type === "observed" ? 0.8 : 0.55,
        },
      };
      });

    return {
      nodes: mappedNodes,
      edges: mappedEdges,
      paths: rawPaths,
    };
  }, [graph, findings]);

  const selectedPath = paths.find(
    (path) => path.id === selectedPathId
  );

  const selectedNode = useMemo(
    () => nodes.find((node) => node.id === selectedNodeId) || null,
    [nodes, selectedNodeId]
  );

  const selectedPathFixes = useMemo(() => {
    if (!selectedPath) return [];
    const pathNodeIds = new Set(
      (selectedPath.node_ids || []).flatMap((nodeId) => [String(nodeId), `finding-${String(nodeId)}`])
    );

    return findings
      .map((finding) => {
        const id = String(finding.id ?? "");
        const remediation = finding.remediation || finding.fix_method || finding.suggested_fix || "";
        if (!remediation) return null;

        if (pathNodeIds.has(id) || pathNodeIds.has(`finding-${id}`)) {
          return remediation.trim();
        }

        return null;
      })
      .filter(Boolean);
  }, [findings, selectedPath]);

  const selectedNodeIds = useMemo(
    () =>
      new Set(
        selectedPath?.node_ids || []
      ),
    [selectedPath]
  );

  const displayedNodes = useMemo(() => {
    if (!selectedPath || selectedPathId === "all") {
      return nodes.map((node) => ({
        ...node,
        style: node.id === selectedNodeId ? { ...node.style, border: "2px solid var(--emerald)" } : node.style,
      }));
    }

    return nodes.map((node) => ({
      ...node,
      style: {
        ...node.style,
        opacity: selectedNodeIds.has(node.id) ? 1 : 0.2,
        border: node.id === selectedNodeId ? "2px solid var(--emerald)" : node.style?.border,
      },
    }));
  }, [nodes, selectedPath, selectedPathId, selectedNodeIds, selectedNodeId]);

  const displayedEdges = useMemo(() => {
    if (!selectedPath || selectedPathId === "all") {
      return edges;
    }

    const pathNodes = selectedPath.node_ids;

    return edges.map((edge) => {
      const belongsToPath =
        pathNodes.includes(edge.source) &&
        pathNodes.includes(edge.target);

      return {
        ...edge,
        style: {
          ...edge.style,
          opacity: belongsToPath ? 1 : 0.08,
          stroke: belongsToPath ? "var(--emerald)" : "var(--border-strong)",
          strokeWidth: belongsToPath ? 3 : 1,
        },
        animated: belongsToPath && edge.animated,
      };
    });
  }, [edges, selectedPath, selectedPathId]);

  async function copyText(value) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = value;
        textarea.setAttribute("readonly", "");
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      return true;
    } catch (error) {
      console.error("Failed to copy attack path data", error);
      return false;
    }
  }

  async function handleCopyPath(path) {
    if (!path) return;
    const fixes = findings
      .map((finding) => {
        const id = String(finding.id ?? "");
        const remediation = finding.remediation || finding.fix_method || finding.suggested_fix || "";
        if (!remediation) return null;
        if ((path.node_ids || []).includes(id) || (path.node_ids || []).includes(`finding-${id}`)) {
          return remediation.trim();
        }
        return null;
      })
      .filter(Boolean);

    const text = [
      `Path: ${path.title}`,
      `Risk: ${formatLabel(path.risk_level)}`,
      `Explanation: ${path.explanation || "No explanation provided."}`,
      `Fix method: ${fixes.length ? fixes.join("\n- ") : "No explicit remediation guidance was provided for this path."}`,
      `Node IDs: ${(path.node_ids || []).join(", ")}`,
    ].join("\n");

    const copied = await copyText(text);
    if (copied) {
      setCopiedPathId(path.id);
      window.setTimeout(() => {
        setCopiedPathId((current) => (current === path.id ? null : current));
      }, 1200);
    }
  }

  async function handleCopySelectedPath() {
    if (!selectedPath) return;
    await handleCopyPath(selectedPath);
  }

  async function handleCopyNode(node) {
    if (!node || !node.data) return;
    const text = [
      `${formatLabel(node.data.nodeType)}: ${node.data.label}`,
      `Severity: ${formatLabel(node.data.riskLevel)}`,
      `Evidence: ${formatLabel(node.data.evidenceType)}`,
      node.data.fileLocation ? `Location: ${node.data.fileLocation}` : null,
      node.data.description ? `Why it matters: ${node.data.description}` : null,
      node.data.remediation ? `Suggested review: ${node.data.remediation}` : null,
      node.data.sourceScanner ? `Detected by: ${node.data.sourceScanner}` : null,
    ].filter(Boolean).join("\n");

    const copied = await copyText(text);
    if (copied) {
      setCopiedNodeId(node.id);
      window.setTimeout(() => {
        setCopiedNodeId((current) => (current === node.id ? null : current));
      }, 1200);
    }
  }

  async function handleCopySelectedNode() {
    if (!selectedNode || !selectedNode.data) return;
    await handleCopyNode(selectedNode);
  }

  if (loading) {
    return (
      <div className="attack-graph-message">
        <span className="loading-spinner" />
        Building the attack graph…
      </div>
    );
  }

  if (error) {
    return (
      <div className="attack-graph-message attack-graph-error">
        {error}
      </div>
    );
  }

  if (!graph) {
    return (
      <div className="attack-graph-message">
        Upload and scan a repository to view its attack graph.
      </div>
    );
  }

  if (nodes.length === 0) {
    return (
      <div className="attack-graph-message">
        This scan returned no graph nodes.
      </div>
    );
  }

  return (
    <div className="attack-graph-wrapper">
      <div className="attack-graph-toolbar">
        <div className="graph-toolbar-counts">
          <span><strong>{nodes.length}</strong> nodes</span>
          <span><strong>{edges.length}</strong> relationships</span>
          <span><strong>{paths.length}</strong> modeled paths</span>
        </div>

        <label className="graph-path-filter">
          <span>Explore path</span>
          <select
            value={selectedPathId}
            onChange={(event) => {
              setSelectedPathId(event.target.value);
              if (event.target.value === "all") setSelectedNodeId(null);
            }}
          >
            <option value="all">Show full graph</option>
            {paths.map((path) => (
              <option key={path.id} value={path.id}>
                {path.title}
              </option>
            ))}
          </select>
        </label>
      </div>

      {paths.length > 0 && (
        <div className="graph-path-list" aria-label="Modeled attack paths">
          {paths.map((path) => {
            const isSelected = path.id === selectedPathId;
            const isCopied = copiedPathId === path.id;
            return (
              <button
                key={path.id}
                type="button"
                className={`graph-path-item ${isSelected ? "selected" : ""}`}
                onClick={() => setSelectedPathId(path.id)}
              >
                <span className="graph-path-item-title">{path.title}</span>
                <span className="graph-path-item-meta">{formatLabel(path.risk_level)} risk</span>
                <span
                  className="graph-path-copy-inline"
                  onClick={(event) => {
                    event.stopPropagation();
                    void handleCopyPath(path);
                  }}
                  role="button"
                  tabIndex={0}
                  aria-label={`Copy path ${path.title}`}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      event.stopPropagation();
                      void handleCopyPath(path);
                    }
                  }}
                >
                  {isCopied ? "Copied" : "Copy"}
                </span>
              </button>
            );
          })}
        </div>
      )}

      <div className="attack-graph-legend">
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <span key={type}>
            <i style={{ background: color }} />
            {formatLabel(type)}
          </span>
        ))}
        <span>
          <i className="legend-observed" />
          Observed relationship
        </span>
        <span>
          <i className="legend-modeled" />
          Modeled relationship
        </span>
      </div>

      <div className="attack-graph-canvas">
        <ReactFlow
          nodes={displayedNodes}
          edges={displayedEdges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          fitView
          fitViewOptions={{ padding: 0.12, maxZoom: 0.85 }}
          minZoom={0.08}
          maxZoom={2}
          nodesDraggable
          elementsSelectable
          onNodeClick={(_, node) => setSelectedNodeId(node.id)}
          proOptions={{ hideAttribution: true }}
        >
          <Background
            color="var(--graph-grid)"
            gap={24}
            size={1}
          />
          <Controls
            showInteractive={false}
            position="bottom-left"
          />
        </ReactFlow>
      </div>

      {selectedPath && (
        <section className="attack-path-details">
          <div className="attack-path-details-heading">
            <div>
              <p className="attack-path-eyebrow">
                SELECTED MODELED PATH
              </p>
              <h3>{selectedPath.title}</h3>
            </div>
            <span
              className={`path-risk risk-${(
                selectedPath.risk_level || "unknown"
              ).toLowerCase()}`}
            >
              {formatLabel(selectedPath.risk_level)}
            </span>
          </div>

          <p>{selectedPath.explanation}</p>

          {selectedPathFixes.length > 0 && (
            <div className="path-fix-details">
              <p className="attack-path-eyebrow">FIX METHOD</p>
              <p>{selectedPathFixes.join("\n")}</p>
            </div>
          )}

          <div className="attack-path-actions">
            <button type="button" className="path-copy-button" onClick={handleCopySelectedPath}>
              {copiedPathId === selectedPath.id ? "Copied" : "Copy selected path"}
            </button>
          </div>

          <p className="path-caveat">
            This is a modeled hypothesis, not a confirmed exploit chain.
          </p>
        </section>
      )}

      {selectedNode && selectedNode.data && (
        <section className="attack-node-details">
          <div className="attack-path-details-heading">
            <div>
              <p className="attack-path-eyebrow">SELECTED NODE</p>
              <h3>{selectedNode.data.label}</h3>
            </div>
            <span className={`path-risk risk-${(selectedNode.data.riskLevel || "unknown").toLowerCase()}`}>
              {formatLabel(selectedNode.data.riskLevel)}
            </span>
          </div>
          <p>{selectedNode.data.description || "No description provided."}</p>
          {selectedNode.data.fileLocation && <p className="node-location"><strong>Location:</strong> {selectedNode.data.fileLocation}</p>}
          {selectedNode.data.remediation && <p className="node-remediation"><strong>Suggested review:</strong> {selectedNode.data.remediation}</p>}
          <div className="attack-path-actions">
            <button type="button" className="path-copy-button" onClick={handleCopySelectedNode}>
              {copiedNodeId === selectedNode.id ? "Copied" : "Copy selected bug"}
            </button>
          </div>
        </section>
      )}

      {graph.warnings?.length > 0 && (
        <details className="attack-graph-warnings">
          <summary>
            Analysis notes ({graph.warnings.length})
          </summary>
          <ul>
            {graph.warnings.map((warning, index) => (
              <li key={`${index}-${warning}`}>{warning}</li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
