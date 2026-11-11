function hasDirectedMemberChain(memberNodeIds, edges) {
  if (memberNodeIds.length < 2) return false;

  const memberSet = new Set(memberNodeIds);
  const adjacency = new Map(memberNodeIds.map((id) => [id, []]));
  edges.forEach((edge) => {
    if (
      memberSet.has(edge.source)
      && memberSet.has(edge.target)
      && edge.source !== edge.target
    ) {
      adjacency.get(edge.source).push(edge.target);
    }
  });

  function visit(nodeId, visited) {
    if (visited.size === memberNodeIds.length) return true;
    return adjacency.get(nodeId).some((nextId) => {
      if (visited.has(nextId)) return false;
      return visit(nextId, new Set([...visited, nextId]));
    });
  }

  return memberNodeIds.some((nodeId) => visit(nodeId, new Set([nodeId])));
}

export function getPathGraphSelection(path, edges, knownNodeIds) {
  const knownIds = knownNodeIds instanceof Set
    ? knownNodeIds
    : new Set(knownNodeIds || []);
  const memberNodeIds = [...new Set(
    (path?.node_ids || [])
      .map((nodeId) => String(nodeId))
      .map((nodeId) => {
        if (knownIds.has(nodeId)) return nodeId;
        const findingId = nodeId.startsWith("finding-")
          ? nodeId.slice("finding-".length)
          : nodeId;
        const graphFindingId = `finding-${findingId}`;
        return knownIds.has(graphFindingId) ? graphFindingId : null;
      })
      .filter(Boolean)
  )];
  const memberIds = new Set(memberNodeIds);
  const incidentEdges = (edges || []).filter(
    (edge) => memberIds.has(edge.source) || memberIds.has(edge.target)
  );
  const visibleNodeIds = new Set(memberNodeIds);
  incidentEdges.forEach((edge) => {
    visibleNodeIds.add(edge.source);
    visibleNodeIds.add(edge.target);
  });

  return {
    relationType: hasDirectedMemberChain(memberNodeIds, incidentEdges)
      ? "relationship_chain"
      : "review_group",
    memberNodeIds: memberIds,
    visibleNodeIds,
    highlightedEdgeIds: new Set(
      incidentEdges.map((edge) => edge.id).filter(Boolean)
    ),
  };
}
