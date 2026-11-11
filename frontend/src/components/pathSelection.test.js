import assert from "node:assert/strict";
import test from "node:test";
import { getPathGraphSelection } from "./pathSelection.js";

test("review groups highlight existing finding relationships and context nodes", () => {
  const graphNodes = new Set([
    "finding-a",
    "finding-b",
    "component-a",
    "scan-1",
    "asset-a",
  ]);
  const edges = [
    { id: "component-edge", source: "component-a", target: "finding-a" },
    { id: "scan-edge", source: "scan-1", target: "finding-a" },
    { id: "asset-edge", source: "finding-b", target: "asset-a" },
  ];

  const selection = getPathGraphSelection(
    { node_ids: ["finding-a", "finding-b"] },
    edges,
    graphNodes
  );

  assert.equal(selection.relationType, "review_group");
  assert.deepEqual([...selection.memberNodeIds], ["finding-a", "finding-b"]);
  assert.deepEqual([...selection.visibleNodeIds], [
    "finding-a",
    "finding-b",
    "component-a",
    "scan-1",
    "asset-a",
  ]);
  assert.deepEqual([...selection.highlightedEdgeIds], [
    "component-edge",
    "scan-edge",
    "asset-edge",
  ]);
});

test("only a directed chain connecting every member is labeled a relationship chain", () => {
  const edges = [
    { id: "ab", source: "finding-a", target: "finding-b" },
    { id: "bc", source: "finding-b", target: "finding-c" },
    { id: "context", source: "component-a", target: "finding-a" },
  ];

  const selection = getPathGraphSelection(
    { node_ids: ["finding-a", "finding-b", "finding-c"] },
    edges,
    new Set(["finding-a", "finding-b", "finding-c", "component-a"])
  );

  assert.equal(selection.relationType, "relationship_chain");
  assert.deepEqual([...selection.highlightedEdgeIds], ["ab", "bc", "context"]);
});

test("missing and disconnected members do not become an inferred chain", () => {
  const selection = getPathGraphSelection(
    { node_ids: ["a", "missing", "b", "c"] },
    [{ id: "ab", source: "finding-a", target: "finding-b" }],
    new Set(["finding-a", "finding-b", "finding-c"])
  );

  assert.equal(selection.relationType, "review_group");
  assert.deepEqual([...selection.memberNodeIds], [
    "finding-a",
    "finding-b",
    "finding-c",
  ]);
});
