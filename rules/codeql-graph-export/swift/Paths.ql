/**
 * @name Code-graph export: source-to-sink taint paths
 * @description Global taint flows from export sources to export sink operands, flattened into
 *              per-flow path edges between source locations, plus catalog sanitizer calls whose
 *              argument or receiver lies on a flow.
 * @kind table
 * @id appsec-review/graph-export/swift/paths
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contracts: ../columns.json `path_flows`,
// `path_edges` and `path_sanitizers`.
//
// Bounding: as in the C/C++ pack, every flow and every edge of the pruned path graph that lies
// on a flow is exported; shortest-path selection is done downstream (graph-normalize/1). No
// barrier is configured, so a path through a sanitizer is exported and the sanitizer is listed.
import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import GraphExport

module GraphTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { GraphExport::source(n, _, _, _, _, _) }

  predicate isSink(DataFlow::Node n) { GraphExport::sinkNode(n, _, _) }

  // In "seeded" mode flows stay inside the exported neighborhood; in "whole_program" mode
  // nothing is a barrier.
  predicate isBarrier(DataFlow::Node n) { not GraphExport::exportedNode(n) }
}

module GraphTaint = TaintTracking::Global<GraphTaintConfig>;

/** The flow key: the source node location and the sink expression location plus argument. */
predicate flowKey(
  GraphTaint::PathNode source, GraphTaint::PathNode sink, string source_path,
  int source_start_line, int source_start_column, int source_end_line, int source_end_column,
  string sink_path, int sink_start_line, int sink_start_column, int sink_end_line,
  int sink_end_column, int argument_index
) {
  GraphTaint::flowPath(source, sink) and
  GraphExport::locationColumns(source.getNode().getLocation(), source_path, source_start_line,
    source_start_column, source_end_line, source_end_column) and
  exists(Expr sinkExpr | GraphExport::sinkNode(sink.getNode(), sinkExpr, argument_index) |
    GraphExport::locationColumns(sinkExpr.getLocation(), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column)
  )
}

/** `n` lies on a flow from `source` to `sink`. */
predicate onFlow(GraphTaint::PathNode source, GraphTaint::PathNode sink, GraphTaint::PathNode n) {
  GraphTaint::flowPath(source, sink) and
  source.getASuccessor*() = n and
  n.getASuccessor*() = sink
}

string edgeKind(GraphTaint::PathNode a, GraphTaint::PathNode b) {
  if a.getNode().getEnclosingCallable() = b.getNode().getEnclosingCallable()
  then result = "local"
  else
    if b.getNode() instanceof DataFlow::ParameterNode
    then result = "call"
    else result = "return"
}

string functionName(GraphTaint::PathNode n) {
  result = GraphExport::qualifiedName(GraphExport::nodeFunction(n.getNode()))
  or
  not exists(GraphExport::nodeFunction(n.getNode())) and result = ""
}

query predicate path_flows(
  string source_path, int source_start_line, int source_start_column, int source_end_line,
  int source_end_column, string sink_path, int sink_start_line, int sink_start_column,
  int sink_end_line, int sink_end_column, int argument_index
) {
  flowKey(_, _, source_path, source_start_line, source_start_column, source_end_line,
    source_end_column, sink_path, sink_start_line, sink_start_column, sink_end_line,
    sink_end_column, argument_index)
}

query predicate path_edges(
  string source_path, int source_start_line, int source_start_column, int source_end_line,
  int source_end_column, string sink_path, int sink_start_line, int sink_start_column,
  int sink_end_line, int sink_end_column, int argument_index, string from_path,
  int from_start_line, int from_start_column, int from_end_line, int from_end_column,
  string from_display, string from_function, string to_path, int to_start_line,
  int to_start_column, int to_end_line, int to_end_column, string to_display,
  string to_function, string edge_kind
) {
  exists(GraphTaint::PathNode source, GraphTaint::PathNode sink, GraphTaint::PathNode a,
    GraphTaint::PathNode b
  |
    flowKey(source, sink, source_path, source_start_line, source_start_column, source_end_line,
      source_end_column, sink_path, sink_start_line, sink_start_column, sink_end_line,
      sink_end_column, argument_index) and
    onFlow(source, sink, a) and
    onFlow(source, sink, b) and
    a.getASuccessor() = b
  |
    GraphExport::locationColumns(a.getNode().getLocation(), from_path, from_start_line,
      from_start_column, from_end_line, from_end_column) and
    from_display = a.getNode().toString() and
    from_function = functionName(a) and
    GraphExport::locationColumns(b.getNode().getLocation(), to_path, to_start_line,
      to_start_column, to_end_line, to_end_column) and
    to_display = b.getNode().toString() and
    to_function = functionName(b) and
    edge_kind = edgeKind(a, b)
  )
}

query predicate path_sanitizers(
  string source_path, int source_start_line, int source_start_column, int source_end_line,
  int source_end_column, string sink_path, int sink_start_line, int sink_start_column,
  int sink_end_line, int sink_end_column, int argument_index, string sanitizer_path,
  int sanitizer_start_line, int sanitizer_start_column, int sanitizer_end_line,
  int sanitizer_end_column, string api
) {
  exists(GraphTaint::PathNode source, GraphTaint::PathNode sink, GraphTaint::PathNode n,
    ApplyExpr sanitizer
  |
    flowKey(source, sink, source_path, source_start_line, source_start_column, source_end_line,
      source_end_column, sink_path, sink_start_line, sink_start_column, sink_end_line,
      sink_end_column, argument_index) and
    onFlow(source, sink, n) and
    api = GraphExport::calleeName(sanitizer) and
    GraphExport::sanitizerApi(api) and
    (
      n.getNode().asExpr() = sanitizer.getAnArgument().getExpr() or
      n.getNode().asExpr() = sanitizer.getQualifier()
    )
  |
    GraphExport::locationColumns(sanitizer.getLocation(), sanitizer_path, sanitizer_start_line,
      sanitizer_start_column, sanitizer_end_line, sanitizer_end_column)
  )
}
