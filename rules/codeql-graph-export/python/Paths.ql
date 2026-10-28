/**
 * @name Code-graph export: source-to-sink taint paths
 * @description Global taint flows from export sources to export sink operands, flattened into
 *              per-flow path edges between source locations, plus catalog sanitizer calls whose
 *              argument lies on a flow.
 * @kind table
 * @id appsec-review/graph-export/python/paths
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contracts: ../columns.json `path_flows`,
// `path_edges` and `path_sanitizers`.
//
// Bounding: this query exports every flow and every edge of the pruned path graph that lies on
// a flow. Selecting at most `max_paths_per_sink` shortest paths of at most `max_path_steps`
// steps is done downstream (graph-normalize/1) over these edges; the runner's row bound is the
// only bound applied here and is reported as `truncated`. No barrier is configured, so a path
// through a sanitizer is exported and the sanitizer is listed instead of silently cutting it.
// The sink location of a flow is the sink node (usually the call); the flow ends at its operand.
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import GraphExport

module GraphTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { GraphExport::source(n, _, _, _, _, _) }

  predicate isSink(DataFlow::Node n) { GraphExport::sinkNode(n, _, _) }

  // In "seeded" mode flows stay inside the exported neighborhood, which bounds the global
  // analysis; in "whole_program" mode nothing is a barrier. Sources and sinks are already
  // restricted to exported functions by GraphExport::source and GraphExport::sink.
  predicate isBarrier(DataFlow::Node n) { not GraphExport::exportedNode(n) }
}

module GraphTaint = TaintTracking::Global<GraphTaintConfig>;

/** The flow key: the source node location and the sink node location plus argument. */
predicate flowKey(
  GraphTaint::PathNode source, GraphTaint::PathNode sink, string source_path,
  int source_start_line, int source_start_column, int source_end_line, int source_end_column,
  string sink_path, int sink_start_line, int sink_start_column, int sink_end_line,
  int sink_end_column, int argument_index
) {
  GraphTaint::flowPath(source, sink) and
  GraphExport::locationColumns(source.getNode().getLocation(), source_path, source_start_line,
    source_start_column, source_end_line, source_end_column) and
  exists(DataFlow::Node sinkNode | GraphExport::sinkNode(sink.getNode(), sinkNode, argument_index) |
    GraphExport::locationColumns(sinkNode.getLocation(), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column)
  )
}

/** `n` lies on a flow from `source` to `sink`. */
predicate onFlow(GraphTaint::PathNode source, GraphTaint::PathNode sink, GraphTaint::PathNode n) {
  GraphTaint::flowPath(source, sink) and
  source.getASuccessor*() = n and
  n.getASuccessor*() = sink
}

/**
 * "local" within one scope, "call" into a parameter, "return" out of a callee into its call.
 * A step between scopes that is neither (a module-level global read or write) is "local".
 */
string edgeKind(GraphTaint::PathNode a, GraphTaint::PathNode b) {
  if a.getNode().getScope() = b.getNode().getScope()
  then result = "local"
  else
    if b.getNode() instanceof DataFlow::ParameterNode
    then result = "call"
    else
      if b.getNode() instanceof DataFlow::CallCfgNode
      then result = "return"
      else result = "local"
}

string functionName(GraphTaint::PathNode n) {
  result = n.getNode().getScope().(Function).getQualifiedName()
  or
  not n.getNode().getScope() instanceof Function and result = ""
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
    DataFlow::CallCfgNode sanitizer
  |
    flowKey(source, sink, source_path, source_start_line, source_start_column, source_end_line,
      source_end_column, sink_path, sink_start_line, sink_start_column, sink_end_line,
      sink_end_column, argument_index) and
    onFlow(source, sink, n) and
    GraphExport::sanitizerCall(sanitizer, api) and
    n.getNode() = sanitizer.getArg(_)
  |
    GraphExport::locationColumns(sanitizer.getLocation(), sanitizer_path, sanitizer_start_line,
      sanitizer_start_column, sanitizer_end_line, sanitizer_end_column)
  )
}
