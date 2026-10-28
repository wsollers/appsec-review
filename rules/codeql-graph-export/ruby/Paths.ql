/**
 * @name Code-graph export: source-to-sink taint paths
 * @description Global taint flows from export sources to export sink operands, flattened into
 *              per-flow path edges between source locations, plus catalog sanitizer calls whose
 *              argument lies on a flow.
 * @kind table
 * @id appsec-review/graph-export/ruby/paths
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contracts: ../columns.json `path_flows`,
// `path_edges` and `path_sanitizers`.
//
// Bounding: this query exports every flow and every edge of the pruned path graph that lies on
// a flow. Selecting at most `max_paths_per_sink` shortest paths of at most `max_path_steps`
// steps is done downstream (graph-normalize/1) over these edges; the runner's row bound is the
// only bound applied here and is reported as `truncated`. No barrier is configured, so a path
// through a sanitizer is exported and the sanitizer is listed instead of silently cutting it.
import codeql.ruby.AST
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking
import GraphExport

module GraphTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { GraphExport::source(n, _, _, _, _, _) }

  predicate isSink(DataFlow::Node n) { GraphExport::sinkNode(n, _, _) }

  // In "seeded" mode flows stay inside the exported neighborhood, which bounds the global
  // analysis; in "whole_program" mode nothing is a barrier. Sources and sinks are already
  // restricted to exported functions by GraphExport::source and GraphExport::sinkNode.
  predicate isBarrier(DataFlow::Node n) { not GraphExport::exportedNode(n) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    GraphExport::sanitizerStep(pred, succ)
  }
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

/** The qualified name of the source-root method a path node lies in, else "". */
string functionName(GraphTaint::PathNode n) {
  result = GraphExport::functionAt(n.getNode().getLocation()).getQualifiedName()
  or
  not exists(GraphExport::functionAt(n.getNode().getLocation())) and result = ""
}

string edgeKind(GraphTaint::PathNode a, GraphTaint::PathNode b) {
  if functionName(a) = functionName(b)
  then result = "local"
  else
    if b.getNode() instanceof DataFlow::ParameterNode
    then result = "call"
    else result = "return"
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
    MethodCall sanitizer
  |
    flowKey(source, sink, source_path, source_start_line, source_start_column, source_end_line,
      source_end_column, sink_path, sink_start_line, sink_start_column, sink_end_line,
      sink_end_column, argument_index) and
    onFlow(source, sink, n) and
    api = sanitizer.getMethodName() and
    GraphExport::sanitizerApi(api) and
    n.getNode().asExpr().getExpr() = sanitizer.getAnArgument()
  |
    GraphExport::locationColumns(sanitizer.getLocation(), sanitizer_path, sanitizer_start_line,
      sanitizer_start_column, sanitizer_end_line, sanitizer_end_column)
  )
}
