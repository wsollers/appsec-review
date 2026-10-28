/**
 * @name Code-graph export: sink sites
 * @description Sink candidates (catalog API arguments and python-all Concepts sinks) with the
 *              model identity, the operand and the enclosing function.
 * @kind table
 * @id appsec-review/graph-export/python/sink-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `sink_sites`.
import python
import semmle.python.dataflow.new.DataFlow
import GraphExport

query predicate sink_sites(
  string sink_path, int sink_start_line, int sink_start_column, int sink_end_line,
  int sink_end_column, int argument_index, string operand_path, int operand_start_line,
  int operand_start_column, int operand_end_line, int operand_end_column, string model,
  string api, string declared_in, string sink_display, string function_name,
  string function_path, int function_start_line, int function_start_column,
  int dominating_sanitizer_count
) {
  exists(DataFlow::Node sinkNode, DataFlow::Node operand |
    GraphExport::sink(sinkNode, operand, argument_index, model, api)
  |
    GraphExport::locationColumns(sinkNode.getLocation(), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column) and
    GraphExport::locationColumns(operand.getLocation(), operand_path, operand_start_line,
      operand_start_column, operand_end_line, operand_end_column) and
    declared_in = GraphExport::declaredIn(sinkNode) and
    sink_display = sinkNode.toString() and
    GraphExport::functionColumns(sinkNode.getScope(), function_name, function_path,
      function_start_line, function_start_column) and
    dominating_sanitizer_count = GraphExport::dominatingSanitizerCount(sinkNode)
  )
}
