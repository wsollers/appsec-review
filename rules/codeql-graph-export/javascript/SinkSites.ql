/**
 * @name Code-graph export: sink sites
 * @description Sink candidates (catalog API arguments and javascript-all sink models) with their
 *              operand, model identity and dominating catalog sanitizer count.
 * @kind table
 * @id appsec-review/graph-export/javascript/sink-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `sink_sites`.
import javascript
import GraphExport

query predicate sink_sites(
  string sink_path, int sink_start_line, int sink_start_column, int sink_end_line,
  int sink_end_column, int argument_index, string operand_path, int operand_start_line,
  int operand_start_column, int operand_end_line, int operand_end_column, string model,
  string api, string declared_in, string sink_display, string function_name,
  string function_path, int function_start_line, int function_start_column,
  int dominating_sanitizer_count
) {
  exists(DataFlow::Node sinkNode, DataFlow::Node operand, GraphExport::SourceFunction function |
    GraphExport::sink(sinkNode, operand, argument_index, model, api) and
    function = sinkNode.getContainer()
  |
    GraphExport::locationColumns(sinkNode.getLocation(), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column) and
    GraphExport::locationColumns(operand.getLocation(), operand_path, operand_start_line,
      operand_start_column, operand_end_line, operand_end_column) and
    declared_in = GraphExport::sinkDeclaredIn(sinkNode) and
    sink_display = sinkNode.toString() and
    function_name = function.getQualifiedName() and
    GraphExport::locationColumns(function.getNameLocation(), function_path, function_start_line,
      function_start_column, _, _) and
    dominating_sanitizer_count = GraphExport::dominatingSanitizerCount(sinkNode)
  )
}
