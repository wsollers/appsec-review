/**
 * @name Code-graph export: ranges at sinks
 * @description One row per sink operand with applicability "not_applicable": JavaScript numbers
 *              have no integral type, so there is no integral range or conversion chain.
 * @kind table
 * @id appsec-review/graph-export/javascript/ranges
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contracts: ../columns.json `ranges` and
// `range_conversions`.
//
// JavaScript has no integral types or implicit integral conversions, and javascript-all ships
// no interval range analysis comparable to C/C++ SimpleRangeAnalysis. Every sink operand is
// exported as "not_applicable" so the normalizer records a named gap per sink instead of an
// absent (silently clean) range fact; `range_conversions` is always empty.
import javascript
import GraphExport

query predicate ranges(
  string sink_path, int sink_start_line, int sink_start_column, int sink_end_line,
  int sink_end_column, int argument_index, string operand_path, int operand_start_line,
  int operand_start_column, int operand_end_line, int operand_end_column,
  string applicability, string type_display, string signed, int bits, string lower,
  string upper
) {
  exists(DataFlow::Node sinkNode, DataFlow::Node operand |
    GraphExport::sink(sinkNode, operand, argument_index, _, _) and
    GraphExport::locationColumns(sinkNode.getLocation(), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column) and
    GraphExport::locationColumns(operand.getLocation(), operand_path, operand_start_line,
      operand_start_column, operand_end_line, operand_end_column)
  |
    applicability = "not_applicable" and
    type_display = "" and
    signed = "" and
    bits = 0 and
    lower = "" and
    upper = ""
  )
}

query predicate range_conversions(
  string sink_path, int sink_start_line, int sink_start_column, int sink_end_line,
  int sink_end_column, int argument_index, int step, string kind, string from_type,
  string to_type, string conversion_path, int conversion_start_line,
  int conversion_start_column, int conversion_end_line, int conversion_end_column
) {
  none() and
  sink_path = "" and
  sink_start_line = 0 and
  sink_start_column = 0 and
  sink_end_line = 0 and
  sink_end_column = 0 and
  argument_index = 0 and
  step = 0 and
  kind = "" and
  from_type = "" and
  to_type = "" and
  conversion_path = "" and
  conversion_start_line = 0 and
  conversion_start_column = 0 and
  conversion_end_line = 0 and
  conversion_end_column = 0
}
