/**
 * @name Code-graph export: ranges at sinks
 * @description One `not_applicable` range row per sink operand: Python integers are unbounded
 *              and the export does not run a range analysis, so no bound is ever claimed.
 * @kind table
 * @id appsec-review/graph-export/python/ranges
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contracts: ../columns.json `ranges` and
// `range_conversions`.
//
// Named gap: Python has no fixed-width integer types and python-all has no sink-operand range
// analysis, so every row is `applicability` "not_applicable" with `type_display` "object",
// `signed` "", `bits` 0 and empty bounds, and `range_conversions` is always empty. This is a
// coverage gap downstream, never evidence that an operand is bounded.
import python
import semmle.python.dataflow.new.DataFlow
import GraphExport

query predicate ranges(
  string sink_path, int sink_start_line, int sink_start_column, int sink_end_line,
  int sink_end_column, int argument_index, string operand_path, int operand_start_line,
  int operand_start_column, int operand_end_line, int operand_end_column, string applicability,
  string type_display, string signed, int bits, string lower, string upper
) {
  exists(DataFlow::Node sinkNode, DataFlow::Node operand |
    GraphExport::sink(sinkNode, operand, argument_index, _, _)
  |
    GraphExport::locationColumns(sinkNode.getLocation(), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column) and
    GraphExport::locationColumns(operand.getLocation(), operand_path, operand_start_line,
      operand_start_column, operand_end_line, operand_end_column) and
    applicability = "not_applicable" and
    type_display = "object" and
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
