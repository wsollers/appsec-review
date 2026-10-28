/**
 * @name Code-graph export: ranges at sinks
 * @description One "not_applicable" row per sink operand: Ruby integers are arbitrary-precision
 *              objects and ruby-all has no range analysis, so no interval or integral conversion
 *              is computed.
 * @kind table
 * @id appsec-review/graph-export/ruby/ranges
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contracts: ../columns.json `ranges` and
// `range_conversions`.
//
// Every sink operand exports applicability "not_applicable", type_display "dynamic", signed "",
// bits 0 and empty bounds; the normalizer records that as a named gap on each range fact, never
// as a proven bound. `range_conversions` is always empty (Ruby has no implicit integral
// conversions).
import codeql.ruby.AST
import GraphExport

query predicate ranges(
  string sink_path, int sink_start_line, int sink_start_column, int sink_end_line,
  int sink_end_column, int argument_index, string operand_path, int operand_start_line,
  int operand_start_column, int operand_end_line, int operand_end_column,
  string applicability, string type_display, string signed, int bits, string lower,
  string upper
) {
  exists(Expr sinkExpr, Expr operand |
    GraphExport::sink(sinkExpr, operand, argument_index, _, _) and
    GraphExport::locationColumns(sinkExpr.getLocation(), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column) and
    GraphExport::locationColumns(operand.getLocation(), operand_path, operand_start_line,
      operand_start_column, operand_end_line, operand_end_column)
  |
    applicability = "not_applicable" and
    type_display = "dynamic" and
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
