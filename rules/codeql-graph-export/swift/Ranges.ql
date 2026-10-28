/**
 * @name Code-graph export: ranges at sinks
 * @description The integral type of each sink operand and, when the operand is an integer
 *              literal, its exact value; every other bound is "unknown".
 * @kind table
 * @id appsec-review/graph-export/swift/ranges
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contracts: ../columns.json `ranges` and
// `range_conversions`.
//
// codeql/swift-all ships no range analysis, so this query is intraprocedural and literal-only:
// an integral operand that resolves to an integer literal exports that value as both bounds
// (CodeQL's `float.toString()` rendering, as in the C/C++ pack); every other integral operand
// exports "unknown" bounds (a named gap, never a clean bound). Swift has no implicit integral
// conversions (every conversion is an explicit initializer call such as `Int32(x)`), so
// `range_conversions` is always empty. Integral width is read from the standard type name;
// `Int` and `UInt` are 64-bit on every platform CodeQL extracts Swift on.
import swift
import GraphExport

/** The standard integral type name of `t` (sugar and aliases removed). */
string integralName(Type t) { result = t.getUnderlyingType().(IntegralType).getName() }

int bitsOf(string name) {
  name = ["Int", "UInt"] and result = 64
  or
  result = name.regexpCapture("U?Int([0-9]+)", 1).toInt()
}

string literalBound(Expr operand) {
  result = operand.resolve().(IntegerLiteralExpr).getStringValue().toInt().toFloat().toString()
  or
  not exists(operand.resolve().(IntegerLiteralExpr).getStringValue().toInt()) and
  result = "unknown"
}

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
      operand_start_column, operand_end_line, operand_end_column) and
    type_display = operand.getType().toString()
  |
    exists(string name | name = integralName(operand.getType()) |
      applicability = "integral" and
      (if name.matches("U%") then signed = "false" else signed = "true") and
      bits = bitsOf(name) and
      lower = literalBound(operand) and
      upper = literalBound(operand)
    )
    or
    not exists(integralName(operand.getType())) and
    applicability = "not_applicable" and
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
