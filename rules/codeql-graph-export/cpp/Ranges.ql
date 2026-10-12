/**
 * @name Code-graph export: ranges at sinks
 * @description SimpleRangeAnalysis bounds of each sink operand and the integral conversion
 *              chain applied to it; "unknown" when a bound is the type's extreme.
 * @kind table
 * @id appsec-review/graph-export/cpp/ranges
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contracts: ../columns.json `ranges` and
// `range_conversions`.
//
// The analysis is intraprocedural and widening-based (may over-approximate). A bound equal to
// the operand type's minimum or maximum is exported as "unknown"; a finite bound is CodeQL's
// `float.toString()` rendering. Non-integral operands export applicability "not_applicable".
import cpp
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.rangeanalysis.RangeAnalysisUtils
import GraphExport

bindingset[bound, extreme]
string boundText(float bound, float extreme) {
  if bound = extreme then result = "unknown" else result = bound.toString()
}

/** The `step`-th conversion CodeQL applies on top of a sink operand (1 = innermost). */
predicate conversionStep(Expr operand, Conversion c, int step) {
  GraphExport::sink(_, operand, _, _, _) and c = operand.getConversion() and step = 1
  or
  exists(Conversion previous, int s |
    conversionStep(operand, previous, s) and c = previous.getConversion() and step = s + 1
  )
}

/** sign_change takes precedence over narrowing, which takes precedence over promotion. */
string conversionKind(IntegralType fromType, IntegralType toType) {
  if
    fromType.isSigned() and not toType.isSigned()
    or
    not fromType.isSigned() and toType.isSigned()
  then result = "sign_change"
  else
    if toType.getSize() < fromType.getSize()
    then result = "narrowing"
    else result = "promotion"
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
    exists(IntegralType t | t = operand.getUnspecifiedType() |
      applicability = "integral" and
      (if t.isSigned() then signed = "true" else signed = "false") and
      bits = t.getSize() * 8 and
      lower = boundText(lowerBound(operand), exprMinVal(operand)) and
      upper = boundText(upperBound(operand), exprMaxVal(operand))
    )
    or
    not operand.getUnspecifiedType() instanceof IntegralType and
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
  exists(Expr sinkExpr, Expr operand, Conversion c, IntegralType fromType, IntegralType toType |
    GraphExport::sink(sinkExpr, operand, argument_index, _, _) and
    conversionStep(operand, c, step) and
    fromType = c.getExpr().getUnspecifiedType() and
    toType = c.getUnspecifiedType() and
    GraphExport::locationColumns(sinkExpr.getLocation(), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column)
  |
    kind = conversionKind(fromType, toType) and
    from_type = c.getExpr().getType().toString() and
    to_type = c.getType().toString() and
    GraphExport::locationColumns(c.getLocation(), conversion_path, conversion_start_line,
      conversion_start_column, conversion_end_line, conversion_end_column)
  )
}
