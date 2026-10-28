/**
 * @name Code-graph export: ranges at sinks
 * @description Constant and sign bounds of each integral sink operand and the explicit integral
 *              cast chain applied to it; "unknown" when no bound is derivable.
 * @kind table
 * @id appsec-review/graph-export/csharp/ranges
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contracts: ../columns.json `ranges` and
// `range_conversions`.
//
// codeql/csharp-all has no interval range analysis (no SimpleRangeAnalysis); this query uses
// constant values and the intraprocedural SignAnalysis library only. A constant operand exports
// its value as both bounds; otherwise the lower bound is "1" (strictly positive), "0"
// (non-negative) or "unknown", and the upper bound "-1" (strictly negative), "0"
// (non-positive) or "unknown". Non-integral operands export applicability "not_applicable".
//
// Conversions: C# integral conversions that matter are explicit casts, which are expressions in
// the CodeQL C# AST. Step 1 is the operand itself when it is a cast, step n+1 the cast directly
// inside step n.
import csharp
import semmle.code.csharp.dataflow.SignAnalysis
import GraphExport

string lowerText(Expr operand) {
  if operand.getValue().regexpMatch("-?[0-9]+")
  then result = operand.getValue()
  else
    if strictlyPositiveExpr(operand)
    then result = "1"
    else
      if positiveExpr(operand)
      then result = "0"
      else result = "unknown"
}

string upperText(Expr operand) {
  if operand.getValue().regexpMatch("-?[0-9]+")
  then result = operand.getValue()
  else
    if strictlyNegativeExpr(operand)
    then result = "-1"
    else
      if negativeExpr(operand)
      then result = "0"
      else result = "unknown"
}

/** The `step`-th integral cast of a sink operand (1 = the operand itself). */
predicate conversionStep(Expr operand, Cast c, int step) {
  GraphExport::sink(_, operand, _, _, _) and c = operand and step = 1
  or
  exists(Cast previous, int s |
    conversionStep(operand, previous, s) and c = previous.getExpr() and step = s + 1
  )
}

/** sign_change takes precedence over narrowing, which takes precedence over promotion. */
string conversionKind(IntegralType fromType, IntegralType toType) {
  if
    fromType instanceof SignedIntegralType and not toType instanceof SignedIntegralType
    or
    not fromType instanceof SignedIntegralType and toType instanceof SignedIntegralType
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
    exists(IntegralType t | t = operand.getType() |
      applicability = "integral" and
      (if t instanceof SignedIntegralType then signed = "true" else signed = "false") and
      bits = t.getSize() * 8 and
      lower = lowerText(operand) and
      upper = upperText(operand)
    )
    or
    not operand.getType() instanceof IntegralType and
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
  exists(Expr sinkExpr, Expr operand, Cast c, IntegralType fromType, IntegralType toType |
    GraphExport::sink(sinkExpr, operand, argument_index, _, _) and
    conversionStep(operand, c, step) and
    fromType = c.getExpr().getType() and
    toType = c.getType() and
    GraphExport::locationColumns(sinkExpr.getLocation(), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column)
  |
    kind = conversionKind(fromType, toType) and
    from_type = fromType.toString() and
    to_type = toType.toString() and
    GraphExport::locationColumns(c.getLocation(), conversion_path, conversion_start_line,
      conversion_start_column, conversion_end_line, conversion_end_column)
  )
}