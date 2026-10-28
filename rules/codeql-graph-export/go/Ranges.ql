/**
 * @name Code-graph export: ranges at sinks
 * @description Guard- and constant-derived bounds of each integer sink operand and the integer
 *              conversion chain applied to it; "unknown" when no bound is established.
 * @kind table
 * @id appsec-review/graph-export/go/ranges
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contracts: ../columns.json `ranges` and
// `range_conversions`.
//
// codeql/go-all has no interval range analysis (no SimpleRangeAnalysis). Bounds here are
// intraprocedural: a constant operand has its exact value; otherwise the tightest bound any
// dominating branch condition establishes through ControlFlow::ConditionGuardNode::ensuresLeq
// on the operand's global value number (`x < 100` controlling the sink gives upper "99").
// Arithmetic, loops and calls are not followed, so a missing bound is "unknown", never a
// claim the operand is unbounded. Non-integer operands export applicability "not_applicable".
import go
import GraphExport

/** The bit width of an integer type (`int`, `uint` and `uintptr` take their widest size). */
int typeBits(IntegerType t) {
  result = t.getSize()
  or
  not exists(t.getSize()) and result = max(t.getASize())
}

/** The integer type underlying `e`, if any. */
IntegerType integerType(Expr e) { result = e.getType().getUnderlyingType() }

/** `cond` holds where the sink call runs and ensures `lesser <= greater + bias`. */
predicate dominatingLeq(DataFlow::CallNode call, DataFlow::Node lesser, DataFlow::Node greater, int bias) {
  exists(ControlFlow::ConditionGuardNode g |
    g.dominates(call.getBasicBlock()) and g.ensuresLeq(lesser, greater, bias)
  )
}

predicate sameValue(DataFlow::Node n, Expr operand) {
  globalValueNumber(n) = globalValueNumber(DataFlow::exprNode(operand))
}

string upperText(DataFlow::CallNode call, Expr operand) {
  if operand.isConst() and exists(operand.getIntValue())
  then result = operand.getIntValue().toString()
  else
    if exists(DataFlow::Node lesser, DataFlow::Node greater, int bias |
        dominatingLeq(call, lesser, greater, bias) and sameValue(lesser, operand) and
        exists(greater.getIntValue())
      )
    then
      result =
        min(int b |
          exists(DataFlow::Node lesser, DataFlow::Node greater, int bias |
            dominatingLeq(call, lesser, greater, bias) and
            sameValue(lesser, operand) and
            b = greater.getIntValue() + bias
          )
        ).toString()
    else result = "unknown"
}

string lowerText(DataFlow::CallNode call, Expr operand) {
  if operand.isConst() and exists(operand.getIntValue())
  then result = operand.getIntValue().toString()
  else
    if exists(DataFlow::Node lesser, DataFlow::Node greater, int bias |
        dominatingLeq(call, lesser, greater, bias) and sameValue(greater, operand) and
        exists(lesser.getIntValue())
      )
    then
      result =
        max(int b |
          exists(DataFlow::Node lesser, DataFlow::Node greater, int bias |
            dominatingLeq(call, lesser, greater, bias) and
            sameValue(greater, operand) and
            b = lesser.getIntValue() - bias
          )
        ).toString()
    else result = "unknown"
}

/** `c` is the `depth`-th conversion from the outside of the sink operand (1 = the operand). */
predicate conversionDepth(Expr operand, ConversionExpr c, int depth) {
  GraphExport::sink(_, operand, _, _, _) and c = operand.stripParens() and depth = 1
  or
  exists(ConversionExpr outer, int d |
    conversionDepth(operand, outer, d) and
    c = outer.getOperand().stripParens() and
    depth = d + 1
  )
}

/** The `step`-th conversion applied to the sink operand's innermost value (1 = innermost). */
predicate conversionStep(Expr operand, ConversionExpr c, int step) {
  exists(int depth |
    conversionDepth(operand, c, depth) and
    step = max(int d | conversionDepth(operand, _, d)) - depth + 1
  )
}

/** sign_change takes precedence over narrowing, which takes precedence over promotion. */
string conversionKind(IntegerType fromType, IntegerType toType) {
  if
    fromType instanceof SignedIntegerType and not toType instanceof SignedIntegerType
    or
    not fromType instanceof SignedIntegerType and toType instanceof SignedIntegerType
  then result = "sign_change"
  else
    if typeBits(toType) < typeBits(fromType)
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
  exists(DataFlow::CallNode call, Expr operand |
    GraphExport::sink(call, operand, argument_index, _, _) and
    GraphExport::locationColumns(GraphExport::sinkLocation(call), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column) and
    GraphExport::locationColumns(operand.getLocation(), operand_path, operand_start_line,
      operand_start_column, operand_end_line, operand_end_column) and
    type_display = operand.getType().pp()
  |
    exists(IntegerType t | t = integerType(operand) |
      applicability = "integral" and
      (if t instanceof SignedIntegerType then signed = "true" else signed = "false") and
      bits = typeBits(t) and
      lower = lowerText(call, operand) and
      upper = upperText(call, operand)
    )
    or
    not exists(integerType(operand)) and
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
  exists(DataFlow::CallNode call, Expr operand, ConversionExpr c, IntegerType fromType,
    IntegerType toType
  |
    GraphExport::sink(call, operand, argument_index, _, _) and
    conversionStep(operand, c, step) and
    fromType = integerType(c.getOperand()) and
    toType = integerType(c) and
    GraphExport::locationColumns(GraphExport::sinkLocation(call), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column)
  |
    kind = conversionKind(fromType, toType) and
    from_type = c.getOperand().getType().pp() and
    to_type = c.getType().pp() and
    GraphExport::locationColumns(c.getLocation(), conversion_path, conversion_start_line,
      conversion_start_column, conversion_end_line, conversion_end_column)
  )
}
