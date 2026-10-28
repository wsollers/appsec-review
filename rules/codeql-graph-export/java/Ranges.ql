/**
 * @name Code-graph export: ranges at sinks
 * @description Range-analysis bounds of each integral sink operand and the explicit integral
 *              cast chain applied to it; "unknown" when no finite bound is proven.
 * @kind table
 * @id appsec-review/graph-export/java/ranges
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contracts: ../columns.json `ranges` and
// `range_conversions`.
//
// Bounds come from the Java range analysis (`bounded` against the zero bound), which is
// intraprocedural. Integral operands are the primitive types byte, short, char, int and long
// (boxed integers are not unboxed here); every other operand, which is most Java sink operands
// (strings, URLs, streams), exports applicability "not_applicable". A bound is the decimal
// integer, or "unknown" when none is proven. Conversions are explicit casts only: Java's
// implicit widening and unboxing conversions are not AST nodes and are not exported.
import java
import semmle.code.java.dataflow.RangeAnalysis
import GraphExport

/** The width in bits of an integral primitive type, by name. */
int integralBits(PrimitiveType t) {
  t.hasName("byte") and result = 8
  or
  t.hasName(["short", "char"]) and result = 16
  or
  t.hasName("int") and result = 32
  or
  t.hasName("long") and result = 64
}

string signedOf(PrimitiveType t) {
  exists(integralBits(t)) and
  if t.hasName("char") then result = "false" else result = "true"
}

/** The greatest proven lower bound of `e`, or "unknown". */
string lowerText(Expr e) {
  if exists(int d | bounded(e, any(ZeroBound z), d, false, _))
  then result = max(int d | bounded(e, any(ZeroBound z), d, false, _)).toString()
  else result = "unknown"
}

/** The least proven upper bound of `e`, or "unknown". */
string upperText(Expr e) {
  if exists(int d | bounded(e, any(ZeroBound z), d, true, _))
  then result = min(int d | bounded(e, any(ZeroBound z), d, true, _)).toString()
  else result = "unknown"
}

/** The `depth`-th explicit cast from the outside of a sink operand (1 = the operand itself). */
predicate castDepth(Expr operand, CastingExpr c, int depth) {
  GraphExport::sink(_, operand, _, _, _) and c = operand and depth = 1
  or
  exists(CastingExpr outer, int d | castDepth(operand, outer, d) |
    c = outer.getExpr() and depth = d + 1
  )
}

/** The `step`-th cast applied to a sink operand, numbered from the innermost (1). */
predicate conversionStep(Expr operand, CastingExpr c, int step) {
  exists(int depth | castDepth(operand, c, depth) |
    step = max(int d | castDepth(operand, _, d)) - depth + 1
  )
}

/** sign_change takes precedence over narrowing, which takes precedence over promotion. */
string conversionKind(PrimitiveType fromType, PrimitiveType toType) {
  if signedOf(fromType) != signedOf(toType)
  then result = "sign_change"
  else
    if integralBits(toType) < integralBits(fromType)
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
    exists(PrimitiveType t | t = operand.getType() and exists(integralBits(t)) |
      applicability = "integral" and
      signed = signedOf(t) and
      bits = integralBits(t) and
      lower = lowerText(operand) and
      upper = upperText(operand)
    )
    or
    not exists(integralBits(operand.getType())) and
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
  exists(Expr sinkExpr, Expr operand, CastingExpr c, PrimitiveType fromType, PrimitiveType toType |
    GraphExport::sink(sinkExpr, operand, argument_index, _, _) and
    conversionStep(operand, c, step) and
    fromType = c.getExpr().getType() and
    toType = c.getType() and
    exists(integralBits(fromType)) and
    exists(integralBits(toType)) and
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
