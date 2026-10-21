/**
 * @name Code-graph export: guards at sinks
 * @description For each sink candidate, every GuardCondition that controls the sink's basic
 *              block (with polarity), relevant guards that do not control it or only follow it,
 *              and an explicit `none` row when no guard controls the sink.
 * @kind table
 * @id appsec-review/graph-export/cpp/guards
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `guards`.
//
// States: `dominating` = the guard controls the sink block (`controls(block, polarity)`);
// `post_dominating_only` = the sink block strictly dominates the guard (a check after the use);
// `non_dominating` = any other guard in the function that mentions a variable of the operand;
// `none` = one row per sink with no controlling guard (condition columns are empty).
// A condition inside a macro expansion is reported at the expansion site with in_macro "true".
//
// Operands: a comparison guard also reports its two operands (`lhs_*`, `rhs_*`: location, closed
// kind, integer constant value). Operand text is never exported; the normalizer slices it from the
// accepted source bytes. Inside a macro expansion an operand may be located at the expansion site.
// Object size: `destination_object_bytes` is the byte size of the fixed-size destination object
// (argument 0) of a catalog memory-write API sink, else -1. It is a type fact, not a safety claim;
// no query classifies how a guard relates to the sink or the destination.
import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.controlflow.Dominance
import semmle.code.cpp.ir.dataflow.DataFlow
import GraphExport

/** A variable read anywhere inside `e`. */
Variable mentioned(Expr e) { e.getAChild*() = result.getAnAccess() }

/** `guard` compares an expression the operand's value locally flows from or is equal to. */
predicate comparesOperand(GuardCondition guard, Expr operand) {
  exists(Expr compared | compared = guard.(ComparisonOperation).getAnOperand() |
    exists(Variable v | operand = v.getAnAccess() and compared = v.getAnAccess())
    or
    DataFlow::localExprFlow(compared, operand)
  )
}

string constrains(GuardCondition guard, Expr operand) {
  if comparesOperand(guard, operand)
  then result = "true"
  else
    if mentioned(operand) = mentioned(guard.(Expr))
    then result = "unknown"
    else result = "false"
}

string operatorOf(GuardCondition guard) {
  result = guard.(ComparisonOperation).getOperator()
  or
  not guard instanceof ComparisonOperation and result = ""
}

string boundDisplay(GuardCondition guard, Expr operand) {
  exists(ComparisonOperation c | c = guard |
    if exists(Variable v | operand = v.getAnAccess() and c.getLeftOperand() = v.getAnAccess())
    then result = c.getRightOperand().toString()
    else
      if exists(Variable v | operand = v.getAnAccess() and c.getRightOperand() = v.getAnAccess())
      then result = c.getLeftOperand().toString()
      else result = c.getRightOperand().toString()
  )
  or
  not guard instanceof ComparisonOperation and result = ""
}

/** The closed kind of a compared operand: sizeof | constant | field | variable | call | other. */
string operandKind(Expr e) {
  if e instanceof SizeofOperator
  then result = "sizeof"
  else
    if e.isConstant()
    then result = "constant"
    else
      if e instanceof FieldAccess
      then result = "field"
      else
        if e instanceof VariableAccess
        then result = "variable"
        else
          if e instanceof Call
          then result = "call"
          else result = "other"
}

/** The decimal value of an integer-constant `e`, else "". */
string operandValue(Expr e) {
  if e.getValue().regexpMatch("-?[0-9]+") then result = e.getValue() else result = ""
}

/** The `role` ("lhs" or "rhs") operand of a comparison guard (conversions excluded). */
Expr operandAt(GuardCondition guard, string role) {
  role = "lhs" and result = guard.(ComparisonOperation).getLeftOperand()
  or
  role = "rhs" and result = guard.(ComparisonOperation).getRightOperand()
}

/**
 * The location and kind columns of the `role` operand of `guard`. A guard that is not a
 * comparison has no operands: empty path, zero positions, kind "other", value "". The operand
 * text is never exported; the normalizer slices it from the accepted source bytes.
 */
predicate operandColumns(
  GuardCondition guard, string role, string path, int startLine, int startColumn, int endLine,
  int endColumn, string kind, string value
) {
  exists(Expr e | e = operandAt(guard, role) |
    GraphExport::locationColumns(e.getLocation(), path, startLine, startColumn, endLine,
      endColumn) and
    kind = operandKind(e) and
    value = operandValue(e)
  )
  or
  not guard instanceof ComparisonOperation and
  role = ["lhs", "rhs"] and
  path = "" and
  startLine = 0 and
  startColumn = 0 and
  endLine = 0 and
  endColumn = 0 and
  kind = "other" and
  value = ""
}

/** The destination (argument 0) of a catalog memory-write API call `sinkExpr`. */
Expr destinationOf(Expr sinkExpr) { GraphExport::memoryWriteDestination(sinkExpr, result) }

/** The destination object's byte size, or -1 when the sink has no destination of known size. */
int objectBytes(Expr sinkExpr) {
  result = GraphExport::destinationObjectBytes(destinationOf(sinkExpr))
  or
  not exists(GraphExport::destinationObjectBytes(destinationOf(sinkExpr))) and result = -1
}

predicate guardState(Expr sinkExpr, Expr operand, GuardCondition guard, string state, string polarity) {
  guard.(Expr).getEnclosingFunction() = sinkExpr.getEnclosingFunction() and
  (
    exists(boolean testIsTrue | guard.controls(sinkExpr.getBasicBlock(), testIsTrue) |
      state = "dominating" and
      (testIsTrue = true and polarity = "true_branch" or testIsTrue = false and polarity = "false_branch")
    )
    or
    not guard.controls(sinkExpr.getBasicBlock(), _) and
    mentioned(operand) = mentioned(guard.(Expr)) and
    polarity = "unknown" and
    (
      if bbStrictlyDominates(sinkExpr.getBasicBlock(), guard.(Expr).getBasicBlock())
      then state = "post_dominating_only"
      else state = "non_dominating"
    )
  )
}

query predicate guards(
  string sink_path, int sink_start_line, int sink_start_column, int sink_end_line,
  int sink_end_column, int argument_index, string guard_state, string polarity,
  string condition_path, int condition_start_line, int condition_start_column,
  int condition_end_line, int condition_end_column, string condition_display, string in_macro,
  string constrains_sink_operand, string comparison_operator, string bound_display,
  string lhs_path, int lhs_start_line, int lhs_start_column, int lhs_end_line,
  int lhs_end_column, string lhs_kind, string lhs_value, string rhs_path, int rhs_start_line,
  int rhs_start_column, int rhs_end_line, int rhs_end_column, string rhs_kind, string rhs_value,
  int destination_object_bytes
) {
  exists(Expr sinkExpr, Expr operand |
    GraphExport::sink(sinkExpr, operand, argument_index, _, _) and
    GraphExport::locationColumns(sinkExpr.getLocation(), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column) and
    destination_object_bytes = objectBytes(sinkExpr)
  |
    exists(GuardCondition guard | guardState(sinkExpr, operand, guard, guard_state, polarity) |
      GraphExport::locationColumns(guard.getLocation(), condition_path, condition_start_line,
        condition_start_column, condition_end_line, condition_end_column) and
      condition_display = guard.toString() and
      (if guard.(Expr).isInMacroExpansion() then in_macro = "true" else in_macro = "false") and
      constrains_sink_operand = constrains(guard, operand) and
      comparison_operator = operatorOf(guard) and
      bound_display = boundDisplay(guard, operand) and
      operandColumns(guard, "lhs", lhs_path, lhs_start_line, lhs_start_column, lhs_end_line,
        lhs_end_column, lhs_kind, lhs_value) and
      operandColumns(guard, "rhs", rhs_path, rhs_start_line, rhs_start_column, rhs_end_line,
        rhs_end_column, rhs_kind, rhs_value)
    )
    or
    not exists(GuardCondition guard | guard.controls(sinkExpr.getBasicBlock(), _)) and
    guard_state = "none" and
    polarity = "unknown" and
    condition_path = "" and
    condition_start_line = 0 and
    condition_start_column = 0 and
    condition_end_line = 0 and
    condition_end_column = 0 and
    condition_display = "" and
    in_macro = "false" and
    constrains_sink_operand = "false" and
    comparison_operator = "" and
    bound_display = "" and
    lhs_path = "" and
    lhs_start_line = 0 and
    lhs_start_column = 0 and
    lhs_end_line = 0 and
    lhs_end_column = 0 and
    lhs_kind = "other" and
    lhs_value = "" and
    rhs_path = "" and
    rhs_start_line = 0 and
    rhs_start_column = 0 and
    rhs_end_line = 0 and
    rhs_end_column = 0 and
    rhs_kind = "other" and
    rhs_value = ""
  )
}
