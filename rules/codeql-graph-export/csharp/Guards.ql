/**
 * @name Code-graph export: guards at sinks
 * @description For each sink candidate, every boolean guard that controls the sink's basic
 *              block (with polarity), relevant guards that do not control it or only follow it,
 *              and an explicit `none` row when no guard controls the sink.
 * @kind table
 * @id appsec-review/graph-export/csharp/guards
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `guards`.
//
// States: `dominating` = the guard controls the sink block with a boolean value
// (`controlsBasicBlock(block, v)`); `post_dominating_only` = the sink block strictly dominates
// the guard (a check after the use); `non_dominating` = any other boolean guard in the callable
// that mentions a variable of the operand; `none` = one row per sink with no controlling guard
// (condition columns are empty).
//
// C# has no macros: `in_macro` is always "false". C# has no fixed-size destination objects:
// `destination_object_bytes` is always -1. Operand text is never exported; the normalizer slices
// it from the accepted source bytes.
import csharp
import semmle.code.csharp.controlflow.Guards
import semmle.code.csharp.dataflow.DataFlow
import GraphExport

/** A boolean condition that controls at least one basic block. */
class BooleanGuard extends Guard {
  BooleanGuard() {
    exists(GuardValue v | exists(v.asBooleanValue()) | this.controlsBasicBlock(_, v))
  }
}

/** A variable (local, parameter or field) read anywhere inside `e`. */
Variable mentioned(Expr e) { e.getAChild*() = result.getAnAccess() }

/** `guard` compares an expression the operand's value locally flows from or is equal to. */
predicate comparesOperand(BooleanGuard guard, Expr operand) {
  exists(Expr compared | compared = guard.(ComparisonOperation).getAnOperand() |
    exists(Variable v | operand = v.getAnAccess() and compared = v.getAnAccess())
    or
    DataFlow::localExprFlow(compared, operand)
  )
}

string constrains(BooleanGuard guard, Expr operand) {
  if comparesOperand(guard, operand)
  then result = "true"
  else
    if mentioned(operand) = mentioned(guard)
    then result = "unknown"
    else result = "false"
}

string operatorOf(BooleanGuard guard) {
  result = guard.(ComparisonOperation).getOperator()
  or
  not guard instanceof ComparisonOperation and result = ""
}

string boundDisplay(BooleanGuard guard, Expr operand) {
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

/**
 * The closed kind of a compared operand: constant | field | variable | call | other. A property
 * access is a "field" (C# has no `sizeof` over runtime objects, so "sizeof" is never emitted).
 */
string operandKind(Expr e) {
  if exists(e.getValue())
  then result = "constant"
  else
    if e instanceof FieldAccess or e instanceof PropertyAccess
    then result = "field"
    else
      if e instanceof LocalScopeVariableAccess
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

/** The `role` ("lhs" or "rhs") operand of a comparison guard. */
Expr operandAt(BooleanGuard guard, string role) {
  role = "lhs" and result = guard.(ComparisonOperation).getLeftOperand()
  or
  role = "rhs" and result = guard.(ComparisonOperation).getRightOperand()
}

/**
 * The location and kind columns of the `role` operand of `guard`. A guard that is not a
 * comparison has no operands: empty path, zero positions, kind "other", value "".
 */
predicate operandColumns(
  BooleanGuard guard, string role, string path, int startLine, int startColumn, int endLine,
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

/** `guard` controls the basic block of `sinkExpr` with the boolean value `b`. */
predicate controlsSink(BooleanGuard guard, Expr sinkExpr, boolean b) {
  exists(GuardValue v | v.asBooleanValue() = b |
    guard.controlsBasicBlock(sinkExpr.getBasicBlock(), v)
  )
}

predicate guardState(Expr sinkExpr, Expr operand, BooleanGuard guard, string state, string polarity) {
  guard.getEnclosingCallable() = sinkExpr.getEnclosingCallable() and
  (
    exists(boolean b | controlsSink(guard, sinkExpr, b) |
      state = "dominating" and
      (b = true and polarity = "true_branch" or b = false and polarity = "false_branch")
    )
    or
    not controlsSink(guard, sinkExpr, _) and
    mentioned(operand) = mentioned(guard) and
    polarity = "unknown" and
    (
      if sinkExpr.getBasicBlock().strictlyDominates(guard.getBasicBlock())
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
    in_macro = "false" and
    destination_object_bytes = -1
  |
    exists(BooleanGuard guard | guardState(sinkExpr, operand, guard, guard_state, polarity) |
      GraphExport::locationColumns(guard.getLocation(), condition_path, condition_start_line,
        condition_start_column, condition_end_line, condition_end_column) and
      condition_display = guard.toString() and
      constrains_sink_operand = constrains(guard, operand) and
      comparison_operator = operatorOf(guard) and
      bound_display = boundDisplay(guard, operand) and
      operandColumns(guard, "lhs", lhs_path, lhs_start_line, lhs_start_column, lhs_end_line,
        lhs_end_column, lhs_kind, lhs_value) and
      operandColumns(guard, "rhs", rhs_path, rhs_start_line, rhs_start_column, rhs_end_line,
        rhs_end_column, rhs_kind, rhs_value)
    )
    or
    not controlsSink(_, sinkExpr, _) and
    guard_state = "none" and
    polarity = "unknown" and
    condition_path = "" and
    condition_start_line = 0 and
    condition_start_column = 0 and
    condition_end_line = 0 and
    condition_end_column = 0 and
    condition_display = "" and
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