/**
 * @name Code-graph export: guards at sinks
 * @description For each sink candidate, every condition block that controls the sink's basic
 *              block (with polarity), relevant conditions that do not control it or only follow
 *              it, and an explicit `none` row when no condition controls the sink.
 * @kind table
 * @id appsec-review/graph-export/python/guards
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `guards`.
//
// A guard is a `ConditionBlock` (a basic block ending in a branch on a condition) in the sink's
// scope. States: `dominating` = the condition controls the sink block (`controls(block,
// polarity)`); `post_dominating_only` = the sink block strictly dominates the condition (a check
// after the use); `non_dominating` = any other condition in the scope that mentions a variable of
// the operand; `none` = one row per sink with no controlling condition (condition columns empty).
// Python has no macros: `in_macro` is always "false".
//
// Operands: a single-operator comparison (`a < b`, `a in b`, `a is not b`) also reports its two
// operands (`lhs_*`, `rhs_*`: location, closed kind, integer literal value). Operand text is never
// exported; the normalizer slices it from the accepted source bytes. Python has no fixed-size
// destination objects: `destination_object_bytes` is always -1.
import python
import semmle.python.dataflow.new.DataFlow
import GraphExport

/** A variable read anywhere inside `e` (`e` itself included). */
Variable mentioned(Expr e) {
  exists(Name n | n = e.getASubExpression*() and n.isUse() and result = n.getVariable())
}

/** The branch condition of the condition block `guard`. */
Expr conditionOf(ConditionBlock guard) { result = guard.getLastNode().getNode() }

/** A single-operator comparison condition. */
Compare comparison(ConditionBlock guard) {
  result = conditionOf(guard) and count(result.getAComparator()) = 1
}

/** `guard` compares an expression the operand's value locally flows from or shares a variable with. */
predicate comparesOperand(ConditionBlock guard, Expr operand) {
  exists(Expr compared, Compare c |
    c = comparison(guard) and compared = [c.getLeft(), c.getComparator(0)]
  |
    exists(Variable v |
      compared.(Name).getVariable() = v and
      operand.getASubExpression*().(Name).getVariable() = v
    )
    or
    exists(DataFlow::Node fromNode, DataFlow::Node toNode |
      fromNode.asExpr() = compared and toNode.asExpr() = operand.getASubExpression*() and
      DataFlow::localFlow(fromNode, toNode)
    )
  )
}

string constrains(ConditionBlock guard, Expr operand) {
  if comparesOperand(guard, operand)
  then result = "true"
  else
    if mentioned(operand) = mentioned(conditionOf(guard))
    then result = "unknown"
    else result = "false"
}

string operatorOf(ConditionBlock guard) {
  result = comparison(guard).getOp(0).getSymbol()
  or
  not exists(comparison(guard)) and result = ""
}

string boundDisplay(ConditionBlock guard, Expr operand) {
  exists(Compare c | c = comparison(guard) |
    if mentioned(c.getLeft()) = mentioned(operand)
    then result = c.getComparator(0).toString()
    else
      if mentioned(c.getComparator(0)) = mentioned(operand)
      then result = c.getLeft().toString()
      else result = c.getComparator(0).toString()
  )
  or
  not exists(comparison(guard)) and result = ""
}

/** The closed kind of a compared operand: constant | field | variable | call | other. */
string operandKind(Expr e) {
  if e instanceof ImmutableLiteral
  then result = "constant"
  else
    if e instanceof Attribute
    then result = "field"
    else
      if e instanceof Name
      then result = "variable"
      else
        if e instanceof Call
        then result = "call"
        else result = "other"
}

/** The decimal value of an integer literal `e`, else "". */
string operandValue(Expr e) {
  result = e.(IntegerLiteral).getValue().toString()
  or
  not e instanceof IntegerLiteral and result = ""
}

/** The `role` ("lhs" or "rhs") operand of a comparison guard. */
Expr operandAt(ConditionBlock guard, string role) {
  role = "lhs" and result = comparison(guard).getLeft()
  or
  role = "rhs" and result = comparison(guard).getComparator(0)
}

/**
 * The location and kind columns of the `role` operand of `guard`. A guard that is not a
 * single-operator comparison has no operands: empty path, zero positions, kind "other", value "".
 */
predicate operandColumns(
  ConditionBlock guard, string role, string path, int startLine, int startColumn, int endLine,
  int endColumn, string kind, string value
) {
  exists(Expr e | e = operandAt(guard, role) |
    GraphExport::locationColumns(e.getLocation(), path, startLine, startColumn, endLine,
      endColumn) and
    kind = operandKind(e) and
    value = operandValue(e)
  )
  or
  not exists(comparison(guard)) and
  role = ["lhs", "rhs"] and
  path = "" and
  startLine = 0 and
  startColumn = 0 and
  endLine = 0 and
  endColumn = 0 and
  kind = "other" and
  value = ""
}

BasicBlock sinkBlock(DataFlow::Node sinkNode) { result = sinkNode.asCfgNode().getBasicBlock() }

predicate guardState(
  DataFlow::Node sinkNode, Expr operand, ConditionBlock guard, string state, string polarity
) {
  guard.getScope() = sinkNode.getScope() and
  (
    exists(boolean testIsTrue | guard.controls(sinkBlock(sinkNode), testIsTrue) |
      state = "dominating" and
      (testIsTrue = true and polarity = "true_branch" or testIsTrue = false and polarity = "false_branch")
    )
    or
    not guard.controls(sinkBlock(sinkNode), _) and
    mentioned(operand) = mentioned(conditionOf(guard)) and
    polarity = "unknown" and
    (
      if sinkBlock(sinkNode).strictlyDominates(guard)
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
  exists(DataFlow::Node sinkNode, DataFlow::Node operandNode, Expr operand |
    GraphExport::sink(sinkNode, operandNode, argument_index, _, _) and
    operand = operandNode.asExpr() and
    GraphExport::locationColumns(sinkNode.getLocation(), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column) and
    destination_object_bytes = -1
  |
    exists(ConditionBlock guard | guardState(sinkNode, operand, guard, guard_state, polarity) |
      GraphExport::locationColumns(conditionOf(guard).getLocation(), condition_path,
        condition_start_line, condition_start_column, condition_end_line, condition_end_column) and
      condition_display = conditionOf(guard).toString() and
      in_macro = "false" and
      constrains_sink_operand = constrains(guard, operand) and
      comparison_operator = operatorOf(guard) and
      bound_display = boundDisplay(guard, operand) and
      operandColumns(guard, "lhs", lhs_path, lhs_start_line, lhs_start_column, lhs_end_line,
        lhs_end_column, lhs_kind, lhs_value) and
      operandColumns(guard, "rhs", rhs_path, rhs_start_line, rhs_start_column, rhs_end_line,
        rhs_end_column, rhs_kind, rhs_value)
    )
    or
    not exists(ConditionBlock guard | guard.controls(sinkBlock(sinkNode), _)) and
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
