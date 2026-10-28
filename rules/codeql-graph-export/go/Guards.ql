/**
 * @name Code-graph export: guards at sinks
 * @description For each sink candidate, every branch condition that controls the sink's basic
 *              block (with polarity), relevant conditions that do not control it or only follow
 *              it, and an explicit `none` row when no condition controls the sink.
 * @kind table
 * @id appsec-review/graph-export/go/guards
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `guards`.
//
// States: `dominating` = a ControlFlow::ConditionGuardNode of the condition dominates the sink
// block (polarity from its outcome); `post_dominating_only` = the sink block strictly dominates
// the condition (a check after the use); `non_dominating` = any other branch condition in the
// function that mentions a variable of the operand; `none` = one row per sink with no
// controlling condition (condition columns are empty).
// Go has no macros: in_macro is always "false". Go has no fixed-size memory-write sink:
// destination_object_bytes is always -1.
import go
import GraphExport

/** A variable read anywhere inside `e`. */
Variable mentioned(Expr e) { e.getAChild*().(Ident).refersTo(result) }

/** A branch condition: the condition of some guard node. */
predicate isCondition(Expr cond) { exists(ControlFlow::ConditionGuardNode g | g.getCondition() = cond) }

/** `cond` compares an expression the operand's value locally flows from or is equal to. */
predicate comparesOperand(ComparisonExpr cond, Expr operand) {
  exists(Expr compared | compared = cond.getAnOperand() |
    exists(Variable v | operand.(Ident).refersTo(v) and compared.(Ident).refersTo(v))
    or
    DataFlow::localFlow(DataFlow::exprNode(compared), DataFlow::exprNode(operand))
  )
}

string constrains(Expr cond, Expr operand) {
  if comparesOperand(cond, operand)
  then result = "true"
  else
    if mentioned(operand) = mentioned(cond)
    then result = "unknown"
    else result = "false"
}

string operatorOf(Expr cond) {
  result = cond.(ComparisonExpr).getOperator()
  or
  not cond instanceof ComparisonExpr and result = ""
}

/** `a` and `b` are reads of one variable. */
predicate sameVariable(Expr a, Expr b) {
  exists(Variable v | a.(Ident).refersTo(v) and b.(Ident).refersTo(v))
}

string boundDisplay(Expr cond, Expr operand) {
  exists(ComparisonExpr c | c = cond |
    if sameVariable(operand, c.getLeftOperand())
    then result = c.getRightOperand().toString()
    else
      if sameVariable(operand, c.getRightOperand())
      then result = c.getLeftOperand().toString()
      else result = c.getRightOperand().toString()
  )
  or
  not cond instanceof ComparisonExpr and result = ""
}

/** The closed kind of a compared operand: constant | field | variable | call | other. */
string operandKind(Expr e) {
  if e.isConst()
  then result = "constant"
  else
    if e.(Name).getTarget() instanceof Field
    then result = "field"
    else
      if e.(Name).getTarget() instanceof Variable
      then result = "variable"
      else
        if e instanceof CallExpr
        then result = "call"
        else result = "other"
}

/** The decimal value of an integer-constant `e`, else "". */
string operandValue(Expr e) {
  if e.getExactValue().regexpMatch("-?[0-9]+") then result = e.getExactValue() else result = ""
}

/** The `role` ("lhs" or "rhs") operand of a comparison condition. */
Expr operandAt(Expr cond, string role) {
  role = "lhs" and result = cond.(ComparisonExpr).getLeftOperand()
  or
  role = "rhs" and result = cond.(ComparisonExpr).getRightOperand()
}

/**
 * The location and kind columns of the `role` operand of `cond`. A condition that is not a
 * comparison has no operands: empty path, zero positions, kind "other", value "".
 */
predicate operandColumns(
  Expr cond, string role, string path, int startLine, int startColumn, int endLine,
  int endColumn, string kind, string value
) {
  exists(Expr e | e = operandAt(cond, role) |
    GraphExport::locationColumns(e.getLocation(), path, startLine, startColumn, endLine,
      endColumn) and
    kind = operandKind(e) and
    value = operandValue(e)
  )
  or
  not cond instanceof ComparisonExpr and
  role = ["lhs", "rhs"] and
  path = "" and
  startLine = 0 and
  startColumn = 0 and
  endLine = 0 and
  endColumn = 0 and
  kind = "other" and
  value = ""
}

/** `cond` controls the sink call's block with outcome `outcome`. */
predicate controls(Expr cond, DataFlow::CallNode call, boolean outcome) {
  exists(ControlFlow::ConditionGuardNode g |
    g.getCondition() = cond and
    g.getOutcome() = outcome and
    g.dominates(call.getBasicBlock())
  )
}

predicate guardState(
  DataFlow::CallNode call, Expr operand, Expr cond, string state, string polarity
) {
  isCondition(cond) and
  cond.getEnclosingFunction() = GraphExport::callFunction(call) and
  (
    exists(boolean outcome | controls(cond, call, outcome) |
      state = "dominating" and
      (outcome = true and polarity = "true_branch" or outcome = false and polarity = "false_branch")
    )
    or
    not controls(cond, call, _) and
    mentioned(operand) = mentioned(cond) and
    polarity = "unknown" and
    (
      if call.getBasicBlock().strictlyDominates(DataFlow::exprNode(cond).getBasicBlock())
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
  exists(DataFlow::CallNode call, Expr operand |
    GraphExport::sink(call, operand, argument_index, _, _) and
    GraphExport::locationColumns(GraphExport::sinkLocation(call), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column) and
    destination_object_bytes = -1 and
    in_macro = "false"
  |
    exists(Expr cond | guardState(call, operand, cond, guard_state, polarity) |
      GraphExport::locationColumns(cond.getLocation(), condition_path, condition_start_line,
        condition_start_column, condition_end_line, condition_end_column) and
      condition_display = cond.toString() and
      constrains_sink_operand = constrains(cond, operand) and
      comparison_operator = operatorOf(cond) and
      bound_display = boundDisplay(cond, operand) and
      operandColumns(cond, "lhs", lhs_path, lhs_start_line, lhs_start_column, lhs_end_line,
        lhs_end_column, lhs_kind, lhs_value) and
      operandColumns(cond, "rhs", rhs_path, rhs_start_line, rhs_start_column, rhs_end_line,
        rhs_end_column, rhs_kind, rhs_value)
    )
    or
    not controls(_, call, _) and
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
