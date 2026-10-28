/**
 * @name Code-graph export: guards at sinks
 * @description For each sink candidate, every condition guard that dominates the sink's basic
 *              block (with polarity), relevant conditions that do not dominate it or only follow
 *              it, and an explicit `none` row when no guard dominates the sink.
 * @kind table
 * @id appsec-review/graph-export/javascript/guards
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `guards`.
//
// States: `dominating` = a ConditionGuardNode of the condition dominates the sink block (its
// outcome is the polarity); `post_dominating_only` = the sink block strictly dominates the
// condition (a check after the use); `non_dominating` = any other condition in the function
// that mentions a variable of the operand; `none` = one row per sink with no dominating guard
// (condition columns are empty). JavaScript has no macros: in_macro is always "false". The
// object-size column has no JavaScript meaning: destination_object_bytes is always -1.
import javascript
import GraphExport

/** A variable read anywhere inside `e`. */
Variable mentioned(Expr e) { e.getAChildExpr*() = result.getAnAccess() }

/** A variable read anywhere inside the sink operand. */
Variable operandVariable(DataFlow::Node operand) { result = mentioned(operand.asExpr()) }

/** `test` compares an expression the operand's value locally flows from or is equal to. */
predicate comparesOperand(Expr test, DataFlow::Node operand) {
  exists(Expr compared |
    compared = test.getUnderlyingValue().(Comparison).getAnOperand().getUnderlyingValue()
  |
    exists(Variable v | operand.asExpr() = v.getAnAccess() and compared = v.getAnAccess())
    or
    DataFlow::valueNode(compared).getASuccessor+() = operand
  )
}

string constrains(Expr test, DataFlow::Node operand) {
  if comparesOperand(test, operand)
  then result = "true"
  else
    if operandVariable(operand) = mentioned(test)
    then result = "unknown"
    else result = "false"
}

string operatorOf(Expr test) {
  result = test.getUnderlyingValue().(Comparison).getOperator()
  or
  not test.getUnderlyingValue() instanceof Comparison and result = ""
}

string boundDisplay(Expr test, DataFlow::Node operand) {
  exists(Comparison c | c = test.getUnderlyingValue() |
    if
      exists(Variable v |
        operand.asExpr() = v.getAnAccess() and c.getLeftOperand().getUnderlyingValue() = v.getAnAccess()
      )
    then result = c.getRightOperand().toString()
    else
      if
        exists(Variable v |
          operand.asExpr() = v.getAnAccess() and
          c.getRightOperand().getUnderlyingValue() = v.getAnAccess()
        )
      then result = c.getLeftOperand().toString()
      else result = c.getRightOperand().toString()
  )
  or
  not test.getUnderlyingValue() instanceof Comparison and result = ""
}

/** The closed kind of a compared operand: constant | field | variable | call | other. */
string operandKind(Expr e) {
  if e.getUnderlyingValue() instanceof Literal or exists(e.getIntValue())
  then result = "constant"
  else
    if e.getUnderlyingValue() instanceof PropAccess
    then result = "field"
    else
      if e.getUnderlyingValue() instanceof VarAccess
      then result = "variable"
      else
        if e.getUnderlyingValue() instanceof InvokeExpr
        then result = "call"
        else result = "other"
}

/** The decimal value of an integer-constant `e`, else "". */
string operandValue(Expr e) {
  result = e.getIntValue().toString()
  or
  not exists(e.getIntValue()) and result = ""
}

/** The `role` ("lhs" or "rhs") operand of a comparison condition. */
Expr operandAt(Expr test, string role) {
  role = "lhs" and result = test.getUnderlyingValue().(Comparison).getLeftOperand()
  or
  role = "rhs" and result = test.getUnderlyingValue().(Comparison).getRightOperand()
}

/**
 * The location and kind columns of the `role` operand of `test`. A condition that is not a
 * comparison has no operands: empty path, zero positions, kind "other", value "".
 */
predicate operandColumns(
  Expr test, string role, string path, int startLine, int startColumn, int endLine,
  int endColumn, string kind, string value
) {
  exists(Expr e | e = operandAt(test, role) |
    GraphExport::locationColumns(e.getLocation(), path, startLine, startColumn, endLine,
      endColumn) and
    kind = operandKind(e) and
    value = operandValue(e)
  )
  or
  not test.getUnderlyingValue() instanceof Comparison and
  role = ["lhs", "rhs"] and
  path = "" and
  startLine = 0 and
  startColumn = 0 and
  endLine = 0 and
  endColumn = 0 and
  kind = "other" and
  value = ""
}

/** The basic block the sink is evaluated in. */
ReachableBasicBlock sinkBlock(DataFlow::Node sinkNode) {
  result = sinkNode.asExpr().getBasicBlock()
}

/** `test` is the condition of a guard node that dominates the sink block. */
predicate dominatingTest(DataFlow::Node sinkNode, Expr test) {
  exists(ConditionGuardNode g | g.getTest() = test | g.dominates(sinkBlock(sinkNode)))
}

predicate guardState(
  DataFlow::Node sinkNode, DataFlow::Node operand, Expr test, string state, string polarity
) {
  test.getContainer() = sinkNode.getContainer() and
  (
    exists(ConditionGuardNode g | g.getTest() = test and g.dominates(sinkBlock(sinkNode)) |
      state = "dominating" and
      (
        g.getOutcome() = true and polarity = "true_branch"
        or
        g.getOutcome() = false and polarity = "false_branch"
      )
    )
    or
    exists(ConditionGuardNode g | g.getTest() = test) and
    not dominatingTest(sinkNode, test) and
    operandVariable(operand) = mentioned(test) and
    polarity = "unknown" and
    (
      if sinkBlock(sinkNode).strictlyDominates(test.getBasicBlock())
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
  exists(DataFlow::Node sinkNode, DataFlow::Node operand |
    GraphExport::sink(sinkNode, operand, argument_index, _, _) and
    GraphExport::locationColumns(sinkNode.getLocation(), sink_path, sink_start_line,
      sink_start_column, sink_end_line, sink_end_column) and
    destination_object_bytes = -1 and
    in_macro = "false"
  |
    exists(Expr test | guardState(sinkNode, operand, test, guard_state, polarity) |
      GraphExport::locationColumns(test.getLocation(), condition_path, condition_start_line,
        condition_start_column, condition_end_line, condition_end_column) and
      condition_display = test.toString() and
      constrains_sink_operand = constrains(test, operand) and
      comparison_operator = operatorOf(test) and
      bound_display = boundDisplay(test, operand) and
      operandColumns(test, "lhs", lhs_path, lhs_start_line, lhs_start_column, lhs_end_line,
        lhs_end_column, lhs_kind, lhs_value) and
      operandColumns(test, "rhs", rhs_path, rhs_start_line, rhs_start_column, rhs_end_line,
        rhs_end_column, rhs_kind, rhs_value)
    )
    or
    not dominatingTest(sinkNode, _) and
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
