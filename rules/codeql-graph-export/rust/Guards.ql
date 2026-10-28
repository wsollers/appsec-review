/**
 * @name Code-graph export: guards at sinks
 * @description For each sink candidate, every boolean condition that controls the sink's
 *              basic block (with polarity), relevant conditions that do not control it or only
 *              follow it, and an explicit `none` row when no condition controls the sink.
 * @kind table
 * @id appsec-review/graph-export/rust/guards
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `guards`.
//
// A guard is the expression that ends a basic block with boolean successors (an `if`/`while`
// condition, a `&&`/`||` operand, a `match` guard) in the sink's function. States:
// `dominating` = the `true`/`false` edge out of the guard block dominates the sink block;
// `post_dominating_only` = the sink block strictly dominates the guard block; `non_dominating` =
// any other guard that mentions a variable of the operand; `none` = one row per sink with no
// controlling guard. Operand kinds are syntactic: Rust has no `sizeof` operand kind.
// `destination_object_bytes` is always -1: Rust has no catalog memory-write API sink.
import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.controlflow.BasicBlocks
import codeql.rust.controlflow.ControlFlowGraph
import GraphExport

/** A boolean guard of the function of `sinkExpr`: the last AST node of a condition block. */
predicate guardOf(Expr sinkExpr, Expr guard, ConditionBasicBlock cb) {
  guard = cb.getLastNode().getAstNode() and
  exists(BooleanSuccessor s | exists(cb.getASuccessor(s))) and
  GraphExport::enclosingFunction(guard) = GraphExport::enclosingFunction(sinkExpr)
}

/** The `branch` edge out of `cb` dominates the block of `sinkExpr`. */
predicate controls(ConditionBasicBlock cb, Expr sinkExpr, boolean branch) {
  exists(BasicBlock bb, BooleanSuccessor s |
    GraphExport::cfgPosition(sinkExpr, bb, _) and
    s.getValue() = branch and
    cb.edgeDominates(bb, s)
  )
}

/** A variable read anywhere inside `e`. */
Variable mentioned(Expr e) { result.getAnAccess().getParentNode*() = e }

/** `guard` compares the operand's variable, or an expression whose value locally flows to it. */
predicate comparesOperand(Expr guard, Expr operand) {
  exists(Expr compared | compared = operandAt(guard, _) |
    exists(Variable v | operand = v.getAnAccess() and compared = v.getAnAccess())
    or
    exists(DataFlow::Node a, DataFlow::Node b |
      a.asExpr() = compared and b.asExpr() = operand and DataFlow::localFlow(a, b)
    )
  )
}

string constrains(Expr guard, Expr operand) {
  if comparesOperand(guard, operand)
  then result = "true"
  else
    if mentioned(operand) = mentioned(guard)
    then result = "unknown"
    else result = "false"
}

string operatorOf(Expr guard) {
  result = guard.(ComparisonOperation).(BinaryExpr).getOperatorName()
  or
  not guard instanceof ComparisonOperation and result = ""
}

string boundDisplay(Expr guard, Expr operand) {
  exists(BinaryExpr c | c = guard and c instanceof ComparisonOperation |
    if exists(Variable v | operand = v.getAnAccess() and c.getLhs() = v.getAnAccess())
    then result = c.getRhs().toString()
    else
      if exists(Variable v | operand = v.getAnAccess() and c.getRhs() = v.getAnAccess())
      then result = c.getLhs().toString()
      else result = c.getRhs().toString()
  )
  or
  not guard instanceof ComparisonOperation and result = ""
}

/** The closed kind of a compared operand: constant | field | variable | call | other. */
string operandKind(Expr e) {
  if e instanceof LiteralExpr
  then result = "constant"
  else
    if e instanceof FieldExpr
    then result = "field"
    else
      if e instanceof VariableAccess
      then result = "variable"
      else
        if e instanceof Call
        then result = "call"
        else result = "other"
}

/** The decimal value of a decimal integer literal `e` (suffix removed), else "". */
string operandValue(Expr e) {
  result =
    e.(IntegerLiteralExpr)
        .getTextValue()
        .regexpCapture("([0-9][0-9_]*)(i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize)?", 1)
        .replaceAll("_", "")
  or
  not e.(IntegerLiteralExpr)
      .getTextValue()
      .regexpMatch("([0-9][0-9_]*)(i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize)?") and
  result = ""
}

Expr operandAt(Expr guard, string role) {
  role = "lhs" and result = guard.(ComparisonOperation).(BinaryExpr).getLhs()
  or
  role = "rhs" and result = guard.(ComparisonOperation).(BinaryExpr).getRhs()
}

predicate operandColumns(
  Expr guard, string role, string path, int startLine, int startColumn, int endLine,
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

predicate guardState(Expr sinkExpr, Expr operand, Expr guard, string state, string polarity) {
  exists(ConditionBasicBlock cb | guardOf(sinkExpr, guard, cb) |
    exists(boolean branch | controls(cb, sinkExpr, branch) |
      state = "dominating" and
      (branch = true and polarity = "true_branch" or branch = false and polarity = "false_branch")
    )
    or
    not controls(cb, sinkExpr, _) and
    mentioned(operand) = mentioned(guard) and
    polarity = "unknown" and
    (
      if
        exists(BasicBlock sb | GraphExport::cfgPosition(sinkExpr, sb, _) | sb.strictlyDominates(cb))
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
    destination_object_bytes = -1
  |
    exists(Expr guard | guardState(sinkExpr, operand, guard, guard_state, polarity) |
      GraphExport::locationColumns(guard.getLocation(), condition_path, condition_start_line,
        condition_start_column, condition_end_line, condition_end_column) and
      condition_display = guard.toString() and
      (if guard.isInMacroExpansion() then in_macro = "true" else in_macro = "false") and
      constrains_sink_operand = constrains(guard, operand) and
      comparison_operator = operatorOf(guard) and
      bound_display = boundDisplay(guard, operand) and
      operandColumns(guard, "lhs", lhs_path, lhs_start_line, lhs_start_column, lhs_end_line,
        lhs_end_column, lhs_kind, lhs_value) and
      operandColumns(guard, "rhs", rhs_path, rhs_start_line, rhs_start_column, rhs_end_line,
        rhs_end_column, rhs_kind, rhs_value)
    )
    or
    not exists(ConditionBasicBlock cb | guardOf(sinkExpr, _, cb) and controls(cb, sinkExpr, _)) and
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
