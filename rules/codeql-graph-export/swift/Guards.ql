/**
 * @name Code-graph export: guards at sinks
 * @description For each sink candidate, every branch condition that controls the sink's basic
 *              block (with polarity), relevant conditions that do not control it or only follow
 *              it, and an explicit `none` row when no condition controls the sink.
 * @kind table
 * @id appsec-review/graph-export/swift/guards
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `guards`.
//
// A guard is the boolean expression that ends a conditional basic block (`if`, `guard`,
// `while`, a ternary); it controls a block when one boolean edge out of it dominates the block.
// States and polarity follow the C/C++ pack. Swift has no macro expansion in the C sense, so
// `in_macro` is always "false"; Swift exposes no fixed-size destination object of a memory
// write, so `destination_object_bytes` is always -1. Operand kinds: `MemoryLayout<T>.size`,
// `.stride` and `.alignment` are "sizeof"; literals are "constant"; member reads are "field";
// variable reads are "variable"; calls are "call"; anything else is "other".
import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.controlflow.BasicBlocks
import codeql.swift.controlflow.ControlFlowGraph
import codeql.swift.generated.ParentChild
import GraphExport

/** A branch condition: the expression evaluated last in a conditional basic block. */
class Guard extends Expr {
  ConditionBlock block;

  Guard() { block.getLastNode().getNode().asAstNode() = this }

  /** This condition's `value` edge dominates `bb`. */
  predicate controls(BasicBlock bb, boolean value) {
    exists(BooleanSuccessor s | s.getValue() = value | block.edgeDominates(bb, s))
  }

  BasicBlock getBlock() { result = block }
}

/** A comparison `a op b` with a standard comparison operator. */
class Comparison extends BinaryExpr {
  Comparison() { this.getOperator().getShortName() = ["<", "<=", ">", ">=", "==", "!="] }

  string getOperatorText() { result = this.getOperator().getShortName() }
}

/** A variable read anywhere inside `e`. */
VarDecl mentioned(Expr e) {
  exists(DeclRefExpr access | access.getDecl() = result and e = getImmediateParent*(access))
}

/** `guard` compares an expression the operand's value locally flows from or is equal to. */
predicate comparesOperand(Guard guard, Expr operand) {
  exists(Expr compared |
    compared = [guard.(Comparison).getLeftOperand(), guard.(Comparison).getRightOperand()]
  |
    exists(VarDecl v |
      operand.resolve().(DeclRefExpr).getDecl() = v and compared.resolve().(DeclRefExpr).getDecl() = v
    )
    or
    DataFlow::localFlow(DataFlow::exprNode(compared), DataFlow::exprNode(operand))
  )
}

string constrains(Guard guard, Expr operand) {
  if comparesOperand(guard, operand)
  then result = "true"
  else
    if mentioned(operand) = mentioned(guard)
    then result = "unknown"
    else result = "false"
}

string operatorOf(Guard guard) {
  result = guard.(Comparison).getOperatorText()
  or
  not guard instanceof Comparison and result = ""
}

/** The `role` ("lhs" or "rhs") operand of a comparison guard. */
Expr operandAt(Guard guard, string role) {
  role = "lhs" and result = guard.(Comparison).getLeftOperand()
  or
  role = "rhs" and result = guard.(Comparison).getRightOperand()
}

/** `e` reads the named variable. */
predicate readsVariableOf(Expr e, Expr operand) {
  exists(VarDecl v |
    e.resolve().(DeclRefExpr).getDecl() = v and operand.resolve().(DeclRefExpr).getDecl() = v
  )
}

string boundDisplay(Guard guard, Expr operand) {
  exists(Comparison c | c = guard |
    if readsVariableOf(c.getLeftOperand(), operand)
    then result = c.getRightOperand().toString()
    else
      if readsVariableOf(c.getRightOperand(), operand)
      then result = c.getLeftOperand().toString()
      else result = c.getRightOperand().toString()
  )
  or
  not guard instanceof Comparison and result = ""
}

/** `MemoryLayout<T>.size`, `.stride` or `.alignment`. */
predicate memoryLayoutQuery(Expr e) {
  exists(MemberRefExpr m | m = e |
    m.getMember().(VarDecl).getName() = ["size", "stride", "alignment"] and
    GraphExport::memberType(m.getMember()).getName() = "MemoryLayout"
  )
}

/** The closed kind of a compared operand: sizeof | constant | field | variable | call | other. */
string operandKind(Expr e) {
  exists(Expr r | r = e.resolve() |
    if memoryLayoutQuery(r)
    then result = "sizeof"
    else
      if r instanceof LiteralExpr
      then result = "constant"
      else
        if r instanceof MemberRefExpr
        then result = "field"
        else
          if r instanceof DeclRefExpr
          then result = "variable"
          else
            if r instanceof ApplyExpr
            then result = "call"
            else result = "other"
  )
}

/** The decimal value of an integer-literal `e`, else "". */
string operandValue(Expr e) {
  if e.resolve().(IntegerLiteralExpr).getStringValue().regexpMatch("-?[0-9]+")
  then result = e.resolve().(IntegerLiteralExpr).getStringValue()
  else result = ""
}

predicate operandColumns(
  Guard guard, string role, string path, int startLine, int startColumn, int endLine,
  int endColumn, string kind, string value
) {
  exists(Expr e | e = operandAt(guard, role) |
    GraphExport::locationColumns(e.getLocation(), path, startLine, startColumn, endLine,
      endColumn) and
    kind = operandKind(e) and
    value = operandValue(e)
  )
  or
  not guard instanceof Comparison and
  role = ["lhs", "rhs"] and
  path = "" and
  startLine = 0 and
  startColumn = 0 and
  endLine = 0 and
  endColumn = 0 and
  kind = "other" and
  value = ""
}

predicate guardState(Expr sinkExpr, Expr operand, Guard guard, string state, string polarity) {
  guard.getEnclosingFunction() = sinkExpr.getEnclosingFunction() and
  (
    exists(boolean testIsTrue | guard.controls(GraphExport::blockOf(sinkExpr), testIsTrue) |
      state = "dominating" and
      (
        testIsTrue = true and polarity = "true_branch"
        or
        testIsTrue = false and polarity = "false_branch"
      )
    )
    or
    not guard.controls(GraphExport::blockOf(sinkExpr), _) and
    mentioned(operand) = mentioned(guard) and
    polarity = "unknown" and
    (
      if GraphExport::blockOf(sinkExpr).strictlyDominates(guard.getBlock())
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
    exists(Guard guard | guardState(sinkExpr, operand, guard, guard_state, polarity) |
      GraphExport::locationColumns(guard.getLocation(), condition_path, condition_start_line,
        condition_start_column, condition_end_line, condition_end_column) and
      condition_display = guard.toString() and
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
    not exists(Guard guard | guard.controls(GraphExport::blockOf(sinkExpr), _)) and
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
