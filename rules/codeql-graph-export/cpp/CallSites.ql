/**
 * @name Code-graph export: call sites
 * @description Every call in a function defined inside the source root, with its resolved
 *              callee or an explicit unresolved row. One row per (call, candidate callee).
 * @kind table
 * @id appsec-review/graph-export/cpp/call-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `call_sites`.
import cpp
import semmle.code.cpp.ir.dataflow.DataFlow
import GraphExport

/** Function addresses flowing to the callee expression of a call through a function pointer. */
module FunctionPointerConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n.asExpr() instanceof FunctionAccess }

  predicate isSink(DataFlow::Node n) { n.asExpr() = any(ExprCall c).getExpr() }
}

module FunctionPointerFlow = DataFlow::Global<FunctionPointerConfig>;

Function pointerTarget(ExprCall call) {
  exists(DataFlow::Node source, DataFlow::Node sink |
    FunctionPointerFlow::flow(source, sink) and
    sink.asExpr() = call.getExpr() and
    result = source.asExpr().(FunctionAccess).getTarget()
  )
}

/** Every defined override (including the static target) a virtual call may dispatch to. */
Function virtualCandidate(FunctionCall call) {
  call.isVirtual() and
  (
    result = call.getTarget()
    or
    result = call.getTarget().(MemberFunction).getAnOverridingFunction+()
  ) and
  result.hasDefinition()
}

/** The dispatch class of a direct (non-virtual, non-pointer) call to `target`. */
string directDispatch(Function target) {
  if not target instanceof GraphExport::SourceFunction
  then result = "external_undefined"
  else
    if target.isConstructedFrom(_)
    then result = "template_instantiation"
    else result = "direct"
}

/** The callee and dispatch of `call`, with the number of candidate callees. */
predicate callee(Call call, Function target, string dispatch, int candidateCount) {
  exists(virtualCandidate(call)) and
  target = virtualCandidate(call) and
  dispatch = "virtual_resolved" and
  candidateCount = count(Function f | f = virtualCandidate(call))
  or
  not call.(FunctionCall).isVirtual() and
  target = call.getTarget() and
  dispatch = directDispatch(target) and
  candidateCount = 1
  or
  target = pointerTarget(call) and
  dispatch = "function_pointer_resolved" and
  candidateCount = count(Function f | f = pointerTarget(call))
}

string inLoop(Call call) {
  if exists(Loop loop | loop.getStmt().getAChild*() = call.getEnclosingStmt())
  then result = "true"
  else result = "false"
}

query predicate call_sites(
  string caller_name, string caller_path, int caller_start_line, int caller_start_column,
  string call_path, int call_start_line, int call_start_column, int call_end_line,
  int call_end_column, string callee_name, string callee_declared_in, string callee_path,
  int callee_start_line, int callee_start_column, string dispatch, int candidate_count,
  int argument_count, string in_loop
) {
  exists(Call call, GraphExport::SourceFunction caller |
    caller = call.getEnclosingFunction() and GraphExport::inSource(call)
  |
    caller_name = caller.getQualifiedName() and
    GraphExport::locationColumns(caller.getLocation(), caller_path, caller_start_line,
      caller_start_column, _, _) and
    GraphExport::locationColumns(call.getLocation(), call_path, call_start_line,
      call_start_column, call_end_line, call_end_column) and
    argument_count = call.getNumberOfArguments() and
    in_loop = inLoop(call) and
    (
      exists(Function target | callee(call, target, dispatch, candidate_count) |
        callee_name = target.getQualifiedName() and
        callee_declared_in = GraphExport::declaredIn(target) and
        GraphExport::locationColumns(target.getLocation(), callee_path, callee_start_line,
          callee_start_column, _, _)
      )
      or
      // A virtual call with no defined candidate, or a pointer call with no resolved target, is
      // published as unresolved instead of being dropped.
      not callee(call, _, _, _) and
      dispatch = "unresolved_indirect" and
      candidate_count = 0 and
      (
        callee_name = "<indirect:" + call.(ExprCall).getExpr().toString() + ">"
        or
        callee_name = call.(FunctionCall).getTarget().getQualifiedName()
      ) and
      callee_declared_in = "" and
      callee_path = "" and
      callee_start_line = 0 and
      callee_start_column = 0
    )
  )
}
