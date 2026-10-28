/**
 * @name Code-graph export: call sites
 * @description Every call in a function defined inside the source root, with its resolved
 *              callee or an explicit unresolved row. One row per (call, candidate callee).
 * @kind table
 * @id appsec-review/graph-export/python/call-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `call_sites`.
//
// Callees come from python-all call resolution (DataFlowDispatch::resolveCall), which resolves
// plain function calls, class instantiation (to `__init__`) and method calls through the
// receiver's class, including `self.m()` overrides in subclasses. Dispatch:
// - several source-root candidates: "virtual_resolved" (one row per candidate);
// - one candidate reached through a plain call whose callee `Name` is not the target's name (a
//   function held in a variable): "function_pointer_resolved";
// - one candidate otherwise: "direct";
// - no source-root candidate and a `Name`/`Attribute` callee: "external_undefined" (a library,
//   builtin or unknown-receiver method call; the callee name is the syntactic name);
// - no candidate and any other callee expression (`f()()`, `getattr(o, n)(...)`):
//   "unresolved_indirect" with candidate count 0.
// "template_instantiation" never occurs in Python.
import python
import semmle.python.dataflow.new.DataFlow
import GraphExport

/** The source-root callees of `call`. */
GraphExport::SourceFunction sourceTarget(DataFlow::CallCfgNode call) {
  GraphExport::resolvedTarget(call, result)
}

predicate callee(DataFlow::CallCfgNode call, Function target, string dispatch, int candidateCount) {
  target = sourceTarget(call) and
  candidateCount = count(sourceTarget(call)) and
  (
    candidateCount > 1 and dispatch = "virtual_resolved"
    or
    candidateCount = 1 and
    if
      GraphExport::plainFunctionTarget(call, target) and
      not call.getFunction().asExpr().(Name).getId() = target.getName()
    then dispatch = "function_pointer_resolved"
    else dispatch = "direct"
  )
}

string inLoop(DataFlow::CallCfgNode call) {
  if
    exists(AstNode loop |
      (loop instanceof For or loop instanceof While) and
      loop = call.asExpr().getParentNode+() and
      loop.getScope() = call.getScope()
    )
  then result = "true"
  else result = "false"
}

int positionalArguments(DataFlow::CallCfgNode call) {
  result = count(int i | exists(call.asExpr().(Call).getPositionalArg(i)))
}

query predicate call_sites(
  string caller_name, string caller_path, int caller_start_line, int caller_start_column,
  string call_path, int call_start_line, int call_start_column, int call_end_line,
  int call_end_column, string callee_name, string callee_declared_in, string callee_path,
  int callee_start_line, int callee_start_column, string dispatch, int candidate_count,
  int argument_count, string in_loop
) {
  exists(DataFlow::CallCfgNode call, GraphExport::SourceFunction caller |
    caller = call.getScope() and
    GraphExport::nodeInSource(call) and
    GraphExport::exported(caller)
  |
    caller_name = caller.getQualifiedName() and
    GraphExport::locationColumns(GraphExport::functionLocation(caller), caller_path,
      caller_start_line, caller_start_column, _, _) and
    GraphExport::locationColumns(call.getLocation(), call_path, call_start_line,
      call_start_column, call_end_line, call_end_column) and
    argument_count = positionalArguments(call) and
    in_loop = inLoop(call) and
    (
      exists(Function target | callee(call, target, dispatch, candidate_count) |
        callee_name = target.getQualifiedName() and
        callee_declared_in = "" and
        GraphExport::locationColumns(GraphExport::functionLocation(target), callee_path,
          callee_start_line, callee_start_column, _, _)
      )
      or
      not exists(sourceTarget(call)) and
      (
        call.getFunction().asExpr() instanceof Name or
        call.getFunction().asExpr() instanceof Attribute
      ) and
      dispatch = "external_undefined" and
      candidate_count = 1 and
      callee_name = GraphExport::callName(call) and
      callee_declared_in = GraphExport::declaredIn(call) and
      callee_path = "" and
      callee_start_line = 0 and
      callee_start_column = 0
      or
      // A call through an arbitrary expression with no resolved target is published as
      // unresolved instead of being dropped.
      not exists(sourceTarget(call)) and
      not call.getFunction().asExpr() instanceof Name and
      not call.getFunction().asExpr() instanceof Attribute and
      dispatch = "unresolved_indirect" and
      candidate_count = 0 and
      callee_name = "<indirect:" + call.getFunction().asExpr().toString() + ">" and
      callee_declared_in = "" and
      callee_path = "" and
      callee_start_line = 0 and
      callee_start_column = 0
    )
  )
}
