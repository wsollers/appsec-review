/**
 * @name Code-graph export: call sites
 * @description Every call and `new` in a function defined inside the source root, with its
 *              resolved callee or an explicit external/unresolved row. One row per
 *              (call, candidate callee).
 * @kind table
 * @id appsec-review/graph-export/javascript/call-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `call_sites`.
//
// Dispatch: a method call (`o.m()`) CodeQL's call graph resolves to source-root methods is
// "virtual_resolved" (one row per candidate); a call through a function or class name is
// "direct"; any other resolved callee value (a parameter, property or variable holding a
// function) is "function_pointer_resolved". A call into an imported module, a global object or a
// global function with no source-root target is "external_undefined" with its modules in
// `callee_declared_in`; every other call (computed member, unknown receiver) is
// "unresolved_indirect". "template_instantiation" is never emitted.
import javascript
import GraphExport

/** The callee value of `call` is a function or class literal (a direct reference). */
predicate directReference(DataFlow::InvokeNode call) {
  call.getCalleeNode().getALocalSource() instanceof DataFlow::FunctionNode
  or
  call.getCalleeNode().getALocalSource() instanceof DataFlow::ClassNode
}

/** The callee and dispatch of `call`, with the number of candidate callees. */
predicate callee(
  DataFlow::InvokeNode call, GraphExport::SourceFunction target, string dispatch,
  int candidateCount
) {
  target = GraphExport::callTarget(call) and
  candidateCount = count(GraphExport::SourceFunction f | f = GraphExport::callTarget(call)) and
  (
    call instanceof DataFlow::MethodCallNode and
    not directReference(call) and
    dispatch = "virtual_resolved"
    or
    directReference(call) and dispatch = "direct"
    or
    not call instanceof DataFlow::MethodCallNode and
    not directReference(call) and
    dispatch = "function_pointer_resolved"
  )
}

string inLoop(DataFlow::InvokeNode call) {
  if
    exists(LoopStmt loop |
      loop.getContainer() = call.getContainer() and
      loop.getBody().getAChild*() = call.asExpr().getEnclosingStmt()
    )
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
  exists(DataFlow::InvokeNode call, GraphExport::SourceFunction caller |
    caller = call.getContainer() and
    GraphExport::inSourceNode(call) and
    GraphExport::exported(caller)
  |
    caller_name = caller.getQualifiedName() and
    GraphExport::locationColumns(caller.getNameLocation(), caller_path, caller_start_line,
      caller_start_column, _, _) and
    GraphExport::locationColumns(call.getLocation(), call_path, call_start_line,
      call_start_column, call_end_line, call_end_column) and
    argument_count = call.getNumArgument() and
    in_loop = inLoop(call) and
    (
      exists(GraphExport::SourceFunction target | callee(call, target, dispatch, candidate_count) |
        callee_name = target.getQualifiedName() and
        callee_declared_in = "" and
        GraphExport::locationColumns(target.getNameLocation(), callee_path, callee_start_line,
          callee_start_column, _, _)
      )
      or
      not exists(GraphExport::callTarget(call)) and
      GraphExport::importedFrom(call, _) and
      dispatch = "external_undefined" and
      candidate_count = 1 and
      callee_name = GraphExport::calleeName(call) and
      callee_declared_in = GraphExport::declaredIn(call) and
      callee_path = "" and
      callee_start_line = 0 and
      callee_start_column = 0
      or
      // A call with no source-root target and no known module is published as unresolved
      // instead of being dropped.
      not exists(GraphExport::callTarget(call)) and
      not GraphExport::importedFrom(call, _) and
      dispatch = "unresolved_indirect" and
      candidate_count = 0 and
      callee_name = "<indirect:" + call.getCalleeNode().toString() + ">" and
      callee_declared_in = "" and
      callee_path = "" and
      callee_start_line = 0 and
      callee_start_column = 0
    )
  )
}
