/**
 * @name Code-graph export: call sites
 * @description Every call in a function defined inside the source root, with its resolved
 *              callee or an explicit unresolved row. One row per (call, candidate callee).
 * @kind table
 * @id appsec-review/graph-export/go/call-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `call_sites`.
//
// Dispatch: an interface method call publishes one `virtual_resolved` row per source-root
// implementation `getACallee()` resolves; a static call to a source-root function is `direct`;
// a call to a function or method without a source-root body (standard library, dependency,
// builtin) is `external_undefined`; a call through a function value whose target CodeQL resolves
// by local flow is `function_pointer_resolved`; anything else (a func-typed parameter, an
// interface call with no source-root implementation) is published as `unresolved_indirect`.
// Go has no templates: `template_instantiation` is never emitted.
import go
import GraphExport

/** `target` is a source-root implementation an interface method call may dispatch to. */
predicate interfaceCandidate(DataFlow::CallNode call, GraphExport::SourceFunction target) {
  call.getTarget().(Method).isInterfaceMethod() and target = call.getACallee()
}

/** The callee function definition, dispatch and candidate count of `call`. */
predicate sourceCallee(
  DataFlow::CallNode call, GraphExport::SourceFunction target, string dispatch, int candidateCount
) {
  interfaceCandidate(call, target) and
  dispatch = "virtual_resolved" and
  candidateCount = count(GraphExport::SourceFunction f | interfaceCandidate(call, f))
  or
  not call.getTarget().(Method).isInterfaceMethod() and
  target = call.getTarget().getFuncDecl() and
  dispatch = "direct" and
  candidateCount = 1
  or
  not exists(call.getTarget()) and
  target = call.getACallee() and
  dispatch = "function_pointer_resolved" and
  candidateCount = count(GraphExport::SourceFunction f | f = call.getACallee())
}

/** `call` statically targets a function or method with no source-root body. */
predicate externalCallee(DataFlow::CallNode call, Function target) {
  target = call.getTarget() and
  not target.(Method).isInterfaceMethod() and
  not target.getFuncDecl() instanceof GraphExport::SourceFunction
}

string inLoop(DataFlow::CallNode call) {
  if exists(LoopStmt loop | loop.getBody().getAChild*() = call.getCall())
  then result = "true"
  else result = "false"
}

/** The display name of an unresolved call. */
string indirectName(DataFlow::CallNode call) {
  result = GraphExport::entityName(call.getTarget())
  or
  not exists(call.getTarget()) and
  result = "<indirect:" + call.getCall().getCalleeExpr().toString() + ">"
}

query predicate call_sites(
  string caller_name, string caller_path, int caller_start_line, int caller_start_column,
  string call_path, int call_start_line, int call_start_column, int call_end_line,
  int call_end_column, string callee_name, string callee_declared_in, string callee_path,
  int callee_start_line, int callee_start_column, string dispatch, int candidate_count,
  int argument_count, string in_loop
) {
  exists(DataFlow::CallNode call, GraphExport::SourceFunction caller |
    caller = GraphExport::callFunction(call) and
    GraphExport::inSource(call.getCall()) and
    GraphExport::exported(caller)
  |
    caller_name = GraphExport::functionName(caller) and
    GraphExport::locationColumns(GraphExport::functionLocation(caller), caller_path,
      caller_start_line, caller_start_column, _, _) and
    GraphExport::locationColumns(call.getCall().getLocation(), call_path, call_start_line,
      call_start_column, call_end_line, call_end_column) and
    argument_count = call.getNumArgument() and
    in_loop = inLoop(call) and
    (
      exists(GraphExport::SourceFunction target |
        sourceCallee(call, target, dispatch, candidate_count)
      |
        callee_name = GraphExport::functionName(target) and
        callee_declared_in = "" and
        GraphExport::locationColumns(GraphExport::functionLocation(target), callee_path,
          callee_start_line, callee_start_column, _, _)
      )
      or
      exists(Function target | externalCallee(call, target) |
        dispatch = "external_undefined" and
        candidate_count = 1 and
        callee_name = GraphExport::entityName(target) and
        callee_declared_in = GraphExport::packagePath(target) and
        callee_path = "" and
        callee_start_line = 0 and
        callee_start_column = 0
      )
      or
      // An interface call with no source-root implementation, or a call through a function
      // value with no resolved target, is published as unresolved instead of being dropped.
      not sourceCallee(call, _, _, _) and
      not externalCallee(call, _) and
      dispatch = "unresolved_indirect" and
      candidate_count = 0 and
      callee_name = indirectName(call) and
      callee_declared_in = "" and
      callee_path = "" and
      callee_start_line = 0 and
      callee_start_column = 0
    )
  )
}
