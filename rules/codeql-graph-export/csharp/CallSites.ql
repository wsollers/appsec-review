/**
 * @name Code-graph export: call sites
 * @description Every call in a callable defined inside the source root, with its resolved
 *              callee or an explicit unresolved row. One row per (call, candidate callee).
 * @kind table
 * @id appsec-review/graph-export/csharp/call-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `call_sites`.
// Property, indexer and event accessor calls and compiler-generated calls are not call sites.
import csharp
import GraphExport

/** The dispatch class of a direct (statically bound) call to `target`. */
string directDispatch(Callable target) {
  if not exists(GraphExport::sourceFunction(target))
  then result = "external_undefined"
  else
    if target.getUnboundDeclaration() != target
    then result = "template_instantiation"
    else result = "direct"
}

/** The callee and dispatch of `call`, with the number of candidate callees. */
predicate callee(GraphExport::SiteCall call, Callable target, string dispatch, int candidateCount) {
  // A virtual or interface call with source-root overrides: one row per candidate.
  target = GraphExport::virtualCandidate(call) and
  dispatch = "virtual_resolved" and
  candidateCount = count(GraphExport::virtualCandidate(call))
  or
  // A virtual call with no source-root candidate (a framework interface such as
  // IDbConnection) is published against its static target.
  GraphExport::isVirtual(call) and
  not exists(GraphExport::virtualCandidate(call)) and
  target = call.getTarget() and
  dispatch = directDispatch(target) and
  candidateCount = 1
  or
  not GraphExport::isVirtual(call) and
  not call instanceof DelegateLikeCall and
  not call instanceof DynamicExpr and
  target = call.getTarget() and
  dispatch = directDispatch(target) and
  candidateCount = 1
  or
  target = GraphExport::delegateCandidate(call) and
  dispatch = "function_pointer_resolved" and
  candidateCount = count(GraphExport::delegateCandidate(call))
}

string inLoop(Call call) {
  if exists(LoopStmt loop | loop.getBody().getAChild*() = call.getEnclosingStmt())
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
  exists(GraphExport::SiteCall call, GraphExport::SourceFunction caller |
    caller = GraphExport::sourceFunction(call.getEnclosingCallable()) and
    GraphExport::exported(caller)
  |
    caller_name = GraphExport::qualifiedName(caller) and
    GraphExport::locationColumns(caller.getLocation(), caller_path, caller_start_line,
      caller_start_column, _, _) and
    GraphExport::locationColumns(call.getLocation(), call_path, call_start_line,
      call_start_column, call_end_line, call_end_column) and
    argument_count = call.getNumberOfArguments() and
    in_loop = inLoop(call) and
    (
      exists(Callable target | callee(call, target, dispatch, candidate_count) |
        callee_name = GraphExport::qualifiedName(target) and
        callee_declared_in = GraphExport::declaredIn(target) and
        (
          GraphExport::locationColumns(GraphExport::sourceFunction(target).getLocation(),
            callee_path, callee_start_line, callee_start_column, _, _)
          or
          // A referenced-assembly or compiler-generated callee (an implicit default
          // constructor) has no source declaration to locate.
          not exists(GraphExport::sourceFunction(target)) and
          callee_path = "" and
          callee_start_line = 0 and
          callee_start_column = 0
        )
      )
      or
      // A dynamic (late-bound) call, or a delegate call with no resolved target, is published
      // as unresolved instead of being dropped.
      not callee(call, _, _, _) and
      dispatch = "unresolved_indirect" and
      candidate_count = 0 and
      callee_name = "<indirect:" + call.toString() + ">" and
      callee_declared_in = "" and
      callee_path = "" and
      callee_start_line = 0 and
      callee_start_column = 0
    )
  )
}