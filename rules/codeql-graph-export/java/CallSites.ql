/**
 * @name Code-graph export: call sites
 * @description Every call in a callable defined inside the source root, with its resolved
 *              callee or an explicit unresolved row. One row per (call, candidate callee).
 * @kind table
 * @id appsec-review/graph-export/java/call-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `call_sites`.
import java
import GraphExport

/** A reflective call (`Method.invoke`, `Constructor.newInstance`) whose target is a runtime value. */
predicate reflectiveCall(MethodCall call) {
  call.getMethod().hasQualifiedName("java.lang.reflect", "Method", "invoke")
  or
  call.getMethod().hasQualifiedName("java.lang.reflect", "Constructor", "newInstance")
}

/** The callee and dispatch of `call`, with the number of candidate callees. */
predicate callee(Call call, Callable target, string dispatch, int candidateCount) {
  not reflectiveCall(call) and
  (
    GraphExport::isVirtualDispatch(call) and
    target = GraphExport::virtualCandidate(call) and
    dispatch = "virtual_resolved" and
    candidateCount = count(GraphExport::virtualCandidate(call))
    or
    not GraphExport::isVirtualDispatch(call) and
    (
      // A single viable source implementation of a virtual call is a direct call to it.
      target = GraphExport::virtualCandidate(call) and dispatch = "direct"
      or
      not exists(GraphExport::virtualCandidate(call)) and
      target = call.getCallee().getSourceDeclaration() and
      (
        if target instanceof GraphExport::SourceFunction
        then dispatch = "direct"
        else dispatch = "external_undefined"
      )
    ) and
    candidateCount = 1
  )
}

string inLoop(Call call) {
  if exists(LoopStmt loop | loop.getBody() = call.getEnclosingStmt().getEnclosingStmt*())
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
    caller = call.getEnclosingCallable() and
    GraphExport::inSource(call) and
    GraphExport::exported(caller)
  |
    caller_name = GraphExport::functionName(caller) and
    GraphExport::locationColumns(caller.getLocation(), caller_path, caller_start_line,
      caller_start_column, _, _) and
    GraphExport::locationColumns(call.getLocation(), call_path, call_start_line,
      call_start_column, call_end_line, call_end_column) and
    argument_count = call.getNumArgument() and
    in_loop = inLoop(call) and
    (
      exists(Callable target | callee(call, target, dispatch, candidate_count) |
        callee_name = GraphExport::calleeName(target) and
        callee_declared_in = GraphExport::declaredIn(target) and
        (
          target instanceof GraphExport::SourceFunction and
          GraphExport::locationColumns(target.getLocation(), callee_path, callee_start_line,
            callee_start_column, _, _)
          or
          // A library callable is named, not located: no source symbol is created for it.
          not target instanceof GraphExport::SourceFunction and
          callee_path = "" and
          callee_start_line = 0 and
          callee_start_column = 0
        )
      )
      or
      // A reflective call names its target only at run time: it is published as unresolved.
      reflectiveCall(call) and
      dispatch = "unresolved_indirect" and
      candidate_count = 0 and
      callee_name = "<reflective:" + call.toString() + ">" and
      callee_declared_in = "" and
      callee_path = "" and
      callee_start_line = 0 and
      callee_start_column = 0
    )
  )
}
