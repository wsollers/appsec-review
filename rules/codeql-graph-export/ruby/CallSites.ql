/**
 * @name Code-graph export: call sites
 * @description Every method call in a method defined inside the source root, with its resolved
 *              callee or an explicit unresolved row. One row per (call, candidate callee).
 * @kind table
 * @id appsec-review/graph-export/ruby/call-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `call_sites`.
//
// Dispatch: a call CodeQL's Ruby call graph resolves to exactly one source-root method is
// "direct"; to several (a receiver whose class is one of several overriding classes) one
// "virtual_resolved" row per candidate. A reflective call (`send`, `public_send`, `__send__`,
// `method`, `instance_variable_get`, `const_get`) with no resolved source-root target is
// "unresolved_indirect"; any other unresolved call is "external_undefined" (a library or core
// method, or a method CodeQL could not resolve). Operator expressions are omitted.
import codeql.ruby.AST
import GraphExport

/** Method names that call a method or read a member whose name is a runtime value. */
predicate reflective(string name) {
  name =
    [
      "send", "public_send", "__send__", "method", "public_method", "instance_variable_get",
      "const_get", "define_method"
    ]
}

/** The callee and dispatch of `call`, with the number of source-root candidate callees. */
predicate callee(
  MethodCall call, GraphExport::SourceFunction target, string dispatch, int candidateCount
) {
  target = call.getATarget() and
  candidateCount = count(GraphExport::SourceFunction t | t = call.getATarget()) and
  (if candidateCount > 1 then dispatch = "virtual_resolved" else dispatch = "direct")
}

/** Iterator methods whose block runs repeatedly. */
predicate iterator(string name) {
  name =
    [
      "each", "each_with_index", "each_with_object", "each_pair", "each_key", "each_value",
      "each_line", "map", "flat_map", "collect", "select", "filter", "reject", "times", "upto",
      "downto", "step", "loop", "find", "detect", "any?", "all?", "none?", "inject", "reduce"
    ]
}

string inLoop(MethodCall call) {
  if
    exists(Loop loop | call.getParent+() = loop.getBody())
    or
    exists(MethodCall outer | iterator(outer.getMethodName()) and call.getParent+() = outer.getBlock())
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
  exists(MethodCall call, GraphExport::SourceFunction caller |
    // Operator expressions (`a == b`, `a + b`) are method calls in Ruby's AST; like built-in
    // operators in the C/C++ pack they are not call sites here.
    not call instanceof Operation and
    caller = call.getEnclosingMethod() and
    GraphExport::inSource(call.getLocation()) and
    GraphExport::exported(caller)
  |
    caller_name = caller.getQualifiedName() and
    GraphExport::locationColumns(caller.getNameLocation(), caller_path, caller_start_line,
      caller_start_column, _, _) and
    GraphExport::locationColumns(call.getLocation(), call_path, call_start_line,
      call_start_column, call_end_line, call_end_column) and
    argument_count = call.getNumberOfArguments() and
    in_loop = inLoop(call) and
    (
      exists(GraphExport::SourceFunction target | callee(call, target, dispatch, candidate_count) |
        callee_name = target.getQualifiedName() and
        callee_declared_in = target.getDeclaringModule() and
        GraphExport::locationColumns(target.getNameLocation(), callee_path, callee_start_line,
          callee_start_column, _, _)
      )
      or
      // A call with no source-root target is published, never dropped.
      not callee(call, _, _, _) and
      candidate_count = 0 and
      callee_path = "" and
      callee_start_line = 0 and
      callee_start_column = 0 and
      (
        reflective(call.getMethodName()) and
        dispatch = "unresolved_indirect" and
        callee_name = "<dynamic:" + call.getMethodName() + ">" and
        callee_declared_in = ""
        or
        not reflective(call.getMethodName()) and
        dispatch = "external_undefined" and
        callee_name = call.getMethodName() and
        callee_declared_in = GraphExport::receiverConstant(call)
      )
    )
  )
}
