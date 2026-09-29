/**
 * @name Call graph edges (Go)
 * @description Static call edges with source locations; contract columns shared with
 *              queries/appsec-graph-cpp/CallEdges.ql. A locator table, never a finding.
 * @kind table
 * @id appsec/go/reachability-call-edges
 */

import go
import Common

from DataFlow::CallNode call, FuncDef caller, Function callee, string calleeFile, int calleeLine, string defined
where
  caller = call.getRoot() and
  callee = call.getTarget() and
  exists(call.getFile().getRelativePath()) and
  (
    exists(callee.getFuncDecl()) and
    calleeFile = relPath(callee.getFuncDecl().getLocation()) and
    calleeLine = callee.getFuncDecl().getLocation().getStartLine() and
    defined = "yes"
    or
    not exists(callee.getFuncDecl()) and calleeFile = "" and calleeLine = 0 and defined = "no"
  )
select funcName(caller) as caller_name, relPath(caller.getLocation()) as caller_file,
  caller.getLocation().getStartLine() as caller_line, relPath(call.getLocation()) as call_file,
  call.getLocation().getStartLine() as call_line, callee.getQualifiedName() as callee_name,
  calleeFile as callee_file, calleeLine as callee_line, defined as callee_defined
