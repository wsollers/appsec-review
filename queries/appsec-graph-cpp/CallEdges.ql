/**
 * @name Call graph edges
 * @description Static call edges (enclosing function -> resolved call target) with source
 *              locations, for reachability evidence (brief E). A locator table, never a finding.
 * @kind table
 * @id appsec/cpp/call-edges
 */

import cpp
import Common

from Call call, Function caller, Function callee
where
  caller = call.getEnclosingFunction() and
  callee = call.getTarget() and
  exists(call.getFile().getRelativePath())
select caller.getQualifiedName() as caller_name, relPath(caller.getLocation()) as caller_file,
  caller.getLocation().getStartLine() as caller_line, relPath(call.getLocation()) as call_file,
  call.getLocation().getStartLine() as call_line, callee.getQualifiedName() as callee_name,
  relPath(callee.getLocation()) as callee_file, callee.getLocation().getStartLine() as callee_line,
  (if callee.hasDefinition() then "yes" else "no") as callee_defined
