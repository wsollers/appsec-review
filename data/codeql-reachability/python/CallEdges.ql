/**
 * @name Call graph edges (Python)
 * @kind table
 * @id appsec/python/reachability-call-edges
 */

import python
import Common

from DataFlow::CallCfgNode call, Scope caller, Function callee
where
  caller = call.getScope() and
  call.getFunction().getALocalSource().asExpr() = callee.getDefinition() and
  exists(call.getLocation().getFile().getRelativePath())
select scopeName(caller) as caller_name, relPath(caller.getLocation()) as caller_file,
  caller.getLocation().getStartLine() as caller_line, relPath(call.getLocation()) as call_file,
  call.getLocation().getStartLine() as call_line, scopeName(callee) as callee_name,
  relPath(callee.getLocation()) as callee_file, callee.getLocation().getStartLine() as callee_line,
  "yes" as callee_defined
