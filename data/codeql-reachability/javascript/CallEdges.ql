/**
 * @name Call graph edges (JavaScript/TypeScript)
 * @kind table
 * @id appsec/javascript/reachability-call-edges
 */

import javascript
import Common

from DataFlow::InvokeNode call, StmtContainer caller, Function callee
where
  caller = call.getContainer() and
  callee = call.getACallee() and
  exists(call.getFile().getRelativePath())
select containerName(caller) as caller_name, relPath(caller.getLocation()) as caller_file,
  caller.getLocation().getStartLine() as caller_line, relPath(call.getAstNode().getLocation()) as call_file,
  call.getAstNode().getLocation().getStartLine() as call_line, containerName(callee) as callee_name,
  relPath(callee.getLocation()) as callee_file, callee.getLocation().getStartLine() as callee_line,
  "yes" as callee_defined
