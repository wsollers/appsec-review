/**
 * @name Call graph edges (C#)
 * @kind table
 * @id appsec/csharp/reachability-call-edges
 */

import csharp
import Common

from Call call, Callable caller, Callable callee
where
  caller = call.getEnclosingCallable() and
  callee = call.getARuntimeTarget().getUnboundDeclaration() and
  exists(call.getFile().getRelativePath())
select callableName(caller) as caller_name, relPath(caller.getLocation()) as caller_file,
  caller.getLocation().getStartLine() as caller_line, relPath(call.getLocation()) as call_file,
  call.getLocation().getStartLine() as call_line, callableName(callee) as callee_name,
  relPath(callee.getLocation()) as callee_file, callee.getLocation().getStartLine() as callee_line,
  (if callee.fromSource() then "yes" else "no") as callee_defined
