/**
 * @name Call graph edges (Java)
 * @description Call edges with source locations (contract columns of queries/appsec-graph-cpp).
 * @kind table
 * @id appsec/java/reachability-call-edges
 */

import java
import Common

from Call call, Callable caller, Callable callee
where
  caller = call.getCaller() and
  (
    callee = call.getCallee().getSourceDeclaration()
    or
    // virtual dispatch: every override of the static target is an edge too
    callee.(Method).overrides+(call.getCallee().getSourceDeclaration())
  ) and
  exists(call.getFile().getRelativePath())
select callableName(caller) as caller_name, relPath(caller.getLocation()) as caller_file,
  caller.getLocation().getStartLine() as caller_line, relPath(call.getLocation()) as call_file,
  call.getLocation().getStartLine() as call_line, callableName(callee) as callee_name,
  relPath(callee.getLocation()) as callee_file, callee.getLocation().getStartLine() as callee_line,
  (if callee.fromSource() then "yes" else "no") as callee_defined
