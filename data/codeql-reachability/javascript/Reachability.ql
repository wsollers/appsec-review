/**
 * @name Entry point reaches a vulnerable dependency symbol (JavaScript/TypeScript)
 * @kind table
 * @id appsec/javascript/reachability-paths
 */

import javascript
import Common

predicate reaches(StmtContainer entry, StmtContainer target) {
  entry = target
  or
  exists(Function mid | edge(entry, mid) and reaches(mid, target))
}

from EntryPoint entry, VulnerableCall call, StmtContainer caller
where
  caller = call.getContainer() and
  reaches(entry, caller)
select containerName(entry) as entry_name, relPath(entry.getLocation()) as entry_file,
  entry.getLocation().getStartLine() as entry_line, containerName(caller) as caller_name,
  relPath(call.getAstNode().getLocation()) as call_file, call.getAstNode().getLocation().getStartLine() as call_line,
  call.getPackage() as package, call.getSymbol() as symbol
