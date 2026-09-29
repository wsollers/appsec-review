/**
 * @name Entry point reaches a vulnerable dependency symbol (Python)
 * @kind table
 * @id appsec/python/reachability-paths
 */

import python
import Common

predicate reaches(Scope entry, Scope target) {
  entry = target
  or
  exists(Function mid | edge(entry, mid) and reaches(mid, target))
}

from EntryPoint entry, VulnerableCall call, Scope caller
where
  caller = call.getScope() and
  reaches(entry, caller)
select scopeName(entry) as entry_name, relPath(entry.getLocation()) as entry_file,
  entry.getLocation().getStartLine() as entry_line, scopeName(caller) as caller_name,
  relPath(call.getLocation()) as call_file, call.getLocation().getStartLine() as call_line,
  call.getPackage() as package, call.getSymbol() as symbol
