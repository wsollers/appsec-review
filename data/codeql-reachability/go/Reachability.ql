/**
 * @name Entry point reaches a vulnerable dependency symbol (Go)
 * @description `edge*` from an entry point to the function containing a call of a symbol listed in
 *              the generated data extension. A locator table, never a finding.
 * @kind table
 * @id appsec/go/reachability-paths
 */

import go
import Common

from EntryPoint entry, VulnerableCall call, FuncDef caller
where
  caller = call.getRoot() and
  edge*(entry, caller)
select funcName(entry) as entry_name, relPath(entry.getLocation()) as entry_file,
  entry.getLocation().getStartLine() as entry_line, funcName(caller) as caller_name,
  relPath(call.getLocation()) as call_file, call.getLocation().getStartLine() as call_line,
  call.getPackage() as package, call.getSymbol() as symbol
