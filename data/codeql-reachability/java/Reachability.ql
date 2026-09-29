/**
 * @name Entry point reaches a vulnerable dependency symbol (Java)
 * @description `polyCalls*` from an entry point to the callable containing a listed call.
 * @kind table
 * @id appsec/java/reachability-paths
 */

import java
import Common

from EntryPoint entry, VulnerableCall call, Callable caller
where
  caller = call.getCaller() and
  edge*(entry, caller)
select callableName(entry) as entry_name, relPath(entry.getLocation()) as entry_file,
  entry.getLocation().getStartLine() as entry_line, callableName(caller) as caller_name,
  relPath(call.getLocation()) as call_file, call.getLocation().getStartLine() as call_line,
  call.getPackage() as package, call.getSymbol() as symbol
