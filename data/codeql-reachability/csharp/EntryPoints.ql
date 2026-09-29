/**
 * @name Entry points (C#)
 * @kind table
 * @id appsec/csharp/reachability-entry-points
 */

import csharp
import Common

from EntryPoint e
select callableName(e) as name, relPath(e.getLocation()) as file, e.getLocation().getStartLine() as line,
  e.getReason() as reason
