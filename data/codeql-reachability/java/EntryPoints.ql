/**
 * @name Entry points (Java)
 * @kind table
 * @id appsec/java/reachability-entry-points
 */

import java
import Common

from EntryPoint e
select callableName(e) as name, relPath(e.getLocation()) as file, e.getLocation().getStartLine() as line,
  e.getReason() as reason
