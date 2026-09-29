/**
 * @name Entry points (Python)
 * @kind table
 * @id appsec/python/reachability-entry-points
 */

import python
import Common

from EntryPoint e
select scopeName(e) as name, relPath(e.getLocation()) as file, e.getLocation().getStartLine() as line,
  e.getReason() as reason
