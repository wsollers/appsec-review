/**
 * @name Entry points (JavaScript/TypeScript)
 * @kind table
 * @id appsec/javascript/reachability-entry-points
 */

import javascript
import Common

from EntryPoint e
select containerName(e) as name, relPath(e.getLocation()) as file, e.getLocation().getStartLine() as line,
  e.getReason() as reason
