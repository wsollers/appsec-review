/**
 * @name Entry points (Go)
 * @description Reachability roots for brief E. A locator table, never a finding.
 * @kind table
 * @id appsec/go/reachability-entry-points
 */

import go
import Common

from EntryPoint e
select funcName(e) as name, relPath(e.getLocation()) as file, e.getLocation().getStartLine() as line,
  e.getReason() as reason
