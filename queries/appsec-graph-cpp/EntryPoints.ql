/**
 * @name Entry-point candidates
 * @description Defined functions that are `main` or have no call site in the database (exported,
 *              callback or dead). Reachability roots for brief E; a locator table, never a finding.
 * @kind table
 * @id appsec/cpp/entry-points
 */

import cpp
import Common

from Function f, string reason
where
  f.hasDefinition() and
  exists(f.getDefinitionLocation().getFile().getRelativePath()) and
  (
    f.hasGlobalName("main") and reason = "main"
    or
    not f.hasGlobalName("main") and
    not exists(Call c | c.getTarget() = f) and
    not exists(FunctionAccess a | a.getTarget() = f) and
    reason = "no-internal-caller"
    or
    not f.hasGlobalName("main") and
    not exists(Call c | c.getTarget() = f) and
    exists(FunctionAccess a | a.getTarget() = f) and
    reason = "address-taken"
  )
select f.getQualifiedName() as name, relPath(f.getDefinitionLocation()) as file,
  f.getDefinitionLocation().getStartLine() as line, reason
