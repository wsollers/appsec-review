/**
 * @name Untrusted flow sources
 * @description Remote and local flow sources from the standard C/C++ taint library
 *              (semmle.code.cpp.security.FlowSources), the source side of brief E's taint and
 *              reachability questions. A locator table, never a finding.
 * @kind table
 * @id appsec/cpp/flow-sources
 */

import cpp
import semmle.code.cpp.security.FlowSources
import Common

from FlowSource source
where exists(source.getLocation().getFile().getRelativePath())
select source.getSourceType() as source_type, relPath(source.getLocation()) as file,
  source.getLocation().getStartLine() as line,
  (if exists(source.getFunction()) then source.getFunction().getQualifiedName() else "") as function
