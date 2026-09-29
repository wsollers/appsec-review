/**
 * @name Remote input reaches a vulnerable dependency symbol (JavaScript/TypeScript)
 * @kind table
 * @id appsec/javascript/reachability-taint
 */

import javascript
import Common

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { exists(VulnerableCall c | sink = c.getAnArgument()) }
}

module Flow = TaintTracking::Global<Config>;

from DataFlow::Node source, DataFlow::Node sink, VulnerableCall c
where Flow::flow(source, sink) and sink = c.getAnArgument()
select relPath(source.getAstNode().getLocation()) as source_file,
  source.getAstNode().getLocation().getStartLine() as source_line,
  relPath(c.getAstNode().getLocation()) as sink_file, c.getAstNode().getLocation().getStartLine() as sink_line,
  c.getPackage() as package, c.getSymbol() as symbol
