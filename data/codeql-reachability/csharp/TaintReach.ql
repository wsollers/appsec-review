/**
 * @name Remote input reaches a vulnerable dependency symbol (C#)
 * @kind table
 * @id appsec/csharp/reachability-taint
 */

import csharp
import Common

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { exists(VulnerableCall c | sink.asExpr() = c.getAnArgument()) }
}

module Flow = TaintTracking::Global<Config>;

from DataFlow::Node source, DataFlow::Node sink, VulnerableCall c
where Flow::flow(source, sink) and sink.asExpr() = c.getAnArgument()
select relPath(source.getLocation()) as source_file, source.getLocation().getStartLine() as source_line,
  relPath(c.getLocation()) as sink_file, c.getLocation().getStartLine() as sink_line,
  c.getPackage() as package, c.getSymbol() as symbol
