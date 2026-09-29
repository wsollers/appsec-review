/**
 * @name Remote input reaches a vulnerable dependency symbol (Python)
 * @kind table
 * @id appsec/python/reachability-taint
 */

import python
import semmle.python.dataflow.new.TaintTracking
import Common

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { exists(VulnerableCall c | sink = c.getArg(_) or sink = c.getArgByName(_)) }
}

module Flow = TaintTracking::Global<Config>;

from DataFlow::Node source, DataFlow::Node sink, VulnerableCall c
where Flow::flow(source, sink) and (sink = c.getArg(_) or sink = c.getArgByName(_))
select relPath(source.getLocation()) as source_file, source.getLocation().getStartLine() as source_line,
  relPath(c.getLocation()) as sink_file, c.getLocation().getStartLine() as sink_line,
  c.getPackage() as package, c.getSymbol() as symbol
