/**
 * @name Remote input reaches a vulnerable dependency symbol (Go)
 * @description `TaintTracking::Global` from `RemoteFlowSource` to an argument (or receiver) of a
 *              call of a listed symbol. A locator table, never a finding.
 * @kind table
 * @id appsec/go/reachability-taint
 */

import go
import Common

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(VulnerableCall c | sink = c.getAnArgument() or sink = c.getReceiver())
  }
}

module Flow = TaintTracking::Global<Config>;

from DataFlow::Node source, DataFlow::Node sink, VulnerableCall c
where
  Flow::flow(source, sink) and
  (sink = c.getAnArgument() or sink = c.getReceiver())
select relPath(source.getLocation()) as source_file, source.getLocation().getStartLine() as source_line,
  relPath(c.getLocation()) as sink_file, c.getLocation().getStartLine() as sink_line,
  c.getPackage() as package, c.getSymbol() as symbol
