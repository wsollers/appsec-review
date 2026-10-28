/**
 * @name Code-graph export: function flow summaries
 * @description Intraprocedural (input, output) dataflow pairs per function defined in the
 *              source root, using local data and taint flow.
 * @kind table
 * @id appsec-review/graph-export/python/flow-summaries
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `flow_summaries`.
// Calls are opaque here: only flow python-all models as a local taint step is followed. Inputs
// are parameters (`self` is index 0 of a method) and reads of global variables; a write through
// a parameter is an attribute or subscript store on it (`p.f = v`, `p[k] = v`).
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import GraphExport

predicate inputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name
) {
  exists(Parameter p | p = n.(DataFlow::ParameterNode).getParameter() and p.getScope() = f |
    kind = "parameter" and index = p.getPosition() and name = p.getName()
  )
  or
  exists(Name read, GlobalVariable g |
    read.getVariable() = g and
    read.isUse() and
    read.getScope() = f and
    n.asExpr() = read
  |
    kind = "global" and index = -1 and name = g.getId()
  )
}

/** `target` stores into the parameter `p` (`p.attr = ...` or `p[key] = ...`). */
predicate parameterStore(Parameter p, Expr target) {
  exists(Name object |
    object = target.(Attribute).getObject() or object = target.(Subscript).getObject()
  |
    object.getVariable() = p.getVariable()
  )
}

predicate outputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name,
  string model
) {
  exists(Return r | r.getScope() = f and n.asExpr() = r.getValue() |
    kind = "return" and index = -1 and name = "" and model = ""
  )
  or
  exists(Parameter p, Assign a |
    p.getScope() = f and
    a.getScope() = f and
    parameterStore(p, a.getATarget()) and
    n.asExpr() = a.getValue()
  |
    kind = "parameter_deref" and index = p.getPosition() and name = p.getName() and model = ""
  )
  or
  exists(GlobalVariable g, Assign a, Name target |
    a.getScope() = f and target = a.getATarget() and target.getVariable() = g and
    n.asExpr() = a.getValue()
  |
    kind = "global" and index = -1 and name = g.getId() and model = ""
  )
  or
  exists(DataFlow::Node sinkNode, string api |
    GraphExport::sink(sinkNode, n, index, model, api) and
    sinkNode.getScope() = f
  |
    kind = "sink" and
    (if api = "" then name = model else name = api)
  )
}

query predicate flow_summaries(
  string function_name, string function_path, int function_start_line,
  int function_start_column, string from_kind, int from_index, string from_name,
  string to_kind, int to_index, string to_name, string to_model, string flow_kind
) {
  exists(GraphExport::SourceFunction f |
    GraphExport::exported(f) and
    function_name = f.getQualifiedName() and
    GraphExport::locationColumns(GraphExport::functionLocation(f), function_path,
      function_start_line, function_start_column, _, _) and
    exists(DataFlow::Node input, DataFlow::Node output |
      inputNode(f, input, from_kind, from_index, from_name) and
      outputNode(f, output, to_kind, to_index, to_name, to_model) and
      TaintTracking::localTaint(input, output)
    ) and
    // A pair is "data" when any witness is plain dataflow, otherwise "taint".
    (
      if
        exists(DataFlow::Node input, DataFlow::Node output |
          inputNode(f, input, from_kind, from_index, from_name) and
          outputNode(f, output, to_kind, to_index, to_name, to_model) and
          DataFlow::localFlow(input, output)
        )
      then flow_kind = "data"
      else flow_kind = "taint"
    )
  )
}
