/**
 * @name Code-graph export: function flow summaries
 * @description Intraprocedural (input, output) dataflow pairs per callable defined in the
 *              source root, using local data and taint flow.
 * @kind table
 * @id appsec-review/graph-export/csharp/flow-summaries
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `flow_summaries`.
// Calls are opaque here: only flow csharp-all models through them (models-as-data summaries)
// is followed. C# has no pointers: "parameter_deref" outputs are writes to `ref`/`out`
// parameters and there is no "parameter_deref" input; "global" is a static field.
import csharp
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.dataflow.TaintTracking
import GraphExport

predicate inputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name
) {
  exists(Parameter p | p = f.getAParameter() |
    n.asParameter() = p and kind = "parameter" and index = p.getPosition() and name = p.getName()
  )
  or
  exists(Field g, FieldRead access |
    g.isStatic() and
    access = g.getAnAccess() and
    access.getEnclosingCallable() = f and
    n.asExpr() = access
  |
    kind = "global" and index = -1 and name = GraphExport::qualifiedName(g)
  )
}

predicate outputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name,
  string model
) {
  (
    exists(ReturnStmt r | r.getEnclosingCallable() = f and n.asExpr() = r.getExpr())
    or
    n.asExpr() = f.getExpressionBody()
  ) and
  kind = "return" and
  index = -1 and
  name = "" and
  model = ""
  or
  exists(Parameter p, AssignableDefinition def |
    p = f.getAParameter() and
    p.isOutOrRef() and
    def.getTarget() = p and
    def.getEnclosingCallable() = f and
    n.asExpr() = def.getSource()
  |
    kind = "parameter_deref" and
    index = p.getPosition() and
    name = p.getName() and
    model = ""
  )
  or
  exists(Field g, AssignableDefinition def |
    g.isStatic() and
    def.getTarget() = g and
    def.getEnclosingCallable() = f and
    n.asExpr() = def.getSource()
  |
    kind = "global" and index = -1 and name = GraphExport::qualifiedName(g) and model = ""
  )
  or
  exists(Expr sinkExpr, string api |
    GraphExport::sinkNode(n, sinkExpr, index) and
    sinkExpr.getEnclosingCallable() = f and
    GraphExport::sink(sinkExpr, _, index, model, api)
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
    function_name = GraphExport::qualifiedName(f) and
    GraphExport::locationColumns(f.getLocation(), function_path, function_start_line,
      function_start_column, _, _) and
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