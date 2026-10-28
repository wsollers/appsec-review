/**
 * @name Code-graph export: function flow summaries
 * @description Intraprocedural (input, output) dataflow pairs per function defined in the
 *              source root, using local data and taint flow plus one level of indirection.
 * @kind table
 * @id appsec-review/graph-export/go/flow-summaries
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `flow_summaries`.
// Calls to functions without a source-root body are opaque here: only flow CodeQL models through
// them is followed. Writes through a parameter are direct stores (`*p = v`, `p.f = v`,
// `p[i] = v`). Inputs are parameters and package-level variable reads.
import go
import GraphExport

predicate inputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name
) {
  exists(Parameter p | p = f.getParameter(index) and name = p.getName() |
    n = DataFlow::parameterNode(p) and kind = "parameter"
  )
  or
  exists(Variable g |
    g.getScope() instanceof PackageScope and
    n.(DataFlow::ReadNode).reads(g) and
    GraphExport::nodeFunction(n) = f
  |
    kind = "global" and index = -1 and name = g.getName()
  )
}

/** `lvalue` stores through parameter `p`: `*p`, `p.f` or `p[i]`. */
predicate parameterStore(Parameter p, Expr lvalue) {
  lvalue.(StarExpr).getBase().(Ident).refersTo(p)
  or
  lvalue.(SelectorExpr).getBase().(Ident).refersTo(p)
  or
  lvalue.(IndexExpr).getBase().(Ident).refersTo(p)
}

predicate outputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name,
  string model
) {
  exists(ReturnStmt r | r.getEnclosingFunction() = f and n.asExpr() = r.getAnExpr() |
    kind = "return" and index = -1 and name = "" and model = ""
  )
  or
  exists(Parameter p, int i | p = f.getParameter(i) |
    kind = "parameter_deref" and
    index = i and
    name = p.getName() and
    model = "" and
    exists(Assignment a, int j |
      a.getEnclosingFunction() = f and
      parameterStore(p, a.getLhs(j)) and
      n.asExpr() = a.getRhs(j)
    )
  )
  or
  exists(Variable g, Assignment a, int j |
    g.getScope() instanceof PackageScope and
    a.getEnclosingFunction() = f and
    a.getLhs(j).(Ident).refersTo(g) and
    n.asExpr() = a.getRhs(j)
  |
    kind = "global" and index = -1 and name = g.getName() and model = ""
  )
  or
  exists(DataFlow::CallNode call, string api |
    GraphExport::sinkNode(n, call, index) and
    GraphExport::callFunction(call) = f and
    GraphExport::sink(call, _, index, model, api)
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
    function_name = GraphExport::functionName(f) and
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
