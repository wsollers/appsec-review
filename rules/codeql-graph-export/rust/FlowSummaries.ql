/**
 * @name Code-graph export: function flow summaries
 * @description Intraprocedural (input, output) dataflow pairs per function defined in the
 *              source root, using local data and taint flow.
 * @kind table
 * @id appsec-review/graph-export/rust/flow-summaries
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `flow_summaries`.
// Inputs are the declared parameters (`self` is not an input); outputs are the function's
// return value and the operands of its sink candidates. Rust has no `parameter_deref` or `global`
// rows: writes through `&mut` parameters and `static` items are a named gap of this pack.
import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking
import GraphExport

predicate inputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name
) {
  exists(Param p | p = f.getParam(index) and n.asParameter() = p |
    kind = "parameter" and
    (
      name = p.getPat().(IdentPat).getName().getText()
      or
      not p.getPat() instanceof IdentPat and name = ""
    )
  )
}

predicate outputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name,
  string model
) {
  kind = "return" and
  index = -1 and
  name = "" and
  model = "" and
  (
    n.asExpr() = f.getFunctionBody()
    or
    exists(ReturnExpr r | r.getEnclosingCallable() = f and n.asExpr() = r.getExpr())
  )
  or
  exists(Expr sinkExpr, string api |
    GraphExport::sinkOperandNode(n, sinkExpr, index) and
    GraphExport::enclosingFunction(sinkExpr) = f and
    GraphExport::sink(sinkExpr, n.asExpr(), index, model, api)
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
