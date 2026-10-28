/**
 * @name Code-graph export: function flow summaries
 * @description Intraprocedural (input, output) dataflow pairs per method defined in the source
 *              root, using local data and taint flow.
 * @kind table
 * @id appsec-review/graph-export/ruby/flow-summaries
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `flow_summaries`.
// Inputs are positional and keyword parameters; outputs are the method's return values (explicit
// `return` and the implicit last expression) and export sink operands. Calls to methods CodeQL
// does not model are opaque here: only flow the library summarizes through them is followed.
// Ruby has no pointer parameters or globals the C/C++ kinds describe, so `parameter_deref` and
// `global` never occur.
import codeql.ruby.AST
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking
import GraphExport

predicate inputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name
) {
  exists(NamedParameter p |
    p = f.getAParameter() and n.asParameter() = p and kind = "parameter" and name = p.getName()
  |
    index = p.getPosition()
    or
    not exists(p.getPosition()) and index = -1
  )
}

predicate outputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name,
  string model
) {
  exists(DataFlow::MethodNode m | m.asCallableAstNode() = f and n = m.getAReturnNode()) and
  kind = "return" and
  index = -1 and
  name = "" and
  model = ""
  or
  exists(Expr sinkExpr, string api |
    GraphExport::sinkNode(n, sinkExpr, index) and
    sinkExpr.getEnclosingMethod() = f and
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
    function_name = f.getQualifiedName() and
    GraphExport::locationColumns(f.getNameLocation(), function_path, function_start_line,
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
