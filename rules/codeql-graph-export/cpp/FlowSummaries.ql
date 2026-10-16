/**
 * @name Code-graph export: function flow summaries
 * @description Intraprocedural (input, output) dataflow pairs per function defined in the
 *              source root, using local data and taint flow plus one level of indirection.
 * @kind table
 * @id appsec-review/graph-export/cpp/flow-summaries
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `flow_summaries`.
// Calls to functions without a definition are opaque here: only flow CodeQL models through
// them is followed. Writes through a parameter are direct stores (`*p`, `p[i]`, `p->f`) and
// call arguments that CodeQL marks as defined by the call.
import cpp
import semmle.code.cpp.ir.dataflow.DataFlow
import semmle.code.cpp.ir.dataflow.TaintTracking
import GraphExport

predicate inputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name
) {
  exists(Parameter p | p = f.getAParameter() and index = p.getIndex() and name = p.getName() |
    n.asParameter() = p and kind = "parameter"
    or
    n.asParameter(1) = p and kind = "parameter_deref"
  )
  or
  exists(GlobalVariable g, VariableAccess access |
    access = g.getAnAccess() and access.getEnclosingFunction() = f and n.asExpr() = access
  |
    kind = "global" and index = -1 and name = g.getQualifiedName()
  )
}

predicate parameterStore(Parameter p, Expr lvalue) {
  lvalue.(PointerDereferenceExpr).getOperand() = p.getAnAccess()
  or
  lvalue.(ArrayExpr).getArrayBase() = p.getAnAccess()
  or
  lvalue.(PointerFieldAccess).getQualifier() = p.getAnAccess()
}

predicate outputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name,
  string model
) {
  exists(ReturnStmt r | r.getEnclosingFunction() = f and n.asExpr() = r.getExpr() |
    kind = "return" and index = -1 and name = "" and model = ""
  )
  or
  exists(Parameter p | p = f.getAParameter() |
    kind = "parameter_deref" and
    index = p.getIndex() and
    name = p.getName() and
    model = "" and
    (
      exists(Assignment a |
        a.getEnclosingFunction() = f and parameterStore(p, a.getLValue()) and n.asExpr() = a.getRValue()
      )
      or
      n.asDefiningArgument() = p.getAnAccess() and n.asDefiningArgument().getEnclosingFunction() = f
    )
  )
  or
  exists(GlobalVariable g, Assignment a |
    a.getEnclosingFunction() = f and a.getLValue() = g.getAnAccess() and n.asExpr() = a.getRValue()
  |
    kind = "global" and index = -1 and name = g.getQualifiedName() and model = ""
  )
  or
  exists(Expr sinkExpr, string api |
    GraphExport::sinkNode(n, sinkExpr, index) and
    sinkExpr.getEnclosingFunction() = f and
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
