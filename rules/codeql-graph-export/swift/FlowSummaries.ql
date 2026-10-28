/**
 * @name Code-graph export: function flow summaries
 * @description Intraprocedural (input, output) dataflow pairs per function defined in the
 *              source root, using local data and taint flow.
 * @kind table
 * @id appsec-review/graph-export/swift/flow-summaries
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `flow_summaries`.
// Calls to functions without a body are opaque here: only flow swift-all models through them is
// followed. Inputs are parameters and module-level variables read in the function; outputs are
// returned values, assignments to `inout` parameters ("parameter_deref"), assignments to
// module-level variables, and catalog or model sink operands.
import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import GraphExport

/** A module-level (global) variable: declared outside any function and any type. */
predicate globalVariable(VarDecl g) {
  not g instanceof ParamDecl and
  not exists(g.getEnclosingFunction()) and
  not exists(GraphExport::memberType(g))
}

/** A read or write of `g`. */
DeclRefExpr accessOf(VarDecl g) { result.getDecl() = g }

predicate inputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name
) {
  exists(ParamDecl p | p = f.getParam(index) and name = p.getName() |
    n.asParameter() = p and kind = "parameter"
  )
  or
  exists(VarDecl g, DeclRefExpr access |
    globalVariable(g) and access = accessOf(g) and access.getEnclosingFunction() = f and
    n.asExpr() = access
  |
    kind = "global" and index = -1 and name = g.getName()
  )
}

predicate outputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name,
  string model
) {
  exists(ReturnStmt r | r.getEnclosingFunction() = f and n.asExpr() = r.getResult() |
    kind = "return" and index = -1 and name = "" and model = ""
  )
  or
  exists(ParamDecl p, AssignExpr a |
    p = f.getParam(index) and
    p.isInout() and
    a.getEnclosingFunction() = f and
    a.getDest() = accessOf(p) and
    n.asExpr() = a.getSource()
  |
    kind = "parameter_deref" and name = p.getName() and model = ""
  )
  or
  exists(VarDecl g, AssignExpr a |
    globalVariable(g) and
    a.getEnclosingFunction() = f and
    a.getDest() = accessOf(g) and
    n.asExpr() = a.getSource()
  |
    kind = "global" and index = -1 and name = g.getName() and model = ""
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
