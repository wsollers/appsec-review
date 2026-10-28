/**
 * @name Code-graph export: function flow summaries
 * @description Intraprocedural (input, output) dataflow pairs per callable defined in the
 *              source root, using local data and taint flow.
 * @kind table
 * @id appsec-review/graph-export/java/flow-summaries
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `flow_summaries`.
// Calls to callables without a source body are opaque here: only flow CodeQL models through
// them is followed. Java passes references by value, so a write through a parameter is a field
// store on it (`p.f = v`, output kind "parameter_deref"); there is no "parameter_deref" input.
// Globals are static fields, named `<declaring type>.<field>`.
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import GraphExport

string staticFieldName(Field field) {
  result = field.getDeclaringType().getSourceDeclaration().getQualifiedName() + "." + field.getName()
}

predicate inputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name
) {
  exists(Parameter p | p = f.getAParameter() and index = p.getPosition() and name = p.getName() |
    n.asParameter() = p and kind = "parameter"
  )
  or
  exists(FieldRead read |
    read.getField().isStatic() and read.getEnclosingCallable() = f and n.asExpr() = read
  |
    kind = "global" and index = -1 and name = staticFieldName(read.getField())
  )
}

predicate outputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name,
  string model
) {
  exists(ReturnStmt r | r.getEnclosingCallable() = f and n.asExpr() = r.getExpr() |
    kind = "return" and index = -1 and name = "" and model = ""
  )
  or
  exists(Parameter p, AssignExpr a |
    p = f.getAParameter() and
    a.getEnclosingCallable() = f and
    a.getDest().(FieldAccess).getQualifier() = p.getAnAccess() and
    n.asExpr() = a.getRhs()
  |
    kind = "parameter_deref" and index = p.getPosition() and name = p.getName() and model = ""
  )
  or
  exists(AssignExpr a, Field field |
    a.getEnclosingCallable() = f and
    field = a.getDest().(FieldAccess).getField() and
    field.isStatic() and
    n.asExpr() = a.getRhs()
  |
    kind = "global" and index = -1 and name = staticFieldName(field) and model = ""
  )
  or
  exists(Expr sinkExpr, string api |
    GraphExport::sinkOperandNode(n, sinkExpr, index) and
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
    function_name = GraphExport::functionName(f) and
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
