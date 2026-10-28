/**
 * @name Code-graph export: function flow summaries
 * @description Intraprocedural (input, output) dataflow pairs per function defined in the
 *              source root, using local data steps and the default taint steps.
 * @kind table
 * @id appsec-review/graph-export/javascript/flow-summaries
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `flow_summaries`.
// Inputs are named parameters and reads of global or module-scope variables; outputs are
// returned values, property writes on a parameter object ("parameter_deref"), assignments to
// global or module-scope variables and sink operands. Calls are opaque here: only flow the
// default taint steps model through them (string, array, path, URI and JSON helpers) is followed.
import javascript
import GraphExport

/** `v` is a global or module-scope variable. */
predicate sharedVariable(Variable v) { v.isGlobal() or v.getScope() instanceof ModuleScope }

predicate inputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name
) {
  exists(SimpleParameter p |
    f.(Function).getParameter(index) = p and name = p.getName() and n = DataFlow::parameterNode(p)
  |
    kind = "parameter"
  )
  or
  exists(Variable v, VarAccess access |
    sharedVariable(v) and
    access = v.getAnAccess() and
    access.getContainer() = f and
    n = DataFlow::valueNode(access) and
    not access instanceof LValue
  |
    kind = "global" and index = -1 and name = v.getName()
  )
}

predicate outputNode(
  GraphExport::SourceFunction f, DataFlow::Node n, string kind, int index, string name,
  string model
) {
  n = DataFlow::valueNode(f.(Function).getAReturnedExpr()) and
  kind = "return" and
  index = -1 and
  name = "" and
  model = ""
  or
  exists(SimpleParameter p, DataFlow::PropWrite write |
    f.(Function).getParameter(index) = p and
    write.getContainer() = f and
    write.getBase().getALocalSource() = DataFlow::parameterNode(p) and
    n = write.getRhs()
  |
    kind = "parameter_deref" and name = p.getName() and model = ""
  )
  or
  exists(Variable v, AssignExpr a |
    sharedVariable(v) and
    a.getContainer() = f and
    a.getLhs() = v.getAnAccess() and
    n = DataFlow::valueNode(a.getRhs())
  |
    kind = "global" and index = -1 and name = v.getName() and model = ""
  )
  or
  exists(DataFlow::Node sinkNode, string api |
    GraphExport::sinkNode(n, sinkNode, index) and
    sinkNode.getContainer() = f and
    GraphExport::sink(sinkNode, n, index, model, api)
  |
    kind = "sink" and
    (if api = "" then name = model else name = api)
  )
}

/** `n` is reached from `input` inside `f`; `data` is true for a pure value-preserving chain. */
predicate reaches(GraphExport::SourceFunction f, DataFlow::Node input, DataFlow::Node n,
  boolean data
) {
  inputNode(f, input, _, _, _) and n = input and data = true
  or
  exists(DataFlow::Node mid, boolean previous | reaches(f, input, mid, previous) |
    n = mid.getASuccessor() and n.getContainer() = f and data = previous
    or
    TaintTracking::defaultTaintStep(mid, n) and n.getContainer() = f and data = false
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
      reaches(f, input, output, _)
    ) and
    // A pair is "data" when any witness is plain dataflow, otherwise "taint".
    (
      if
        exists(DataFlow::Node input, DataFlow::Node output |
          inputNode(f, input, from_kind, from_index, from_name) and
          outputNode(f, output, to_kind, to_index, to_name, to_model) and
          reaches(f, input, output, true)
        )
      then flow_kind = "data"
      else flow_kind = "taint"
    )
  )
}
