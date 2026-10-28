/**
 * @name Code-graph export: source sites
 * @description java-all modeled flow sources (remote, command-line, environment, local input)
 *              and catalog API sources the model library does not cover, with model identity
 *              and source type.
 * @kind table
 * @id appsec-review/graph-export/java/source-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `source_sites`.
import java
import semmle.code.java.dataflow.DataFlow
import GraphExport

query predicate source_sites(
  string source_path, int source_start_line, int source_start_column, int source_end_line,
  int source_end_column, string model, string source_type, string node_kind, string api,
  string declared_in, int index, string source_display, string function_name,
  string function_path, int function_start_line, int function_start_column
) {
  exists(DataFlow::Node n, GraphExport::SourceFunction function |
    GraphExport::source(n, model, source_type, node_kind, api, index) and
    function = n.getEnclosingCallable()
  |
    GraphExport::locationColumns(n.getLocation(), source_path, source_start_line,
      source_start_column, source_end_line, source_end_column) and
    (
      declared_in = GraphExport::declaredIn(GraphExport::sourceCallee(n))
      or
      not exists(GraphExport::sourceCallee(n)) and declared_in = ""
    ) and
    source_display = n.toString() and
    function_name = GraphExport::functionName(function) and
    GraphExport::locationColumns(function.getLocation(), function_path, function_start_line,
      function_start_column, _, _)
  )
}
