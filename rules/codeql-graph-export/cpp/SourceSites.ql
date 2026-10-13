/**
 * @name Code-graph export: source sites
 * @description cpp-all modeled flow sources (remote, local, argv, environment) and catalog API
 *              sources the model library does not cover, with model identity and source type.
 * @kind table
 * @id appsec-review/graph-export/cpp/source-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `source_sites`.
import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import GraphExport

query predicate source_sites(
  string source_path, int source_start_line, int source_start_column, int source_end_line,
  int source_end_column, string model, string source_type, string node_kind, string api,
  string declared_in, int index, string source_display, string function_name,
  string function_path, int function_start_line, int function_start_column
) {
  exists(DataFlow::Node n, Function function |
    GraphExport::source(n, model, source_type, node_kind, api, index) and
    function = n.getEnclosingCallable()
  |
    GraphExport::locationColumns(n.getLocation(), source_path, source_start_line,
      source_start_column, source_end_line, source_end_column) and
    (if api = "" then declared_in = "" else declared_in = GraphExport::declaredInName(api)) and
    source_display = n.toString() and
    function_name = function.getQualifiedName() and
    GraphExport::locationColumns(function.getLocation(), function_path, function_start_line,
      function_start_column, _, _)
  )
}
