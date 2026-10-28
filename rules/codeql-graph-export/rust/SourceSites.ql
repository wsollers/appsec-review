/**
 * @name Code-graph export: source sites
 * @description rust-all threat-model sources (remote, commandargs, environment, file,
 *              stdin, database) and catalog API sources the model library does not cover.
 * @kind table
 * @id appsec-review/graph-export/rust/source-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `source_sites`.
import rust
import codeql.rust.dataflow.DataFlow
import GraphExport

query predicate source_sites(
  string source_path, int source_start_line, int source_start_column, int source_end_line,
  int source_end_column, string model, string source_type, string node_kind, string api,
  string declared_in, int index, string source_display, string function_name,
  string function_path, int function_start_line, int function_start_column
) {
  exists(DataFlow::Node n, Function function |
    GraphExport::source(n, model, source_type, node_kind, api, index, declared_in) and
    function = GraphExport::nodeFunction(n)
  |
    GraphExport::locationColumns(n.getLocation(), source_path, source_start_line,
      source_start_column, source_end_line, source_end_column) and
    source_display = n.toString() and
    function_name = GraphExport::functionName(function) and
    GraphExport::locationColumns(GraphExport::functionLocation(function), function_path,
      function_start_line, function_start_column, _, _)
  )
}
