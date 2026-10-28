/**
 * @name Code-graph export: source sites
 * @description ruby-all modeled remote flow sources and ARGV/ENV reads (local sources), with model
 *              identity and source type.
 * @kind table
 * @id appsec-review/graph-export/ruby/source-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `source_sites`.
// `declared_in` is the constant a source method is called on (`ENV` in `ENV["HOME"]`), else "".
import codeql.ruby.AST
import codeql.ruby.DataFlow
import GraphExport

query predicate source_sites(
  string source_path, int source_start_line, int source_start_column, int source_end_line,
  int source_end_column, string model, string source_type, string node_kind, string api,
  string declared_in, int index, string source_display, string function_name,
  string function_path, int function_start_line, int function_start_column
) {
  exists(DataFlow::Node n, GraphExport::SourceFunction function |
    GraphExport::source(n, model, source_type, node_kind, api, index) and
    function = GraphExport::functionAt(n.getLocation())
  |
    GraphExport::locationColumns(n.getLocation(), source_path, source_start_line,
      source_start_column, source_end_line, source_end_column) and
    (
      declared_in = GraphExport::receiverConstant(n.asExpr().getExpr())
      or
      not n.asExpr().getExpr() instanceof MethodCall and declared_in = ""
    ) and
    source_display = n.toString() and
    function_name = function.getQualifiedName() and
    GraphExport::locationColumns(function.getNameLocation(), function_path, function_start_line,
      function_start_column, _, _)
  )
}
