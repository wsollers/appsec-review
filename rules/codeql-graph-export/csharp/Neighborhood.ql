/**
 * @name Code-graph export: neighborhood
 * @description Every callable exported in "seeded" mode with its minimum call-graph distance
 *              from a seed callable; no rows in "whole_program" mode.
 * @kind table
 * @id appsec-review/graph-export/csharp/neighborhood
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `neighborhood`.
// Scope and seeds are bound with `--external` (see GraphExport.qll).
import csharp
import GraphExport

query predicate neighborhood(
  string function_name, string function_path, int function_start_line,
  int function_start_column, int depth
) {
  not GraphExport::wholeProgram() and
  exists(GraphExport::SourceFunction f |
    GraphExport::near(f, _) and
    depth = min(int d | GraphExport::near(f, d)) and
    function_name = GraphExport::qualifiedName(f) and
    GraphExport::locationColumns(f.getLocation(), function_path, function_start_line,
      function_start_column, _, _)
  )
}