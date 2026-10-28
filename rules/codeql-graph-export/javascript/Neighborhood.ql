/**
 * @name Code-graph export: neighborhood
 * @description Every function exported in "seeded" mode with its minimum call-graph distance
 *              from a seed function; no rows in "whole_program" mode.
 * @kind table
 * @id appsec-review/graph-export/javascript/neighborhood
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `neighborhood`. Scope and seeds are bound with
// `--external` (see GraphExport.qll).
import javascript
import GraphExport

query predicate neighborhood(
  string function_name, string function_path, int function_start_line,
  int function_start_column, int depth
) {
  not GraphExport::wholeProgram() and
  exists(GraphExport::SourceFunction f |
    GraphExport::near(f, _) and
    depth = min(int d | GraphExport::near(f, d)) and
    function_name = f.getQualifiedName() and
    GraphExport::locationColumns(f.getNameLocation(), function_path, function_start_line,
      function_start_column, _, _)
  )
}
