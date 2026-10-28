/**
 * @name Code-graph export: seed functions
 * @description The source-root callables each seed location (finding lines) resolved to in
 *              "seeded" mode; no rows in "whole_program" mode.
 * @kind table
 * @id appsec-review/graph-export/csharp/seeds
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `seed_functions`.
// Scope and seeds are bound with `--external` (see GraphExport.qll).
import csharp
import GraphExport

query predicate seed_functions(
  string seed_path, int seed_start_line, int seed_end_line, string function_name,
  string function_path, int function_start_line, int function_start_column
) {
  not GraphExport::wholeProgram() and
  exists(GraphExport::SourceFunction f |
    GraphExport::seedMatch(seed_path, seed_start_line, seed_end_line, f) and
    function_name = GraphExport::qualifiedName(f) and
    GraphExport::locationColumns(f.getLocation(), function_path, function_start_line,
      function_start_column, _, _)
  )
}