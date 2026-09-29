/**
 * Advisory symbols for brief E (ADR-0022). Rows come ONLY from the data extension that
 * dep_reachability_codeql.py generates (model pack appsec/java-reachability-symbols); no advisory
 * or model text is ever spliced into QL.
 */

/** `package` (import path / namespace / module) declares the vulnerable `symbol` (`Name` or `Type.Name`). */
extensible predicate vulnerableSymbol(string package, string symbol);
