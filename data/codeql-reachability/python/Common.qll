/** Shared definitions for appsec/python-reachability (brief E, ADR-0022). Locator tables, never findings. */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources
import Symbols

string relPath(Location l) {
  if exists(l.getFile().getRelativePath()) then result = l.getFile().getRelativePath() else result = ""
}

string scopeName(Scope s) {
  if s instanceof Module then result = s.(Module).getName() else result = s.getQualifiedName()
}

/** A resolved call edge (new data-flow call graph) from a scope to a Python function. */
predicate edge(Scope caller, Function callee) {
  exists(DataFlow::CallCfgNode c |
    c.getScope() = caller and
    c.getFunction().getALocalSource().asExpr() = callee.getDefinition()
  )
}

/** A call of `symbol` exported by module `pkg` (`name` or `Type.name`, via API graphs). */
class VulnerableCall extends DataFlow::CallCfgNode {
  string pkg;
  string sym;

  VulnerableCall() {
    vulnerableSymbol(pkg, sym) and
    (
      not sym.matches("%.%") and this = API::moduleImport(pkg).getMember(sym).getACall()
      or
      exists(string t, string m | sym = t + "." + m |
        this = API::moduleImport(pkg).getMember(t).getMember(m).getACall() or
        this = API::moduleImport(pkg).getMember(t).getReturn().getMember(m).getACall()
      )
    )
  }

  string getPackage() { result = pkg }

  string getSymbol() { result = sym }
}

/** Roots: every module body (runs on import), `main`, and functions reading remote input (views/handlers). */
class EntryPoint extends Scope {
  string reason;

  EntryPoint() {
    exists(this.getLocation().getFile().getRelativePath()) and
    (
      this instanceof Module and reason = "module-body"
      or
      this.(Function).getName() = "main" and reason = "main"
      or
      exists(RemoteFlowSource s | s.getScope() = this) and reason = "remote-flow-source"
    )
  }

  string getReason() { result = reason }
}
