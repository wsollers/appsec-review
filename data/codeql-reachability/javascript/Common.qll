/** Shared definitions for appsec/javascript-reachability (brief E, ADR-0022). Locator tables, never findings. */

import javascript
import semmle.javascript.security.dataflow.RemoteFlowSources
import Symbols

string relPath(Location l) {
  if exists(l.getFile().getRelativePath()) then result = l.getFile().getRelativePath() else result = ""
}

/** A printable name for a function or top-level container. */
string containerName(StmtContainer c) {
  if exists(c.(Function).getName())
  then result = c.(Function).getName()
  else
    if c instanceof TopLevel
    then result = "<toplevel>"
    else result = "<anonymous>"
}

/** A call edge from `caller` (function or module top level) to a resolved callee function. */
predicate edge(StmtContainer caller, Function callee) {
  exists(DataFlow::InvokeNode c | c.getContainer() = caller and callee = c.getACallee())
}

/** A call of `symbol` exported by module `pkg` (`name` or `Type.name`, via API graphs). */
class VulnerableCall extends DataFlow::InvokeNode {
  string pkg;
  string sym;

  VulnerableCall() {
    vulnerableSymbol(pkg, sym) and
    (
      not sym.matches("%.%") and
      this = API::moduleImport(pkg).getMember(sym).getAnInvocation()
      or
      exists(string t, string m | sym = t + "." + m |
        this = API::moduleImport(pkg).getMember(t).getMember(m).getAnInvocation() or
        this = API::moduleImport(pkg).getMember(t).getInstance().getMember(m).getAnInvocation()
      )
      or
      sym = "default" and this = API::moduleImport(pkg).getAnInvocation()
    )
  }

  string getPackage() { result = pkg }

  string getSymbol() { result = sym }
}

/** Roots: every module top level (it runs on load), route handlers, and functions reading remote input. */
class EntryPoint extends StmtContainer {
  string reason;

  EntryPoint() {
    exists(this.getFile().getRelativePath()) and
    (
      this instanceof TopLevel and reason = "module-top-level"
      or
      this = any(Http::RouteHandler h).(DataFlow::FunctionNode).getFunction() and reason = "route-handler"
      or
      exists(RemoteFlowSource s | s.getContainer() = this) and reason = "remote-flow-source"
    )
  }

  string getReason() { result = reason }
}
