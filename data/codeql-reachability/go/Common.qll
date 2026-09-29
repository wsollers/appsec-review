/** Shared definitions for appsec/go-reachability (brief E, ADR-0022). Locator tables, never findings. */

import go
import Symbols

/** The checkout-relative path of `l`, or "" when the file is outside the source root. */
string relPath(Location l) {
  if exists(l.getFile().getRelativePath()) then result = l.getFile().getRelativePath() else result = ""
}

/** A printable name for a function body: the qualified name of a declaration, else "func-literal". */
string funcName(FuncDef f) {
  if exists(f.(FuncDecl).getFunction().getQualifiedName())
  then result = f.(FuncDecl).getFunction().getQualifiedName()
  else result = "func-literal"
}

/** A static call edge from the body `caller` to the body `callee`. */
predicate edge(FuncDef caller, FuncDef callee) {
  exists(DataFlow::CallNode c | c.getRoot() = caller and c.getACallee() = callee)
}

/** A call of a vulnerable symbol: `Name` (package function) or `Type.Name` (method). */
class VulnerableCall extends DataFlow::CallNode {
  string pkg;
  string sym;

  VulnerableCall() {
    vulnerableSymbol(pkg, sym) and
    (
      this.getTarget().hasQualifiedName(pkg, sym)
      or
      exists(string t, string m |
        sym = t + "." + m and this.getTarget().(Method).hasQualifiedName(pkg, t, m)
      )
    )
  }

  string getPackage() { result = pkg }

  string getSymbol() { result = sym }
}

/** Reachability roots: `main`/`init` of package main, `init` anywhere, and handler functions that read remote input. */
class EntryPoint extends FuncDef {
  string reason;

  EntryPoint() {
    exists(this.getLocation().getFile().getRelativePath()) and
    (
      this.(FuncDecl).getName() = "main" and
      this.(FuncDecl).getFunction().getPackage().getName() = "main" and
      reason = "main"
      or
      this.(FuncDecl).getName() = "init" and reason = "init"
      or
      exists(RemoteFlowSource s | s.getRoot() = this) and reason = "remote-flow-source"
    )
  }

  string getReason() { result = reason }
}
