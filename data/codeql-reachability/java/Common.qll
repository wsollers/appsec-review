/** Shared definitions for appsec/java-reachability (brief E, ADR-0022). Locator tables, never findings. */

import java
import semmle.code.java.dataflow.FlowSources
import Symbols

string relPath(Location l) {
  if exists(l.getFile().getRelativePath()) then result = l.getFile().getRelativePath() else result = ""
}

string callableName(Callable c) { result = c.getDeclaringType().getQualifiedName() + "." + c.getName() }

/** A call edge including overriding targets (virtual dispatch over the class hierarchy). */
predicate edge(Callable caller, Callable callee) { caller.polyCalls(callee) }

/** A call of a vulnerable symbol: `Type.method` in package `pkg`, or `method` of any type in `pkg`. */
class VulnerableCall extends Call {
  string pkg;
  string sym;

  VulnerableCall() {
    vulnerableSymbol(pkg, sym) and
    exists(Callable target | target = this.getCallee().getSourceDeclaration() |
      exists(string t, string m |
        sym = t + "." + m and target.getName() = m and target.getDeclaringType().hasQualifiedName(pkg, t)
      )
      or
      not sym.matches("%.%") and target.getName() = sym and
      target.getDeclaringType().getPackage().getName() = pkg
    )
  }

  string getPackage() { result = pkg }

  string getSymbol() { result = sym }
}

/** Roots: `main`, servlet `do*`, request-mapping annotated methods, and methods reading remote input. */
class EntryPoint extends Callable {
  string reason;

  EntryPoint() {
    this.fromSource() and
    (
      this instanceof MainMethod and reason = "main"
      or
      this.getName().matches("do%") and
      this.getDeclaringType().getASupertype*().hasQualifiedName(["javax.servlet.http", "jakarta.servlet.http"], "HttpServlet") and
      reason = "servlet"
      or
      this.getAnAnnotation().getType().getName().matches("%Mapping") and reason = "request-mapping"
      or
      exists(RemoteFlowSource s | s.getEnclosingCallable() = this) and reason = "remote-flow-source"
    )
  }

  string getReason() { result = reason }
}
