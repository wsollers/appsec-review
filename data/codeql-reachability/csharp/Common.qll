/** Shared definitions for appsec/csharp-reachability (brief E, ADR-0022). Locator tables, never findings. */

import csharp
import semmle.code.csharp.security.dataflow.flowsources.Remote
import Symbols

string relPath(Location l) {
  if exists(l.getFile().getRelativePath()) then result = l.getFile().getRelativePath() else result = ""
}

string callableName(Callable c) { result = c.getDeclaringType().getName() + "." + c.getName() }

/** A call edge including runtime (virtual/interface) targets. */
predicate edge(Callable caller, Callable callee) {
  exists(Call c | c.getEnclosingCallable() = caller and callee = c.getARuntimeTarget().getUnboundDeclaration())
}

/** A call of `Type.Method` in namespace `pkg`, or `Method` of any type in `pkg`. */
class VulnerableCall extends Call {
  string pkg;
  string sym;

  VulnerableCall() {
    vulnerableSymbol(pkg, sym) and
    exists(Callable target | target = this.getTarget().getUnboundDeclaration() |
      exists(string t, string m |
        sym = t + "." + m and target.getName() = m and target.getDeclaringType().hasFullyQualifiedName(pkg, t)
      )
      or
      not sym.matches("%.%") and target.getName() = sym and
      target.getDeclaringType().getNamespace().getFullName() = pkg
    )
  }

  string getPackage() { result = pkg }

  string getSymbol() { result = sym }
}

/** Roots: `Main`, public controller actions, and callables reading remote input. */
class EntryPoint extends Callable {
  string reason;

  EntryPoint() {
    this.fromSource() and
    (
      this.getName() = "Main" and this.(Method).isStatic() and reason = "main"
      or
      this.(Method).isPublic() and this.getDeclaringType().getName().matches("%Controller") and
      reason = "controller-action"
      or
      exists(RemoteFlowSource s | s.getEnclosingCallable() = this) and reason = "remote-flow-source"
    )
  }

  string getReason() { result = reason }
}
