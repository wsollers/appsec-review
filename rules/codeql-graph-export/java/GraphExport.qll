/**
 * Shared definitions for the appsec-review Java/Kotlin code-graph export pack.
 *
 * LIVE-UNVERIFIED: written against the `codeql/java-all` library bundled with the pinned CodeQL
 * 2.27.0 CLI, but not compiled in the repository's offline CI. The live tier
 * (tests/live/test_codeql_graph_export_java_live.py) compiles and runs the pack on the pinned image.
 *
 * Export conventions (the column contract is ../columns.json, section `java`):
 * - every exported column is a primitive `string` or `int`; no query exports an entity column, so
 *   no database-internal element id leaves the database;
 * - a location is five columns `<p>_path, <p>_start_line, <p>_start_column, <p>_end_line,
 *   <p>_end_column`: the path is relative to the database source root
 *   (`File.getRelativePath()`), lines and columns are 1-based and the end column is inclusive;
 *   an element outside the source root exports path "" and zero positions;
 * - booleans are the strings "true" and "false";
 * - a callable defined in the source root is named `<declaring type>::<signature>`, for example
 *   `app.Server::lookup(java.lang.String)`: the qualified source declaration of the declaring
 *   type, then `Callable.getSignature()` (name and fully qualified parameter types), so overloads
 *   stay distinct; a library callable without a body in the source root is named by its bare
 *   name, and its declaring types are carried in `declared_in`;
 * - argument index -1 is the call's qualifier (the receiver) for sinks and the return value for
 *   sources;
 * - classification into sink and source classes is not done here: rows carry the CodeQL model
 *   identity (the models-as-data sink kind, or the source class) and the API name, and
 *   ../catalog.json classifies them downstream.
 *
 * Kotlin: the same queries run over Kotlin databases (CodeQL language `java`). A Kotlin function
 * location may start at a modifier or `fun` rather than at its name, so the normalizer's name span
 * falls back to a name scan (`symbol_name_mismatch`, inexact) there.
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.dispatch.VirtualDispatch
import semmle.code.java.controlflow.Dominance

module GraphExport {
  /**
   * Export scope, bound at evaluation time (`codeql database run-queries --external`) from the
   * one-row CSV `<mode>,<depth>`. `mode` is "whole_program" (everything is exported, `depth` is
   * ignored) or "seeded" (only the neighborhood of the seed functions is exported). See
   * docs/architecture/seeded-codeql-neighborhoods.md.
   */
  external predicate exportScope(string mode, int depth);

  /**
   * Seed locations, bound from the header-less CSV `<path>,<start_line>,<end_line>`: a path
   * relative to the database source root and a 1-based inclusive line range. Empty in
   * "whole_program" mode.
   */
  external predicate exportSeed(string path, int startLine, int endLine);

  /** Holds when `l` exports as the five location columns. */
  predicate locationColumns(
    Location l, string path, int startLine, int startColumn, int endLine, int endColumn
  ) {
    path = l.getFile().getRelativePath() and
    startLine = l.getStartLine() and
    startColumn = l.getStartColumn() and
    endLine = l.getEndLine() and
    endColumn = l.getEndColumn()
    or
    not exists(l.getFile().getRelativePath()) and
    path = "" and
    startLine = 0 and
    startColumn = 0 and
    endLine = 0 and
    endColumn = 0
  }

  /** Holds when `e` lies inside the database source root (an accepted source file). */
  predicate inSource(Element e) { exists(e.getLocation().getFile().getRelativePath()) }

  /**
   * A callable with a body inside the source root. Compiler-generated default constructors and
   * class and instance initializers (`<clinit>`, `<obinit>`) have no defining name in the source
   * and are not functions here, so calls in field initializers are not exported.
   */
  class SourceFunction extends Callable {
    SourceFunction() {
      this.fromSource() and
      inSource(this) and
      exists(this.getBody()) and
      not this instanceof InitializerMethod and
      not this.(Constructor).isDefaultConstructor()
    }
  }

  /** The export name of a callable: `<declaring type>::<signature>`. */
  string functionName(Callable c) {
    result =
      c.getSourceDeclaration().getDeclaringType().getSourceDeclaration().getQualifiedName() + "::" +
        c.getSourceDeclaration().getSignature()
  }

  /** The export name of a call target: `functionName` in the source root, else the bare name. */
  string calleeName(Callable c) {
    if c.getSourceDeclaration() instanceof SourceFunction
    then result = functionName(c)
    else result = c.getName()
  }

  /** Holds in "whole_program" mode, where every function is exported. */
  predicate wholeProgram() { exportScope("whole_program", _) }

  /** The call-graph radius of the neighborhood in "seeded" mode. */
  private int scopeDepth() { exportScope("seeded", result) }

  /**
   * Every source-root implementation a virtual call may dispatch to (CodeQL `viableImpl`, which
   * prunes by the receiver's possible runtime types).
   */
  SourceFunction virtualCandidate(MethodCall call) {
    result = viableImpl(call).getSourceDeclaration()
  }

  /**
   * `call` is published as `virtual_resolved`: more than one source implementation is viable, or
   * its static target has no body (an interface or abstract method) and a source implementation
   * is viable. A virtual call with exactly one viable bodied target is published as `direct`.
   */
  predicate isVirtualDispatch(MethodCall call) {
    exists(virtualCandidate(call)) and
    (
      count(virtualCandidate(call)) > 1
      or
      not exists(call.getMethod().getSourceDeclaration().getBody())
    )
  }

  /** `caller` contains a call to `callee`, directly or as a virtual candidate. */
  private predicate callEdge(SourceFunction caller, SourceFunction callee) {
    exists(Call call | call.getEnclosingCallable() = caller |
      callee = call.getCallee().getSourceDeclaration()
      or
      callee = virtualCandidate(call)
    )
  }

  /** The last line of `f`'s body. */
  private int functionEndLine(SourceFunction f) { result = f.getBody().getLocation().getEndLine() }

  /**
   * `f` is a source-root callable whose definition (name through closing brace) overlaps the seed
   * lines `[startLine, endLine]` of `path`. Every overlapping callable matches, so a lambda and the
   * method enclosing it both seed.
   */
  predicate seedMatch(string path, int startLine, int endLine, SourceFunction f) {
    exportSeed(path, startLine, endLine) and
    f.getFile().getRelativePath() = path and
    startLine <= functionEndLine(f) and
    endLine >= f.getLocation().getStartLine()
  }

  /** A function that contains finding lines (a seed). */
  predicate seedFunction(SourceFunction f) { seedMatch(_, _, _, f) }

  /**
   * `f` is within `distance` call-graph steps of a seed function, following call edges in either
   * direction. The recursion is monotone and bounded by the scope depth; it yields every
   * distance a walk can realise, so take the minimum for the shortest.
   */
  predicate near(SourceFunction f, int distance) {
    not wholeProgram() and
    (
      seedFunction(f) and distance = 0
      or
      exists(SourceFunction other, int previous |
        near(other, previous) and
        (callEdge(other, f) or callEdge(f, other)) and
        distance = previous + 1 and
        distance <= scopeDepth()
      )
    )
  }

  /** `f` is exported: every function in "whole_program" mode, else the seeded neighborhood. */
  predicate exported(Callable f) { wholeProgram() or near(f, _) }

  /** `e` lies in an exported function, or outside any function in "whole_program" mode. */
  predicate exportedExpr(Expr e) { wholeProgram() or exported(e.getEnclosingCallable()) }

  /** The dataflow node lies in an exported function. */
  predicate exportedNode(DataFlow::Node n) { wholeProgram() or exported(n.getEnclosingCallable()) }

  /**
   * Comma-joined sorted qualified names of the type declaring `c` and of every type declaring a
   * method `c` overrides (the catalog `declared_in`), so a call through a subtype still matches a
   * rule written for the declaring interface or class.
   */
  string declaredIn(Callable c) {
    result =
      concat(string name |
        name = c.getSourceDeclaration().getDeclaringType().getSourceDeclaration().getQualifiedName()
        or
        exists(Method overridden |
          c.getSourceDeclaration().(Method).overrides+(overridden) and
          name = overridden.getDeclaringType().getSourceDeclaration().getQualifiedName()
        )
      |
        name, "," order by name
      )
  }

  /** "true" or "false". */
  bindingset[b]
  string flag(boolean b) { b = true and result = "true" or b = false and result = "false" }

  /**
   * Catalog API sinks: method `name` and the dangerous argument `arg` (-1: the qualifier). Kept
   * equal to the `api` sink rules of ../catalog.json by tests/graph/test_java_export.py.
   */
  predicate apiSinkArgument(string name, int arg) {
    name = "exec" and arg = 0
    or
    name = "executeQuery" and arg = 0
    or
    name = "executeUpdate" and arg = 0
    or
    name = "execute" and arg = 0
    or
    name = "addBatch" and arg = 0
    or
    name = "readObject" and arg = -1
    or
    name = "readUnshared" and arg = -1
    or
    name = "forName" and arg = 0
    or
    name = "loadClass" and arg = 0
    or
    name = "eval" and arg = 0
  }

  /**
   * Catalog API sources the model library does not cover: `arg` -1 is the return value. Kept
   * equal to the `api` source rules of ../catalog.json.
   */
  predicate apiSourceArgument(string name, int arg) {
    name = "getRequestURI" and arg = -1
    or
    name = "getRequestBody" and arg = -1
    or
    name = "getRequestHeaders" and arg = -1
    or
    name = "readLine" and arg = -1
  }

  /**
   * The type a catalog API sink or source is declared in (matched against `declaredIn`). Kept
   * equal to the `declared_in` of the `api` rules of ../catalog.json.
   */
  predicate apiDeclaringType(string name, string type) {
    name = "exec" and type = "java.lang.Runtime"
    or
    name = "executeQuery" and type = "java.sql.Statement"
    or
    name = "executeUpdate" and type = "java.sql.Statement"
    or
    name = "execute" and type = "java.sql.Statement"
    or
    name = "addBatch" and type = "java.sql.Statement"
    or
    name = "readObject" and type = "java.io.ObjectInputStream"
    or
    name = "readUnshared" and type = "java.io.ObjectInputStream"
    or
    name = "forName" and type = "java.lang.Class"
    or
    name = "loadClass" and type = "java.lang.ClassLoader"
    or
    name = "eval" and type = "javax.script.ScriptEngine"
    or
    name = "getRequestURI" and type = "com.sun.net.httpserver.HttpExchange"
    or
    name = "getRequestBody" and type = "com.sun.net.httpserver.HttpExchange"
    or
    name = "getRequestHeaders" and type = "com.sun.net.httpserver.HttpExchange"
    or
    name = "readLine" and type = "java.io.Console"
  }

  /** Catalog sanitizer APIs. Kept equal to the `sanitizers` of ../catalog.json. */
  predicate sanitizerApi(string name) {
    name = ["getCanonicalPath", "getCanonicalFile", "normalize", "setString", "encodeForHTML"]
  }

  /**
   * The models-as-data sink kinds exported as sink models; `sinkNode(n, kind)` rows of any other
   * kind are not exported. Kept equal to the closed `models_java` sink vocabulary of
   * ../catalog.schema.json.
   */
  predicate sinkModelKind(string kind) {
    kind =
      [
        "sql-injection", "command-injection", "path-injection", "request-forgery",
        "url-redirection", "ldap-injection", "xpath-injection", "template-injection",
        "html-injection", "js-injection", "log-injection", "response-splitting",
        "unsafe-deserialization", "jndi-injection", "mvel-injection", "ognl-injection",
        "groovy-injection", "jexl-injection", "xslt-injection", "fragment-injection"
      ]
  }

  /** `call` targets catalog API `api` declared in its catalog type. */
  predicate apiTarget(Call call, string api) {
    api = call.getCallee().getName() and
    exists(string type |
      apiDeclaringType(api, type) and declaredIn(call.getCallee()).splitAt(",") = type
    )
  }

  /** `operand` is argument `arg` of `call`, or its qualifier when `arg` is -1. */
  predicate callOperand(Call call, Expr operand, int arg) {
    arg >= 0 and operand = call.getArgument(arg)
    or
    arg = -1 and operand = call.getQualifier()
  }

  private predicate apiCallSink(Call call, Expr operand, int arg, string api) {
    apiTarget(call, api) and
    apiSinkArgument(api, arg) and
    callOperand(call, operand, arg)
  }

  /**
   * Model-based sinks; a catalog API match suppresses every model match on the same call. A
   * models-as-data access qualifier (`path-injection[read]`) is dropped: the exported model is
   * the bare kind.
   */
  private predicate modelCallSink(Call call, Expr operand, int arg, string model) {
    not apiTarget(call, _) and
    callOperand(call, operand, arg) and
    sinkModelKind(model) and
    exists(DataFlow::Node n, string kind |
      n.asExpr() = operand and
      sinkNode(n, kind) and
      model = kind.regexpCapture("([a-z-]+)(\\[[a-z-]+\\])?", 1)
    )
  }

  /**
   * A sink candidate: call `sinkExpr` uses `operand` at argument `arg` (-1: the qualifier).
   * `model` is "api" for a catalog API match, otherwise the models-as-data sink kind; `api` is the
   * target's bare name.
   */
  predicate sink(Expr sinkExpr, Expr operand, int arg, string model, string api) {
    inSource(sinkExpr) and
    exportedExpr(sinkExpr) and
    exists(Call call | sinkExpr = call |
      apiCallSink(call, operand, arg, api) and model = "api"
      or
      modelCallSink(call, operand, arg, model) and api = call.getCallee().getName()
    )
  }

  /** The dataflow node that reaches the sink operand. */
  predicate sinkOperandNode(DataFlow::Node n, Expr sinkExpr, int arg) {
    exists(Expr operand | sink(sinkExpr, operand, arg, _, _) | n.asExpr() = operand)
  }

  /**
   * Number of catalog sanitizer calls that strictly dominate `sinkExpr` in its callable (same
   * basic block and earlier, or a dominating block).
   */
  int dominatingSanitizerCount(Expr sinkExpr) {
    result =
      count(Call sanitizer |
        sanitizerApi(sanitizer.getCallee().getName()) and
        sanitizer.getEnclosingCallable() = sinkExpr.getEnclosingCallable() and
        strictlyDominates(sanitizer.(Expr).getControlFlowNode(), sinkExpr.getControlFlowNode())
      )
  }

  /** The CodeQL source class of a modeled flow source node. */
  private string modelClass(SourceNode n) {
    if n instanceof RemoteFlowSource
    then result = "RemoteFlowSource"
    else
      if n instanceof LocalUserInput
      then result = "LocalUserInput"
      else result = "SourceNode"
  }

  /** `getSourceType()` of a remote source, else its threat model (for example "commandargs"). */
  private string sourceTypeOf(SourceNode n) {
    result = n.(RemoteFlowSource).getSourceType()
    or
    not n instanceof RemoteFlowSource and result = n.getThreatModel()
  }

  /**
   * How a source node relates to the code: `kind` is "return_value" of a call to `api` (`index`
   * -1), "parameter" (`index` the parameter position), or "expression".
   */
  private predicate nodeShape(DataFlow::Node n, string kind, string api, int index) {
    exists(Call call | n.asExpr() = call |
      kind = "return_value" and api = call.getCallee().getName() and index = -1
    )
    or
    exists(Parameter p | n.asParameter() = p |
      kind = "parameter" and api = "" and index = p.getPosition()
    )
    or
    not n.asExpr() instanceof Call and
    not exists(n.asParameter()) and
    kind = "expression" and
    api = "" and
    index = -1
  }

  /** The callee whose return value is source node `n`. */
  Callable sourceCallee(DataFlow::Node n) { result = n.asExpr().(Call).getCallee() }

  /**
   * A source candidate: `model` is the CodeQL source class ("api" for a catalog API source the
   * model library does not cover), `sourceType` the remote `getSourceType()` or the threat model
   * ("" for "api"). Every modeled source is exported whatever the active threat model; the
   * catalog decides which source classes are attacker-reachable.
   */
  predicate source(
    DataFlow::Node n, string model, string sourceType, string kind, string api, int index
  ) {
    (inSource(n.asExpr()) or inSource(n.asParameter())) and
    exportedNode(n) and
    (
      model = modelClass(n) and
      sourceType = sourceTypeOf(n) and
      nodeShape(n, kind, api, index)
      or
      not n instanceof SourceNode and
      model = "api" and
      sourceType = "" and
      kind = "return_value" and
      exists(Call call |
        apiTarget(call, api) and apiSourceArgument(api, index) and index = -1 and n.asExpr() = call
      )
    )
  }
}
