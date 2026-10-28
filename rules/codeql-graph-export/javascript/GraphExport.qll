/**
 * Shared definitions for the appsec-review JavaScript/TypeScript code-graph export pack.
 *
 * LIVE-UNVERIFIED: written against the `codeql/javascript-all` library bundled with the pinned
 * CodeQL 2.27.0 CLI, but not compiled in the repository's offline CI. The live tier
 * (tests/live/test_codeql_graph_export_javascript_live.py) compiles and runs the pack on the
 * pinned image.
 *
 * Export conventions (the column contract is ../columns.json, `languages.javascript`):
 * - every exported column is a primitive `string` or `int`; no query exports an entity column, so
 *   no database-internal element id leaves the database;
 * - a location is five columns `<p>_path, <p>_start_line, <p>_start_column, <p>_end_line,
 *   <p>_end_column`: the path is relative to the database source root
 *   (`File.getRelativePath()`), lines and columns are 1-based and the end column is inclusive;
 *   an element outside the source root exports path "" and zero positions;
 * - booleans are the strings "true" and "false";
 * - a "function" is a statement container with a body: a function, method, arrow function or
 *   constructor, or a file's top level ("<toplevel>"). Its exported location is its defining
 *   name (method name, function identifier), else the container's own location;
 * - classification into sink and source classes is not done here: rows carry the CodeQL model
 *   identity and the API name, and ../catalog.json classifies them downstream.
 */

import javascript
import semmle.javascript.security.dataflow.SqlInjectionCustomizations
import semmle.javascript.security.dataflow.CommandInjectionCustomizations
import semmle.javascript.security.dataflow.TaintedPathCustomizations
import semmle.javascript.security.dataflow.RequestForgeryCustomizations
import semmle.javascript.security.dataflow.CodeInjectionCustomizations
import semmle.javascript.security.dataflow.UnsafeDeserializationCustomizations
import semmle.javascript.security.dataflow.ReflectedXssCustomizations
import semmle.javascript.security.dataflow.ServerSideUrlRedirectCustomizations
import semmle.javascript.security.dataflow.XxeCustomizations
import semmle.javascript.security.dataflow.XpathInjectionCustomizations
import semmle.javascript.security.dataflow.RegExpInjectionCustomizations

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
  predicate inSource(Locatable e) { exists(e.getLocation().getFile().getRelativePath()) }

  /** Holds when the dataflow node `n` lies inside the database source root. */
  predicate inSourceNode(DataFlow::Node n) { exists(n.getLocation().getFile().getRelativePath()) }

  /**
   * A source-root function with a body (function, method, arrow function, constructor) or a
   * non-externs file top level.
   */
  class SourceFunction extends StmtContainer {
    SourceFunction() {
      exists(this.getFile().getRelativePath()) and
      (
        exists(this.(Function).getBody())
        or
        this instanceof TopLevel and not this.(TopLevel).isExterns()
      )
    }

    /** `Class::method` for a class member, the function's (inferred) name, or a placeholder. */
    string getQualifiedName() {
      exists(MethodDeclaration m | m.getBody() = this |
        exists(string owner |
          owner = m.getDeclaringType().getName()
          or
          not exists(m.getDeclaringType().getName()) and owner = "<anonymous>"
        |
          result = owner + "::" + m.getName()
          or
          not exists(m.getName()) and result = owner + "::<computed>"
        )
      )
      or
      not this = any(MethodDeclaration m).getBody() and
      (
        result = this.(Function).getName()
        or
        this instanceof Function and
        not exists(this.(Function).getName()) and
        result = "<anonymous>"
        or
        this instanceof TopLevel and result = "<toplevel>"
      )
    }

    /** The location of the defining name: method name, function identifier, else the container. */
    Location getNameLocation() {
      exists(MethodDeclaration m | m.getBody() = this | result = m.getNameExpr().getLocation())
      or
      not this = any(MethodDeclaration m).getBody() and
      (
        result = this.(Function).getIdentifier().getLocation()
        or
        not exists(this.(Function).getIdentifier()) and result = this.getLocation()
      )
    }
  }

  /** Holds in "whole_program" mode, where every function is exported. */
  predicate wholeProgram() { exportScope("whole_program", _) }

  /** The call-graph radius of the neighborhood in "seeded" mode. */
  private int scopeDepth() { exportScope("seeded", result) }

  /** Every source-root function CodeQL's JavaScript call graph resolves `call` to. */
  SourceFunction callTarget(DataFlow::InvokeNode call) { result = call.getACallee() }

  /** `caller` contains a call that may invoke `callee`. */
  private predicate callEdge(SourceFunction caller, SourceFunction callee) {
    exists(DataFlow::InvokeNode call | call.getContainer() = caller | callee = callTarget(call))
  }

  /** `f`'s line span overlaps the seed lines `[startLine, endLine]` of `path`. */
  private predicate overlaps(string path, int startLine, int endLine, SourceFunction f) {
    exportSeed(path, startLine, endLine) and
    f.getFile().getRelativePath() = path and
    startLine <= f.getLocation().getEndLine() and
    endLine >= f.getLocation().getStartLine()
  }

  /**
   * `f` is a source-root function whose span overlaps the seed lines `[startLine, endLine]` of
   * `path`. Every overlapping function matches, so a callback and the function enclosing it both
   * seed. A file top level seeds only when no function of that file overlaps the seed lines.
   */
  predicate seedMatch(string path, int startLine, int endLine, SourceFunction f) {
    overlaps(path, startLine, endLine, f) and
    (
      f instanceof Function
      or
      f instanceof TopLevel and
      not exists(SourceFunction g | overlaps(path, startLine, endLine, g) and g instanceof Function)
    )
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
  predicate exported(StmtContainer f) { wholeProgram() or near(f, _) }

  /** `e` lies in an exported function. */
  predicate exportedExpr(Expr e) { wholeProgram() or exported(e.getContainer()) }

  /** The dataflow node lies in an exported function. */
  predicate exportedNode(DataFlow::Node n) { wholeProgram() or exported(n.getContainer()) }

  /** The name of the function `n` lies in, or "" outside a source-root function. */
  string containerName(DataFlow::Node n) {
    result = n.getContainer().(SourceFunction).getQualifiedName()
    or
    not n.getContainer() instanceof SourceFunction and result = ""
  }

  /**
   * `call` invokes a member of, or the value of, module `m` (an `import`/`require` of an npm or
   * Node.js module), a member of the global object `m` (`Math`, `JSON`, `console`, ...), or a
   * global function (`m` = "global"). This is the catalog `declared_in` of external APIs.
   */
  predicate importedFrom(DataFlow::InvokeNode call, string m) {
    call = DataFlow::moduleMember(m, _).getAnInvocation()
    or
    call = DataFlow::moduleImport(m).getAMemberInvocation(_)
    or
    call = DataFlow::moduleImport(m).getAnInvocation()
    or
    call = DataFlow::globalVarRef(m).getAMemberInvocation(_)
    or
    exists(string name | call = DataFlow::globalVarRef(name).getAnInvocation()) and m = "global"
  }

  /** Comma-joined sorted modules `call` is imported from (the catalog `declared_in`), or "". */
  string declaredIn(DataFlow::InvokeNode call) {
    result = concat(string m | importedFrom(call, m) | m, "," order by m)
  }

  /** The callee name of `call` (the property name of a method call), or "". */
  string calleeName(DataFlow::InvokeNode call) {
    result = call.getCalleeName()
    or
    not exists(call.getCalleeName()) and result = ""
  }

  /** "true" or "false". */
  bindingset[b]
  string flag(boolean b) { b = true and result = "true" or b = false and result = "false" }

  /**
   * Catalog API sinks: callee `name` and the dangerous argument `arg` (-1: the call itself).
   * The call must be imported from `apiModule(name, _)`. Kept equal to the `api` sink rules of
   * ../catalog.json by tests/graph/test_javascript_export.py.
   */
  predicate apiSinkArgument(string name, int arg) {
    name = "unserialize" and arg = 0
    or
    name = "log" and arg = 0
    or
    name = "info" and arg = 0
    or
    name = "warn" and arg = 0
    or
    name = "error" and arg = 0
    or
    name = "random" and arg = -1
  }

  /**
   * Catalog API sources: callee `name`, `arg` -1 the return value. The call must be imported
   * from `apiModule(name, _)`. Kept equal to the `api` source rules of ../catalog.json.
   */
  predicate apiSourceArgument(string name, int arg) {
    name = "question" and arg = -1
    or
    name = "prompt" and arg = -1
  }

  /** The module (or global object) a catalog API sink or source is imported from. */
  predicate apiModule(string name, string m) {
    name = "unserialize" and m = "node-serialize"
    or
    name = ["log", "info", "warn", "error"] and m = "console"
    or
    name = "random" and m = "Math"
    or
    name = ["question", "prompt"] and m = "readline-sync"
  }

  /** Catalog sanitizer APIs. Kept equal to the `sanitizers` of ../catalog.json. */
  predicate sanitizerApi(string name) {
    name = ["basename", "escape", "escapeId", "encodeURIComponent"]
  }

  /** `call` is a catalog API call: callee `api` imported from its catalog module. */
  private predicate apiCall(DataFlow::InvokeNode call, string api) {
    api = call.getCalleeName() and
    exists(string m | apiModule(api, m) and importedFrom(call, m))
  }

  private predicate apiCallSink(
    DataFlow::InvokeNode call, DataFlow::Node operand, int arg, string api
  ) {
    apiCall(call, api) and
    apiSinkArgument(api, arg) and
    (
      arg >= 0 and operand = call.getArgument(arg)
      or
      arg = -1 and operand = call
    )
  }

  /** The javascript-all sink model class `n` belongs to. */
  private predicate modelSink(DataFlow::Node n, string model) {
    n instanceof SqlInjection::Sink and model = "SqlInjection::Sink"
    or
    n instanceof CommandInjection::Sink and model = "CommandInjection::Sink"
    or
    n instanceof TaintedPath::Sink and model = "TaintedPath::Sink"
    or
    n instanceof RequestForgery::Sink and model = "RequestForgery::Sink"
    or
    n instanceof CodeInjection::Sink and model = "CodeInjection::Sink"
    or
    n instanceof UnsafeDeserialization::Sink and model = "UnsafeDeserialization::Sink"
    or
    n instanceof ReflectedXss::Sink and model = "ReflectedXss::Sink"
    or
    n instanceof ServerSideUrlRedirect::Sink and model = "ServerSideUrlRedirect::Sink"
    or
    n instanceof Xxe::Sink and model = "Xxe::Sink"
    or
    n instanceof XpathInjection::Sink and model = "XpathInjection::Sink"
    or
    n instanceof RegExpInjection::Sink and model = "RegExpInjection::Sink"
  }

  /**
   * Model-based sinks. A modeled operand that is argument `arg` of a call reports the call as
   * the sink expression; any other modeled node is its own sink expression (`arg` -1, `api` "").
   * A catalog API match suppresses every model match on the same call.
   */
  private predicate modelCallSink(
    DataFlow::Node sinkNode, DataFlow::Node operand, int arg, string model, string api
  ) {
    modelSink(operand, model) and
    (
      exists(DataFlow::InvokeNode call | operand = call.getArgument(arg) |
        sinkNode = call and api = calleeName(call) and not apiCallSink(call, _, _, _)
      )
      or
      not operand = any(DataFlow::InvokeNode call).getAnArgument() and
      sinkNode = operand and
      arg = -1 and
      api = ""
    )
  }

  /**
   * A sink candidate: `sinkNode` (a call, or the modeled node itself) uses `operand` at argument
   * `arg` (-1 when the operand is not a call argument). `model` is "api" for a catalog API match,
   * otherwise the javascript-all sink model; `api` is the callee name ("" for a non-call sink).
   */
  predicate sink(
    DataFlow::Node sinkNode, DataFlow::Node operand, int arg, string model, string api
  ) {
    inSourceNode(sinkNode) and
    exportedNode(sinkNode) and
    (
      apiCallSink(sinkNode, operand, arg, api) and model = "api"
      or
      modelCallSink(sinkNode, operand, arg, model, api)
    )
  }

  /** The dataflow node that reaches the sink operand. */
  predicate sinkNode(DataFlow::Node n, DataFlow::Node sinkNode, int arg) {
    sink(sinkNode, n, arg, _, _)
  }

  /** `sinkNode`'s `declared_in`: the modules of a sink call, "" for a non-call sink. */
  string sinkDeclaredIn(DataFlow::Node sinkNode) {
    result = declaredIn(sinkNode)
    or
    not sinkNode instanceof DataFlow::InvokeNode and result = ""
  }

  /** The control-flow node `a` is evaluated before `b` on every path to `b`. */
  predicate cfgDominates(ControlFlowNode a, ControlFlowNode b) {
    exists(ReachableBasicBlock ba, ReachableBasicBlock bb, int i, int j |
      ba.getNode(i) = a and bb.getNode(j) = b
    |
      ba.strictlyDominates(bb)
      or
      ba = bb and i < j
    )
  }

  /** A catalog sanitizer call (callee name in `sanitizerApi`). */
  predicate sanitizerCall(DataFlow::InvokeNode call, string api) {
    api = call.getCalleeName() and sanitizerApi(api)
  }

  /** Number of catalog sanitizer calls that dominate `sinkNode` in its function. */
  int dominatingSanitizerCount(DataFlow::Node sinkNode) {
    result =
      count(DataFlow::InvokeNode sanitizer |
        sanitizerCall(sanitizer, _) and
        sanitizer.getContainer() = sinkNode.getContainer() and
        cfgDominates(sanitizer.asExpr(), sinkNode.asExpr()) and
        sanitizer != sinkNode
      )
  }

  /** The threat models exported with their own model name; others export "ThreatModelSource". */
  private predicate namedThreatModel(string tm) {
    tm = ["commandargs", "environment", "response", "file", "database", "stdin"]
  }

  /** The model identity of a modeled flow source node. */
  private string modelClass(ThreatModelSource n) {
    if n instanceof RemoteFlowSource
    then result = "RemoteFlowSource"
    else
      if namedThreatModel(n.getThreatModel())
      then result = "ThreatModelSource." + n.getThreatModel()
      else result = "ThreatModelSource"
  }

  /** The 0-based position of parameter node `n` in its function. */
  private int parameterIndex(DataFlow::ParameterNode n) {
    exists(Function f | f.getParameter(result) = n.getParameter())
  }

  /**
   * How a source node relates to the code: `kind` is "return_value" of a call to `api`
   * (`index` -1), "parameter" (`index` the parameter position), or "expression".
   */
  private predicate nodeShape(DataFlow::Node n, string kind, string api, int index) {
    n instanceof DataFlow::InvokeNode and
    kind = "return_value" and
    api = calleeName(n) and
    index = -1
    or
    n instanceof DataFlow::ParameterNode and
    kind = "parameter" and
    api = "" and
    index = parameterIndex(n)
    or
    not n instanceof DataFlow::InvokeNode and
    not n instanceof DataFlow::ParameterNode and
    kind = "expression" and
    api = "" and
    index = -1
  }

  /**
   * A source candidate: `model` is the javascript-all model ("api" for a catalog API source the
   * model library does not cover), `sourceType` CodeQL's `getSourceType()` ("" for "api").
   */
  predicate source(
    DataFlow::Node n, string model, string sourceType, string kind, string api, int index
  ) {
    inSourceNode(n) and
    exportedNode(n) and
    (
      model = modelClass(n) and
      sourceType = n.(ThreatModelSource).getSourceType() and
      nodeShape(n, kind, api, index)
      or
      not n instanceof ThreatModelSource and
      model = "api" and
      sourceType = "" and
      kind = "return_value" and
      apiCall(n, api) and
      apiSourceArgument(api, index) and
      index = -1
    )
  }

  /** A source node's `declared_in`: the modules of a call source, else "". */
  string sourceDeclaredIn(DataFlow::Node n) {
    result = declaredIn(n)
    or
    not n instanceof DataFlow::InvokeNode and result = ""
  }
}
