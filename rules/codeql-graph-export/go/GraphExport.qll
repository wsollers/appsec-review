/**
 * Shared definitions for the appsec-review Go code-graph export pack.
 *
 * LIVE-UNVERIFIED: written against the `codeql/go-all` library bundled with the pinned CodeQL
 * 2.27.0 CLI, but not compiled in the repository's offline CI. The live tier
 * (tests/live/test_codeql_graph_export_go_live.py) compiles and runs the pack on the pinned image.
 *
 * Export conventions (the column contract is ../columns.json, identical to the cpp pack):
 * - every exported column is a primitive `string` or `int`; no query exports an entity column, so
 *   no database-internal element id leaves the database;
 * - a location is five columns `<p>_path, <p>_start_line, <p>_start_column, <p>_end_line,
 *   <p>_end_column`: the path is relative to the database source root
 *   (`File.getRelativePath()`), lines and columns are 1-based and the end column is inclusive;
 *   an element outside the source root exports path "" and zero positions;
 * - booleans are the strings "true" and "false";
 * - a function is named `Name` (a package function), `Recv::Name` (a method on the receiver base
 *   type `Recv`) or `<enclosing>::func` (a function literal); its location is the defining name
 *   (the `func` keyword of a literal). `declared_in` is the Go package path (`net/http`);
 * - classification into sink and source classes is not done here: rows carry the CodeQL model
 *   identity and the API name, and ../catalog.json classifies them downstream.
 */

import go
import semmle.go.dataflow.ExternalFlow as ExternalFlow

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
  predicate inSource(AstNode e) { exists(e.getLocation().getFile().getRelativePath()) }

  /** Holds when the dataflow node `n` lies inside the database source root. */
  predicate nodeInSource(DataFlow::Node n) {
    exists(n.getLocation().getFile().getRelativePath())
  }

  /** A function (declaration with a body, or a function literal) inside the source root. */
  class SourceFunction extends FuncDef {
    SourceFunction() { inSource(this) and exists(this.getBody()) }
  }

  /** The innermost function definition strictly enclosing the function literal `lit`. */
  private FuncDef outerFunction(FuncLit lit) { result = lit.getEnclosingFunction() }

  /** The export name of `f`: `Name`, `Recv::Name` or `<enclosing>::func`. */
  string functionName(FuncDef f) {
    result = f.(MethodDecl).getReceiverBaseType().getName() + "::" + f.(MethodDecl).getNameExpr().getName()
    or
    not f instanceof MethodDecl and result = f.(FuncDecl).getNameExpr().getName()
    or
    result = functionName(outerFunction(f)) + "::func"
  }

  /** The location of the defining name of `f` (the `func` keyword of a function literal). */
  Location functionLocation(FuncDef f) {
    result = f.(FuncDecl).getNameExpr().getLocation()
    or
    result = f.(FuncLit).getLocation()
  }

  /** The export name of a callee entity: `Name`, or `Recv::Name` for a method. */
  string entityName(Function t) {
    result = t.(Method).getReceiverBaseType().getName() + "::" + t.getName()
    or
    not exists(t.(Method).getReceiverBaseType().getName()) and result = t.getName()
  }

  /** The package path that declares `t`, or "" (a builtin). */
  string packagePath(Function t) {
    result = t.getPackage().getPath()
    or
    not exists(t.getPackage()) and result = ""
  }

  /** The function enclosing a call. */
  FuncDef callFunction(DataFlow::CallNode call) { result = call.getCall().getEnclosingFunction() }

  /** The function enclosing a dataflow node. */
  FuncDef nodeFunction(DataFlow::Node n) { result = n.getRoot() }

  /** Holds in "whole_program" mode, where every function is exported. */
  predicate wholeProgram() { exportScope("whole_program", _) }

  /** The call-graph radius of the neighborhood in "seeded" mode. */
  private int scopeDepth() { exportScope("seeded", result) }

  /** `caller` contains a call that may dispatch to `callee` (static, interface or func value). */
  private predicate callEdge(SourceFunction caller, SourceFunction callee) {
    exists(DataFlow::CallNode call | callFunction(call) = caller | callee = call.getACallee())
  }

  /**
   * `f` is a source-root function whose definition overlaps the seed lines `[startLine, endLine]`
   * of `path`. Every overlapping function matches, so a function literal and the function
   * enclosing it both seed.
   */
  predicate seedMatch(string path, int startLine, int endLine, SourceFunction f) {
    exportSeed(path, startLine, endLine) and
    f.getLocation().getFile().getRelativePath() = path and
    startLine <= f.getLocation().getEndLine() and
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
  predicate exported(FuncDef f) { wholeProgram() or near(f, _) }

  /** The call lies in an exported function. */
  predicate exportedCall(DataFlow::CallNode call) {
    wholeProgram() or exported(callFunction(call))
  }

  /** The dataflow node lies in an exported function. */
  predicate exportedNode(DataFlow::Node n) { wholeProgram() or exported(nodeFunction(n)) }

  /** "true" or "false". */
  bindingset[b]
  string flag(boolean b) { b = true and result = "true" or b = false and result = "false" }

  /** `call` calls the package function `pkg.name`. */
  predicate apiCall(DataFlow::CallNode call, string pkg, string name) {
    call.getTarget().hasQualifiedName(pkg, name)
  }

  /**
   * Catalog API sinks: package `pkg` function `name` and the dangerous argument `arg`
   * (-1: the call expression itself). Kept equal to the `api` sink rules of ../catalog.json by
   * tests/graph/test_go_export.py. Only APIs that codeql/go-all has no sink model for.
   */
  predicate apiSinkArgument(string pkg, string name, int arg) {
    pkg = "encoding/gob" and name = "NewDecoder" and arg = 0
    or
    pkg = "net" and name = "Dial" and arg = 1
    or
    pkg = "syscall" and name = "Exec" and arg = 0
    or
    pkg = "math/rand" and name = "Intn" and arg = -1
    or
    pkg = "strings" and name = "Repeat" and arg = 1
  }

  /**
   * Catalog API sources: `arg` -1 is the first return value. Kept equal to the `api` source
   * rules of ../catalog.json.
   */
  predicate apiSourceArgument(string pkg, string name, int arg) {
    pkg = "syscall" and name = "Getenv" and arg = -1
  }

  /** Catalog sanitizer APIs. Kept equal to the `sanitizers` of ../catalog.json. */
  predicate sanitizerApi(string pkg, string name) {
    pkg = "path/filepath" and name = "Clean"
    or
    pkg = "path/filepath" and name = "Rel"
    or
    pkg = "path/filepath" and name = "EvalSymlinks"
    or
    pkg = "path/filepath" and name = "Base"
    or
    pkg = "regexp" and name = "QuoteMeta"
    or
    pkg = "html" and name = "EscapeString"
  }

  /** `call` is a catalog sanitizer call to `api`. */
  predicate sanitizerCall(DataFlow::CallNode call, string api) {
    exists(string pkg | apiCall(call, pkg, api) and sanitizerApi(pkg, api))
  }

  /** `operand` is syntactic argument `arg` of `call`. */
  predicate argumentOperand(DataFlow::CallNode call, Expr operand, int arg) {
    operand = call.getSyntacticArgument(arg).asExpr()
  }

  /** The API name of the target of `call`, or "" when CodeQL resolves no target. */
  string calleeApi(DataFlow::CallNode call) {
    result = call.getTarget().getName()
    or
    not exists(call.getTarget()) and result = ""
  }

  /** The package path declaring the target of `call`, or "". */
  string declaredIn(DataFlow::CallNode call) {
    result = packagePath(call.getTarget())
    or
    not exists(call.getTarget()) and result = ""
  }

  private predicate apiSinkCall(DataFlow::CallNode call) {
    exists(string pkg, string name | apiCall(call, pkg, name) and apiSinkArgument(pkg, name, _))
  }

  private predicate apiCallSink(DataFlow::CallNode call, Expr operand, int arg, string api) {
    exists(string pkg |
      apiCall(call, pkg, api) and
      apiSinkArgument(pkg, api, arg)
    |
      arg >= 0 and argumentOperand(call, operand, arg)
      or
      arg = -1 and operand = call.getCall()
    )
  }

  /**
   * Concept and model sinks of codeql/go-all (the concepts subsume the models-as-data sink kinds
   * `sql-injection`, `command-injection`, `path-injection` and `url-redirection`). The model is
   * the concept class; the operand is the syntactic call argument the concept names.
   */
  private predicate modelOperand(DataFlow::CallNode call, Expr operand, int arg, string model) {
    argumentOperand(call, operand, arg) and
    (
      exists(SQL::QueryString q | q.asExpr() = operand) and model = "SQL::QueryString"
      or
      exists(SystemCommandExecution e | e.getCommandName().asExpr() = operand) and
      model = "SystemCommandExecution"
      or
      exists(FileSystemAccess a | a.getAPathArgument().asExpr() = operand) and
      model = "FileSystemAccess"
      or
      exists(Http::ClientRequest r | r.getUrl().asExpr() = operand) and
      model = "Http::ClientRequest"
      or
      exists(Http::Redirect r | r.getUrl().asExpr() = operand) and model = "Http::Redirect"
      or
      exists(Http::HeaderWrite h | h.getValue().asExpr() = operand) and
      model = "Http::HeaderWrite"
      or
      exists(Http::ResponseBody b | b.asExpr() = operand) and model = "Http::ResponseBody"
      or
      exists(LoggerCall l | l.getAMessageComponent().asExpr() = operand) and model = "LoggerCall"
      or
      exists(UnmarshalingFunction f, FunctionInput input |
        call.getTarget() = f and input = f.getAnInput() and input.isParameter(arg)
      ) and
      model = "UnmarshalingFunction"
    )
  }

  /**
   * A sink candidate: `call` uses `operand` at argument `arg` (-1 when the operand is the call
   * itself). `model` is "api" for a catalog API match, otherwise the codeql/go-all concept;
   * `api` is the target's name ("" when unresolved). A catalog API match suppresses every model
   * match on the same call.
   */
  predicate sink(DataFlow::CallNode call, Expr operand, int arg, string model, string api) {
    nodeInSource(call) and
    exportedCall(call) and
    (
      apiCallSink(call, operand, arg, api) and model = "api"
      or
      not apiSinkCall(call) and
      modelOperand(call, operand, arg, model) and
      api = calleeApi(call)
    )
  }

  /** The location of the sink call expression. */
  Location sinkLocation(DataFlow::CallNode call) { result = call.getCall().getLocation() }

  /** The dataflow node that reaches the sink operand. */
  predicate sinkNode(DataFlow::Node n, DataFlow::CallNode call, int arg) {
    exists(Expr operand | sink(call, operand, arg, _, _) | n.asExpr() = operand)
  }

  /** `a` comes before `b` in the same basic block. */
  private predicate earlierInBlock(DataFlow::CallNode a, DataFlow::CallNode b) {
    exists(BasicBlock bb, int i, int j |
      bb.getNode(i) = a.asInstruction() and bb.getNode(j) = b.asInstruction() and i < j
    )
  }

  /** Number of catalog sanitizer calls that dominate the sink `call` in its function. */
  int dominatingSanitizerCount(DataFlow::CallNode call) {
    result =
      count(DataFlow::CallNode sanitizer |
        sanitizerCall(sanitizer, _) and
        callFunction(sanitizer) = callFunction(call) and
        sanitizer != call and
        (
          sanitizer.getBasicBlock().strictlyDominates(call.getBasicBlock())
          or
          earlierInBlock(sanitizer, call)
        )
      )
  }

  /**
   * How a source node relates to the code: `kind` is "return_value" of a call to `api`
   * (`index` -1), "parameter" (`index` the parameter position), or "expression" (a field or
   * variable read such as `os.Args` or `r.Body`).
   */
  private predicate nodeShape(
    DataFlow::Node n, string kind, string api, string declared, int index
  ) {
    exists(DataFlow::CallNode call | n = call.getAResult() |
      kind = "return_value" and api = calleeApi(call) and declared = declaredIn(call) and index = -1
    )
    or
    exists(FuncDef f, int i | n.asParameter() = f.getParameter(i) |
      kind = "parameter" and api = "" and declared = "" and index = i
    )
    or
    not n = any(DataFlow::CallNode call).getAResult() and
    not exists(n.asParameter()) and
    kind = "expression" and
    api = "" and
    declared = "" and
    index = -1
  }

  /**
   * A source candidate. `model` is "RemoteFlowSource" (`sourceType` "remote"), "sourceModel"
   * (a models-as-data source; `sourceType` its threat-model kind such as "commandargs",
   * "environment", "file", "stdin" or "database"), "SourceNode" (any other threat-model source;
   * `sourceType` its threat model) or "api" (a catalog API source the model library does not
   * cover; `sourceType` "").
   */
  predicate source(
    DataFlow::Node n, string model, string sourceType, string kind, string api, string declared,
    int index
  ) {
    nodeInSource(n) and
    exportedNode(n) and
    (
      n instanceof RemoteFlowSource and
      model = "RemoteFlowSource" and
      sourceType = "remote" and
      nodeShape(n, kind, api, declared, index)
      or
      not n instanceof RemoteFlowSource and
      ExternalFlow::sourceNode(n, sourceType) and
      model = "sourceModel" and
      nodeShape(n, kind, api, declared, index)
      or
      not n instanceof RemoteFlowSource and
      not ExternalFlow::sourceNode(n, _) and
      sourceType = n.(SourceNode).getThreatModel() and
      model = "SourceNode" and
      nodeShape(n, kind, api, declared, index)
      or
      not n instanceof RemoteFlowSource and
      not ExternalFlow::sourceNode(n, _) and
      not n instanceof SourceNode and
      model = "api" and
      sourceType = "" and
      exists(DataFlow::CallNode call, string pkg |
        apiCall(call, pkg, api) and apiSourceArgument(pkg, api, index)
      |
        index = -1 and
        n = call.getResult(0) and
        kind = "return_value" and
        declared = pkg
      )
    )
  }

  /** The function enclosing a dataflow node, or "" when it lies outside every function. */
  string nodeFunctionName(DataFlow::Node n) {
    result = functionName(nodeFunction(n))
    or
    not exists(nodeFunction(n)) and result = ""
  }
}
