/**
 * Shared definitions for the appsec-review Rust code-graph export pack.
 *
 * LIVE-UNVERIFIED: written against the `codeql/rust-all` 0.2.21 library bundled with the pinned
 * CodeQL 2.27.0 CLI, but not compiled in the repository's offline CI. The live tier
 * (tests/live/test_codeql_graph_export_rust_live.py) compiles and runs the pack on the pinned
 * image.
 *
 * Export conventions (the column contract is ../columns.json, language `rust`):
 * - every exported column is a primitive `string` or `int`; no query exports an entity column, so
 *   no database-internal element id leaves the database;
 * - a location is five columns `<p>_path, <p>_start_line, <p>_start_column, <p>_end_line,
 *   <p>_end_column`: the path is relative to the database source root
 *   (`File.getRelativePath()`), lines and columns are 1-based and the end column is inclusive;
 *   an element outside the source root (the standard library, registry crates) exports path ""
 *   and zero positions;
 * - a function is named by its canonical path (`Addressable.getCanonicalPath()`, for example
 *   `crate::module::name` or `<crate::Type as crate::Trait>::name`) and located at its name
 *   (`Function.getName().getLocation()`);
 * - booleans are the strings "true" and "false";
 * - classification into sink and source classes is not done here: rows carry the models-as-data
 *   kind (or "api") and the API name, and ../catalog.json classifies them downstream.
 *
 * Named gaps of codeql/rust-all 0.2.21 that this pack reports instead of approximating:
 * - no range analysis library: Ranges.ql exports applicability "not_applicable" for every sink
 *   and range_conversions has no rows;
 * - no models-as-data sink kind for deserialization: the `apiSinkArgument` rules cover serde
 *   entry points by name;
 * - the run-time targets of closure and function-value calls are internal to the dataflow
 *   library: such calls export as `unresolved_indirect`.
 */

import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.FlowSink
import codeql.rust.Concepts
import codeql.rust.controlflow.BasicBlocks
import codeql.rust.controlflow.ControlFlowGraph
private import codeql.rust.dataflow.internal.Node as N
private import codeql.rust.dataflow.internal.TaintTrackingImpl as TT
private import codeql.rust.dataflow.internal.FlowSummaryImpl as FS

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

  /** A function with a body inside the source root (vendored path dependencies included). */
  class SourceFunction extends Function {
    SourceFunction() { exists(this.getFunctionBody()) and inSource(this) }
  }

  /** The export location of `f`: its name. */
  Location functionLocation(Function f) { result = f.getName().getLocation() }

  /** The export name of `f`: its canonical path, else its plain name. */
  string functionName(Function f) {
    result = min(f.getCanonicalPath())
    or
    not exists(f.getCanonicalPath()) and result = f.getName().getText()
  }

  /** `owner` without `<...>` and without a trailing ` as Trait`. */
  bindingset[owner]
  private string ownerType(string owner) {
    if owner.matches("<%>")
    then
      exists(string inner | inner = owner.substring(1, owner.length() - 1) |
        if inner.indexOf(" as ") >= 0
        then result = inner.prefix(inner.indexOf(" as "))
        else result = inner
      )
    else result = owner
  }

  /**
   * The module or type that declares `f` (the catalog `declared_in`): the canonical path without
   * its last segment, for example `std::fs` or `std::process::Command`; "" when unknown.
   */
  string declaredIn(Function f) {
    exists(string path, string name, int cut |
      path = functionName(f) and
      name = f.getName().getText() and
      cut = path.length() - name.length() - 2 and
      cut > 0 and
      path.suffix(cut) = "::" + name
    |
      result = ownerType(path.prefix(cut))
    )
    or
    not exists(string path, string name, int cut |
      path = functionName(f) and
      name = f.getName().getText() and
      cut = path.length() - name.length() - 2 and
      cut > 0 and
      path.suffix(cut) = "::" + name
    ) and
    result = ""
  }

  /** The function that encloses `n`, looking through closures to their defining function. */
  Function enclosingFunction(AstNode n) {
    result = n.getEnclosingCallable()
    or
    result = enclosingFunction(n.getEnclosingCallable().(ClosureExpr))
  }

  /** The function of a CFG scope (a function, or the function defining a closure). */
  Function scopeFunction(CfgScope s) {
    result = s
    or
    result = enclosingFunction(s.(ClosureExpr))
  }

  /** The function of the CFG scope of dataflow node `n`. */
  Function nodeFunction(DataFlow::Node n) { result = scopeFunction(n.(N::Node).getCfgScope()) }

  /** The export name of the function of `n`, "" when it has none. */
  string nodeFunctionName(DataFlow::Node n) {
    result = functionName(nodeFunction(n))
    or
    not exists(nodeFunction(n)) and result = ""
  }

  /** Holds when `a` and `b` lie in the same CFG scope (function or closure body). */
  predicate sameCallable(DataFlow::Node a, DataFlow::Node b) {
    a.(N::Node).getCfgScope() = b.(N::Node).getCfgScope()
  }

  /**
   * One local (intra-procedural) taint step: a local dataflow step (which includes simple
   * value-preserving models-as-data summaries), the library's default additional taint step,
   * or a step through a models-as-data taint summary (`to_string`, `clone`, `canonicalize`).
   * codeql/rust-all 0.2.21 exports no `TaintTracking::localTaint`; the summary steps are the
   * ones the shared library provides for exposed local taint relations.
   */
  predicate localTaintStep(DataFlow::Node a, DataFlow::Node b) {
    DataFlow::localFlowStep(a, b)
    or
    TT::RustTaintTracking::defaultAdditionalTaintStep(a, b, _) and sameCallable(a, b)
    or
    FS::Private::Steps::summaryThroughStepTaint(a, b, _)
    or
    FS::Private::Steps::summaryGetterStep(a, _, b, _)
  }

  /** Local taint in zero or more steps. */
  predicate localTaint(DataFlow::Node a, DataFlow::Node b) { localTaintStep*(a, b) }

  /** Holds in "whole_program" mode, where every function is exported. */
  predicate wholeProgram() { exportScope("whole_program", _) }

  /** The call-graph radius of the neighborhood in "seeded" mode. */
  private int scopeDepth() { exportScope("seeded", result) }

  /** A call the export publishes: a call expression (not a tuple struct/variant) or a method call. */
  class ExportCall extends Call {
    ExportCall() { this instanceof CallExpr or this instanceof MethodCallExpr }
  }

  /**
   * A call to a closure or a function value: the callee is not a path, or is a path to a local
   * variable (mirrors the library's internal `DynamicCallExpr`).
   */
  predicate dynamicCall(CallExpr call) {
    exists(Expr f | f = call.getFunction() |
      f instanceof PathExpr implies f = any(Variable v).getAnAccess()
    )
  }

  /** Every implementation a trait-method call may dispatch to, when there is more than one. */
  Function virtualCandidate(ExportCall call) {
    result = call.getARuntimeTarget() and
    strictcount(call.getARuntimeTarget()) > 1
  }

  /** `caller` contains a call to `callee`, directly or as a trait-dispatch candidate. */
  private predicate callEdge(SourceFunction caller, SourceFunction callee) {
    exists(ExportCall call | enclosingFunction(call) = caller |
      callee = call.getStaticTarget()
      or
      callee = call.getARuntimeTarget()
    )
  }

  private int functionStartLine(SourceFunction f) { result = f.getLocation().getStartLine() }

  private int functionEndLine(SourceFunction f) {
    result = f.getFunctionBody().getLocation().getEndLine()
  }

  /**
   * `f` is a source-root function whose definition (`fn` through closing brace) overlaps the seed
   * lines `[startLine, endLine]` of `path`. Every overlapping function matches.
   */
  predicate seedMatch(string path, int startLine, int endLine, SourceFunction f) {
    exportSeed(path, startLine, endLine) and
    f.getLocation().getFile().getRelativePath() = path and
    startLine <= functionEndLine(f) and
    endLine >= functionStartLine(f)
  }

  /** A function that contains finding lines (a seed). */
  predicate seedFunction(SourceFunction f) { seedMatch(_, _, _, f) }

  /**
   * `f` is within `distance` call-graph steps of a seed function, following call edges in either
   * direction. The recursion is monotone and bounded by the scope depth; take the minimum for
   * the shortest.
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
  predicate exported(Function f) { wholeProgram() or near(f, _) }

  /** `e` lies in an exported function, or anywhere in "whole_program" mode. */
  predicate exportedExpr(Expr e) { wholeProgram() or exported(enclosingFunction(e)) }

  /** The dataflow node lies in an exported function. */
  predicate exportedNode(DataFlow::Node n) {
    wholeProgram() or exported(scopeFunction(n.(N::Node).getCfgScope()))
  }

  /** "true" or "false". */
  bindingset[b]
  string flag(boolean b) { b = true and result = "true" or b = false and result = "false" }

  /**
   * Catalog API sinks the model library does not cover: function `name` declared in module
   * `declared` and the dangerous argument `arg`. Kept equal to the `api` sink rules of
   * ../catalog.json by tests/graph/test_rust_export.py.
   */
  predicate apiSinkArgument(string name, int arg) {
    name = "from_str" and arg = 0
    or
    name = "from_slice" and arg = 0
    or
    name = "from_reader" and arg = 0
    or
    name = "deserialize" and arg = 0
  }

  /** The modules whose `apiSinkArgument` functions are catalog sinks. */
  predicate apiSinkModule(string declared) {
    declared = ["serde_json", "serde_json::de", "serde_yaml", "serde_yaml::de", "bincode"]
  }

  /**
   * Catalog API sources the model library does not cover: `arg` -1 is the return value. Kept
   * equal to the `api` source rules of ../catalog.json.
   */
  predicate apiSourceArgument(string name, int arg) {
    name = "accept" and arg = -1
    or
    name = "recv_from" and arg = -1
  }

  /** The types whose `apiSourceArgument` methods are catalog sources. */
  predicate apiSourceModule(string declared) {
    declared = ["std::net::tcp::TcpListener", "std::net::udp::UdpSocket"]
  }

  /** Catalog sanitizer APIs. Kept equal to the `sanitizers` of ../catalog.json. */
  predicate sanitizerApi(string name) { name = ["canonicalize"] }

  /**
   * The models-as-data sink kinds this pack exports. Kept equal to the `model` sink rules of
   * ../catalog.json and the `models_rust` schema vocabulary.
   */
  predicate sinkModelKind(string kind) {
    kind =
      [
        "sql-injection", "command-injection", "path-injection", "request-url", "log-injection",
        "html-injection", "alloc-size", "alloc-layout", "pointer-access", "disable-certificate",
        "hasher-input", "credentials-key", "credentials-iv", "credentials-nonce"
      ]
  }

  /** The name of the static target of `call`. */
  string targetName(Call call) { result = call.getStaticTarget().getName().getText() }

  /** The `declared_in` of the static target of `call`, "" when it has none. */
  string targetDeclaredIn(Call call) {
    result = declaredIn(call.getStaticTarget())
    or
    not exists(call.getStaticTarget()) and result = ""
  }

  /** `operand` is argument `arg` of `call` (-1: the method receiver). */
  predicate callOperand(Call call, Expr operand, int arg) {
    operand = call.getPositionalArgument(arg)
    or
    operand = call.(MethodCall).getReceiver() and arg = -1
  }

  private predicate apiCallSink(Call call, Expr operand, int arg, string api) {
    api = targetName(call) and
    apiSinkArgument(api, arg) and
    apiSinkModule(targetDeclaredIn(call)) and
    callOperand(call, operand, arg)
  }

  /**
   * Model-based sinks: a models-as-data sink node whose reporting element is an argument of
   * `call`. A catalog API match suppresses every model match on the same call.
   */
  private predicate modelCallSink(Call call, Expr operand, int arg, string model) {
    not apiCallSink(call, _, _, _) and
    sinkModelKind(model) and
    exists(N::FlowSummaryNode n |
      sinkNode(n, model) and
      n.getSummaryNode().getSourceSinkReportingElement() = operand
    ) and
    callOperand(call, operand, arg)
  }

  /**
   * A sink candidate: `sinkExpr` (a call) uses `operand` at argument `arg` (-1: the receiver).
   * `model` is "api" for a catalog API match, otherwise the models-as-data sink kind; `api` is
   * the target's name ("" when the target is unresolved).
   */
  predicate sink(Expr sinkExpr, Expr operand, int arg, string model, string api) {
    inSource(sinkExpr) and
    exportedExpr(sinkExpr) and
    exists(Call call | sinkExpr = call |
      apiCallSink(call, operand, arg, api) and model = "api"
      or
      modelCallSink(call, operand, arg, model) and
      (api = targetName(call) or not exists(targetName(call)) and api = "")
    )
  }

  /** The dataflow node of the sink operand (the argument expression). */
  predicate sinkOperandNode(DataFlow::Node n, Expr sinkExpr, int arg) {
    exists(Expr operand | sink(sinkExpr, operand, arg, _, _) | n.asExpr() = operand)
  }

  /** The basic block and index of the CFG node of `e`. */
  predicate cfgPosition(AstNode e, BasicBlock bb, int i) { bb.getNode(i).getAstNode() = e }

  /** `a` is evaluated before `b` on every path that reaches `b`. */
  predicate astDominates(AstNode a, AstNode b) {
    exists(BasicBlock ba, BasicBlock bb, int i, int j | cfgPosition(a, ba, i) and cfgPosition(b, bb, j) |
      ba.strictlyDominates(bb)
      or
      ba = bb and i < j
    )
  }

  /** Number of catalog sanitizer calls that dominate `sinkExpr` in its function. */
  int dominatingSanitizerCount(Expr sinkExpr) {
    result =
      count(ExportCall sanitizer |
        sanitizerApi(targetName(sanitizer)) and
        enclosingFunction(sanitizer) = enclosingFunction(sinkExpr) and
        astDominates(sanitizer, sinkExpr) and
        sanitizer != sinkExpr
      )
  }

  /** The call whose return value source node `n` is, if any. */
  Call sourceCall(DataFlow::Node n) {
    result = n.(N::FlowSummaryNode).getSummaryNode().getSourceSinkReportingElement() or
    result = n.asExpr()
  }

  /** The source-root AST element a source node reports at. */
  AstNode sourceElement(DataFlow::Node n) {
    result = n.(N::FlowSummaryNode).getSummaryNode().getSourceSinkReportingElement()
    or
    result = n.asExpr()
    or
    result = n.asParameter()
  }

  /**
   * A source candidate: `model` is the threat model of a `ThreatModelSource` ("api" for a
   * catalog API source the model library does not cover), `sourceType` its `getSourceType()`
   * ("" for "api"). `declared` is the declaring module or type of the called API.
   */
  predicate source(
    DataFlow::Node n, string model, string sourceType, string kind, string api, int index,
    string declared
  ) {
    inSource(sourceElement(n)) and
    exportedNode(n) and
    (
      model = n.(ThreatModelSource).getThreatModel() and
      sourceType = n.(ThreatModelSource).getSourceType() and
      (
        exists(Call call | call = sourceCall(n) |
          kind = "return_value" and
          index = -1 and
          (api = targetName(call) or not exists(targetName(call)) and api = "") and
          declared = targetDeclaredIn(call)
        )
        or
        not exists(sourceCall(n)) and
        nodeShapeNoCall(n, kind, index) and
        api = "" and
        declared = ""
      )
      or
      not n instanceof ThreatModelSource and
      model = "api" and
      sourceType = "" and
      kind = "return_value" and
      exists(Call call |
        n.asExpr() = call and
        api = targetName(call) and
        apiSourceArgument(api, index) and
        declared = targetDeclaredIn(call) and
        apiSourceModule(declared)
      )
    )
  }

  /** The shape of a source node that is not a call: a parameter or another expression. */
  private predicate nodeShapeNoCall(DataFlow::Node n, string kind, int index) {
    exists(Param p, Callable c | n.asParameter() = p and p = c.getParam(index) | kind = "parameter")
    or
    not exists(n.asParameter()) and kind = "expression" and index = -1
  }
}
