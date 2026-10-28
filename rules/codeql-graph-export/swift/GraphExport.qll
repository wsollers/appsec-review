/**
 * Shared definitions for the appsec-review Swift code-graph export pack.
 *
 * LIVE-UNVERIFIED: written against the `codeql/swift-all` library bundled with the pinned CodeQL
 * 2.27.0 CLI, but not compiled in the repository's offline CI. CodeQL extracts Swift only on a
 * macOS executor, so the live tier (tests/live/test_codeql_graph_export_swift_live.py) skips
 * until one is configured.
 *
 * Export conventions (the column contract is ../columns.json, identical in shape to the C/C++
 * pack):
 * - every exported column is a primitive `string` or `int`; no query exports an entity column, so
 *   no database-internal element id leaves the database;
 * - a location is five columns `<p>_path, <p>_start_line, <p>_start_column, <p>_end_line,
 *   <p>_end_column`: the path is relative to the database source root
 *   (`File.getRelativePath()`), lines and columns are 1-based and the end column is inclusive;
 *   an element outside the source root exports path "" and zero positions;
 * - booleans are the strings "true" and "false";
 * - a function name is `Type.name(labels:)` for a member of a nominal type (an extension member
 *   names the extended type) and `name(labels:)` otherwise; a function location is the whole
 *   declaration, so it starts at its first modifier or the `func`/`init` keyword, not the name;
 * - `declared_in` is `Module.Type` for a member of a nominal type and `Module` otherwise;
 * - classification into sink and source classes is not done here: rows carry the CodeQL model
 *   identity and the API name, and ../catalog.json classifies them downstream.
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.FlowSources
import codeql.swift.controlflow.BasicBlocks
import codeql.swift.controlflow.ControlFlowGraph
import codeql.swift.security.SqlInjectionExtensions
import codeql.swift.security.CommandInjectionExtensions
import codeql.swift.security.PathInjectionExtensions
import codeql.swift.security.UnsafeUnpackExtensions
import codeql.swift.security.XXEExtensions
import codeql.swift.security.UnsafeJsEvalExtensions
import codeql.swift.security.UncontrolledFormatStringExtensions
import codeql.swift.security.PredicateInjectionExtensions
import codeql.swift.security.UnsafeWebViewFetchExtensions
import codeql.swift.security.CleartextLoggingExtensions

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

  /** Holds when the dataflow node lies inside the database source root. */
  predicate nodeInSource(DataFlow::Node n) { exists(n.getLocation().getFile().getRelativePath()) }

  /** A function (method, free function, initializer or accessor) with a body inside the source root. */
  class SourceFunction extends Function {
    SourceFunction() { exists(this.getBody()) and inSource(this) }
  }

  /** The nominal type `d` is a member of; an extension member resolves to the extended type. */
  NominalTypeDecl memberType(Decl d) { result = d.getEnclosingDecl().asNominalTypeDecl() }

  /**
   * The exported function name: `Type.name` for a type member, else `name` (argument labels
   * removed; overloads are told apart by their location).
   */
  string qualifiedName(Function f) {
    result = memberType(f).getName() + "." + f.getShortName()
    or
    not exists(memberType(f)) and result = f.getShortName()
  }

  /** The catalog `declared_in` of a declaration: `Module.Type` for a type member, else `Module`. */
  string declaredIn(Decl d) {
    result = d.getModule().getName() + "." + memberType(d).getName()
    or
    not exists(memberType(d)) and result = d.getModule().getName()
    or
    not exists(d.getModule()) and result = ""
  }

  /** The base name a catalog API rule matches: the function name without its argument labels. */
  string shortName(Callable c) {
    result = c.(Function).getShortName()
    or
    not c instanceof Function and result = c.getName()
  }

  /** The catalog name of the target of `call` ("" when CodeQL resolves no static target). */
  string calleeName(ApplyExpr call) {
    result = shortName(call.getStaticTarget())
    or
    not exists(shortName(call.getStaticTarget())) and result = ""
  }

  /** The function a dataflow node lies in (closures belong to their enclosing function). */
  Function nodeFunction(DataFlow::Node n) {
    result = n.getCfgNode().getNode().asAstNode().getEnclosingFunction()
    or
    not exists(n.getCfgNode()) and result = n.asParameter().getEnclosingFunction()
  }

  /** Holds in "whole_program" mode, where every function is exported. */
  predicate wholeProgram() { exportScope("whole_program", _) }

  /** The call-graph radius of the neighborhood in "seeded" mode. */
  private int scopeDepth() { exportScope("seeded", result) }

  /** A direct base of `t`: an inherited class or protocol, or a protocol an extension adds. */
  private TypeDecl directBase(TypeDecl t) {
    result = t.getABaseTypeDecl()
    or
    exists(ExtensionDecl e | e.getExtendedTypeDecl() = t and result = e.getAProtocol())
  }

  /** `impl` overrides or implements `m` in a derived class or a conforming type. */
  predicate implementsMember(Method m, Method impl) {
    impl != m and
    impl.getName() = m.getName() and
    directBase+(memberType(impl)) = memberType(m)
  }

  /**
   * `m` is dispatched dynamically: a protocol requirement, or an instance method of a class that
   * a derived class overrides.
   */
  predicate dynamicMethod(Method m) {
    memberType(m) instanceof ProtocolDecl
    or
    memberType(m) instanceof ClassDecl and
    m.isInstanceMethod() and
    implementsMember(m, _)
  }

  /** Every implementation with a body (including the static target) a dynamic call may reach. */
  Function virtualCandidate(ApplyExpr call) {
    exists(Method m | m = call.getStaticTarget() and dynamicMethod(m) |
      result = m
      or
      implementsMember(m, result)
    ) and
    exists(result.getBody())
  }

  /** `caller` contains a call to `callee`, directly or as a dynamic dispatch candidate. */
  private predicate callEdge(SourceFunction caller, SourceFunction callee) {
    exists(ApplyExpr call | call.getEnclosingFunction() = caller |
      callee = call.getStaticTarget()
      or
      callee = virtualCandidate(call)
    )
  }

  /**
   * `f` is a source-root function whose declaration (first modifier through closing brace)
   * overlaps the seed lines `[startLine, endLine]` of `path`. Every overlapping function matches.
   */
  predicate seedMatch(string path, int startLine, int endLine, SourceFunction f) {
    exportSeed(path, startLine, endLine) and
    f.getLocation().getFile().getRelativePath() = path and
    startLine <= functionEndLine(f) and
    endLine >= f.getLocation().getStartLine()
  }

  private int functionEndLine(SourceFunction f) {
    result = f.getBody().getLocation().getEndLine()
    or
    not exists(f.getBody().getLocation()) and result = f.getLocation().getEndLine()
  }

  /** A function that contains finding lines (a seed). */
  predicate seedFunction(SourceFunction f) { seedMatch(_, _, _, f) }

  /**
   * `f` is within `distance` call-graph steps of a seed function, following call edges in either
   * direction, bounded by the scope depth. Take the minimum distance for the shortest.
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

  /** `e` lies in an exported function, or outside any function in "whole_program" mode. */
  predicate exportedExpr(Expr e) { wholeProgram() or exported(e.getEnclosingFunction()) }

  /** The dataflow node lies in an exported function. */
  predicate exportedNode(DataFlow::Node n) { wholeProgram() or exported(nodeFunction(n)) }

  /** "true" or "false". */
  bindingset[b]
  string flag(boolean b) { b = true and result = "true" or b = false and result = "false" }

  /**
   * Catalog API sinks the swift-all sink models do not cover: base name `name` (argument labels
   * removed) and the dangerous argument `arg` (-1: the call expression itself). The catalog rule
   * also requires the `declared_in` type. Kept equal to the `api` sink rules of ../catalog.json
   * by tests/graph/test_swift_export.py.
   */
  predicate apiSinkArgument(string name, int arg) {
    name = "dataTask" and arg = 0
    or
    name = "downloadTask" and arg = 0
    or
    name = "unarchiveTopLevelObjectWithData" and arg = 0
    or
    name = "unarchiveObject" and arg = 0
    or
    name = "allocate" and arg = 0
  }

  /**
   * Catalog API sources the swift-all source models do not cover: `arg` -1 is the value of a
   * property read or a call's return value. Kept equal to the `api` source rules of
   * ../catalog.json.
   */
  predicate apiSourceArgument(string name, int arg) {
    name = "arguments" and arg = -1
    or
    name = "environment" and arg = -1
  }

  /** Catalog sanitizer APIs. Kept equal to the `sanitizers` of ../catalog.json. */
  predicate sanitizerApi(string name) {
    name = ["resolvingSymlinksInPath", "lexicallyNormalized", "sqlite3_bind_text"]
  }

  private predicate apiCallSink(ApplyExpr call, Expr operand, int arg, string api) {
    api = calleeName(call) and
    apiSinkArgument(api, arg) and
    (
      arg >= 0 and operand = call.getArgument(arg).getExpr()
      or
      arg = -1 and operand = call
    )
  }

  /** The swift-all sink model class of a dataflow node (a node may belong to several). */
  string sinkModel(DataFlow::Node n) {
    n instanceof SqlInjectionSink and result = "SqlInjectionSink"
    or
    n instanceof CommandInjectionSink and result = "CommandInjectionSink"
    or
    n instanceof PathInjectionSink and result = "PathInjectionSink"
    or
    n instanceof UnsafeUnpackSink and result = "UnsafeUnpackSink"
    or
    n instanceof XxeSink and result = "XxeSink"
    or
    n instanceof UnsafeJsEvalSink and result = "UnsafeJsEvalSink"
    or
    n instanceof UncontrolledFormatStringSink and result = "UncontrolledFormatStringSink"
    or
    n instanceof PredicateInjectionSink and result = "PredicateInjectionSink"
    or
    n instanceof UnsafeWebViewFetchSink and result = "UnsafeWebViewFetchSink"
    or
    n instanceof CleartextLoggingSink and result = "CleartextLoggingSink"
  }

  /**
   * Model-based sinks; a catalog API match suppresses every model match on the same call. A
   * modeled call argument reports the call; a modeled receiver reports argument -1; any other
   * modeled expression reports itself at argument -1. Post-update sink nodes (a modeled property
   * assignment such as `Process.arguments`) have no expression and are not exported.
   */
  private predicate modelSink(Expr sinkExpr, Expr operand, int arg, string model, string api) {
    exists(DataFlow::Node n | model = sinkModel(n) and operand = n.asExpr() |
      exists(ApplyExpr call |
        sinkExpr = call and
        not apiSinkArgument(calleeName(call), _) and
        api = calleeName(call)
      |
        operand = call.getArgument(arg).getExpr()
        or
        arg = -1 and operand = call.getQualifier()
      )
      or
      not exists(ApplyExpr call |
        operand = call.getAnArgument().getExpr() or operand = call.getQualifier()
      ) and
      sinkExpr = operand and
      arg = -1 and
      api = ""
    )
  }

  /**
   * A sink candidate: `sinkExpr` (a call, or a modeled expression) uses `operand` at argument
   * `arg` (-1 for the receiver or the expression itself). `model` is "api" for a catalog API
   * match, otherwise the swift-all sink model class; `api` is the target's base name.
   */
  predicate sink(Expr sinkExpr, Expr operand, int arg, string model, string api) {
    inSource(sinkExpr) and
    exportedExpr(sinkExpr) and
    (
      exists(ApplyExpr call | sinkExpr = call | apiCallSink(call, operand, arg, api)) and
      model = "api"
      or
      modelSink(sinkExpr, operand, arg, model, api)
    )
  }

  /** The dataflow node that reaches the sink operand. */
  predicate sinkNode(DataFlow::Node n, Expr sinkExpr, int arg) {
    exists(Expr operand | sink(sinkExpr, operand, arg, _, _) | n.asExpr() = operand)
  }

  /** The basic block of an expression's control-flow node. */
  BasicBlock blockOf(Expr e) {
    exists(ControlFlowNode n | n.getNode().asAstNode() = e and result = n.getBasicBlock())
  }

  /** `a` is evaluated before `b` on every path to `b` (CFG dominance). */
  predicate exprDominates(Expr a, Expr b) {
    exists(ControlFlowNode na, ControlFlowNode nb |
      na.getNode().asAstNode() = a and nb.getNode().asAstNode() = b
    |
      na.getBasicBlock().strictlyDominates(nb.getBasicBlock())
      or
      exists(BasicBlock bb, int i, int j | na = bb.getNode(i) and nb = bb.getNode(j) and i < j)
    )
  }

  /** Number of catalog sanitizer calls that dominate `sinkExpr` in its function. */
  int dominatingSanitizerCount(Expr sinkExpr) {
    result =
      count(ApplyExpr sanitizer |
        sanitizerApi(calleeName(sanitizer)) and
        sanitizer.getEnclosingFunction() = sinkExpr.getEnclosingFunction() and
        exprDominates(sanitizer, sinkExpr) and
        sanitizer != sinkExpr
      )
  }

  /** The CodeQL model class of a modeled flow source node. */
  private string modelClass(FlowSource n) {
    if n instanceof RemoteFlowSource
    then result = "RemoteFlowSource"
    else
      if n instanceof LocalFlowSource
      then result = "LocalFlowSource"
      else result = "FlowSource"
  }

  /**
   * How a source node relates to the code: `kind` is "return_value" (a call's result, or the
   * value of a property read, which Swift evaluates through a getter) of `api`, "parameter"
   * (`index` the parameter position), or "expression". Swift has no output arguments.
   */
  private predicate nodeShape(DataFlow::Node n, string kind, string api, int index) {
    exists(ApplyExpr call | n.asExpr() = call |
      kind = "return_value" and api = calleeName(call) and index = -1
    )
    or
    exists(LookupExpr read | n.asExpr() = read |
      kind = "return_value" and api = read.getMember().(VarDecl).getName() and index = -1
    )
    or
    exists(ParamDecl p, Callable c | n.asParameter() = p and c.getParam(index) = p |
      kind = "parameter" and api = ""
    )
    or
    not n.asExpr() instanceof ApplyExpr and
    not n.asExpr().(LookupExpr).getMember() instanceof VarDecl and
    not exists(n.asParameter()) and
    kind = "expression" and
    api = "" and
    index = -1
  }

  /** The catalog `declared_in` of the API a source node reads ("" when it reads none). */
  string sourceDeclaredIn(DataFlow::Node n) {
    result = declaredIn(n.asExpr().(ApplyExpr).getStaticTarget())
    or
    result = declaredIn(n.asExpr().(LookupExpr).getMember().(VarDecl))
    or
    not exists(n.asExpr().(ApplyExpr).getStaticTarget()) and
    not n.asExpr().(LookupExpr).getMember() instanceof VarDecl and
    result = ""
  }

  /**
   * A source candidate: `model` is the CodeQL model class ("api" for a catalog API source the
   * model library does not cover), `sourceType` CodeQL's `getSourceType()` ("" for "api").
   */
  predicate source(
    DataFlow::Node n, string model, string sourceType, string kind, string api, int index
  ) {
    nodeInSource(n) and
    exportedNode(n) and
    (
      model = modelClass(n) and
      sourceType = n.(FlowSource).getSourceType() and
      nodeShape(n, kind, api, index)
      or
      not n instanceof FlowSource and
      model = "api" and
      sourceType = "" and
      kind = "return_value" and
      index = -1 and
      apiSourceArgument(api, index) and
      (
        exists(ApplyExpr call | n.asExpr() = call | calleeName(call) = api)
        or
        exists(LookupExpr read | n.asExpr() = read | read.getMember().(VarDecl).getName() = api)
      )
    )
  }
}
