/**
 * Shared definitions for the appsec-review Ruby code-graph export pack.
 *
 * LIVE-UNVERIFIED: written against the `codeql/ruby-all` library bundled with the pinned CodeQL
 * 2.27.0 CLI, but not compiled in the repository's offline CI. The live tier
 * (tests/live/test_codeql_graph_export_ruby_live.py) compiles and runs the pack on the pinned
 * image.
 *
 * Export conventions (the column contract is ../columns.json, the same shape as the C/C++ pack):
 * - every exported column is a primitive `string` or `int`; no query exports an entity column, so
 *   no database-internal element id leaves the database;
 * - a location is five columns `<p>_path, <p>_start_line, <p>_start_column, <p>_end_line,
 *   <p>_end_column`: the path is relative to the database source root
 *   (`File.getRelativePath()`), lines and columns are 1-based and the end column is inclusive;
 *   an element outside the source root exports path "" and zero positions;
 * - booleans are the strings "true" and "false";
 * - a function is a `def` (instance or singleton method). Its qualified name is
 *   `<enclosing module qualified name>::<method name>` for both kinds, and its location is the
 *   method-name token so the normalizer's name check holds;
 * - classification into sink and source classes is not done here: rows carry the CodeQL concept
 *   (model) identity and the API (method) name, and ../catalog.json classifies them downstream.
 *
 * Ruby has no integral range semantics the export can state, so Ranges.ql reports every sink
 * operand as "not_applicable" (a named gap downstream, never a clean result).
 */

import codeql.ruby.AST
import codeql.ruby.CFG
import codeql.ruby.DataFlow
import codeql.ruby.Concepts
import codeql.ruby.Frameworks
import codeql.ruby.dataflow.RemoteFlowSources
import codeql.ruby.security.UnsafeDeserializationCustomizations
private import codeql.ruby.ast.internal.AST as AstInternal
private import codeql.ruby.ast.internal.TreeSitter

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

  /** Holds when `l` lies inside the database source root (an accepted source file). */
  predicate inSource(Location l) { exists(l.getFile().getRelativePath()) }

  /** A method (`def m` or `def self.m`) defined inside the source root. */
  class SourceFunction extends MethodBase {
    SourceFunction() { inSource(this.getLocation()) }

    /** `<enclosing module qualified name>::<name>`; just the name when the module is anonymous. */
    string getQualifiedName() {
      result = this.getEnclosingModule().getModule().getQualifiedName() + "::" + this.getName()
      or
      not exists(this.getEnclosingModule().getModule().getQualifiedName()) and
      result = this.getName()
    }

    /** The location of the method-name token (the whole `def` when the token is synthesized). */
    Location getNameLocation() {
      result = AstInternal::toGenerated(this).(Ruby::Method).getName().getLocation()
      or
      result = AstInternal::toGenerated(this).(Ruby::SingletonMethod).getName().getLocation()
      or
      not exists(AstInternal::toGenerated(this)) and result = this.getLocation()
    }

    /** The qualified name of the module that defines this method ("" when anonymous). */
    string getDeclaringModule() {
      result = this.getEnclosingModule().getModule().getQualifiedName()
      or
      not exists(this.getEnclosingModule().getModule().getQualifiedName()) and result = ""
    }
  }

  /** Holds in "whole_program" mode, where every function is exported. */
  predicate wholeProgram() { exportScope("whole_program", _) }

  /** The call-graph radius of the neighborhood in "seeded" mode. */
  private int scopeDepth() { exportScope("seeded", result) }

  /** `caller` contains a call that may dispatch to `callee` (CodeQL's Ruby call graph). */
  private predicate callEdge(SourceFunction caller, SourceFunction callee) {
    exists(MethodCall call | call.getEnclosingMethod() = caller | callee = call.getATarget())
  }

  /**
   * `f` is a source-root method whose definition (`def` through `end`) overlaps the seed lines
   * `[startLine, endLine]` of `path`. Every overlapping method matches, so a nested `def` and the
   * method enclosing it both seed.
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
  predicate exported(MethodBase f) { wholeProgram() or near(f, _) }

  /** `e` lies in an exported function, or outside any function in "whole_program" mode. */
  predicate exportedExpr(AstNode e) { wholeProgram() or exported(e.getEnclosingMethod()) }

  /** `l` lies inside the `def` ... `end` span of `f`. */
  predicate within(Location l, SourceFunction f) {
    l.getFile() = f.getLocation().getFile() and
    l.getStartLine() >= f.getLocation().getStartLine() and
    l.getEndLine() <= f.getLocation().getEndLine()
  }

  /**
   * The innermost source-root method whose span contains `l`. Located by span rather than by AST
   * parent so SSA definition, parameter and post-update nodes resolve like expressions.
   */
  SourceFunction functionAt(Location l) {
    result =
      max(SourceFunction f |
        within(l, f)
      |
        f order by f.getLocation().getStartLine(), f.getLocation().getStartColumn()
      )
  }

  /** The dataflow node lies in an exported function. */
  predicate exportedNode(DataFlow::Node n) {
    wholeProgram() or exported(functionAt(n.getLocation()))
  }

  /** The name of the constant a call is made on (`File` in `File.read(p)`), else "". */
  string receiverConstant(MethodCall call) {
    result = call.getReceiver().(ConstantReadAccess).getName()
    or
    not call.getReceiver() instanceof ConstantReadAccess and result = ""
  }

  /** "true" or "false". */
  bindingset[b]
  string flag(boolean b) { b = true and result = "true" or b = false and result = "false" }

  /**
   * Catalog API sinks. Ruby sinks are concept (model) matches only, so there is no API rule and
   * this predicate is empty; it is kept so tests/graph/test_ruby_export.py can hold it equal to
   * the (empty) `api` sink rules of ../catalog.json.
   */
  predicate apiSinkArgument(string name, int arg) {
    none() and name = "" and arg = 0
  }

  /**
   * Catalog API sources. Empty for the same reason as `apiSinkArgument`; ENV and ARGV reads are
   * model sources ("LocalFlowSource") below.
   */
  predicate apiSourceArgument(string name, int arg) {
    none() and name = "" and arg = 0
  }

  /** Catalog sanitizer APIs (method names). Kept equal to the `sanitizers` of ../catalog.json. */
  predicate sanitizerApi(string name) { name = ["basename", "shellescape"] }

  /**
   * A concept (model) sink: `anchor` is the concept node and `operand` the node whose value is
   * dangerous; `model` names the concept. A model with no catalog rule is published unclassified.
   */
  private predicate conceptSink(DataFlow::Node anchor, DataFlow::Node operand, string model) {
    operand = anchor.(SqlExecution).getSql() and model = "SqlExecution"
    or
    operand = anchor.(SqlConstruction).getSql() and model = "SqlConstruction"
    or
    operand = anchor.(SystemCommandExecution).getAnArgument() and model = "SystemCommandExecution"
    or
    exists(CodeExecution c | c = anchor and operand = c.getCode() |
      c.runsArbitraryCode() and model = "CodeExecution"
      or
      not c.runsArbitraryCode() and model = "CodeExecution.reflective"
    )
    or
    operand = anchor.(FileSystemAccess).getAPathArgument() and model = "FileSystemAccess"
    or
    operand = anchor.(Http::Client::Request).getAUrlPart() and model = "HttpClientRequest"
    or
    exists(XmlParserCall x | x = anchor and x.externalEntitiesEnabled() and operand = x.getInput()) and
    model = "XmlParserCall"
    or
    operand = anchor.(XPathExecution).getXPath() and model = "XPathExecution"
    or
    operand = anchor.(LdapExecution).getQuery() and model = "LdapExecution"
    or
    operand = anchor.(TemplateRendering).getTemplate() and model = "TemplateRendering"
    or
    operand = anchor.(Http::Server::HttpRedirectResponse).getRedirectLocation() and
    model = "HttpRedirectResponse"
    or
    operand = anchor.(Http::Server::HeaderWriteAccess).getValue() and model = "HeaderWriteAccess"
    or
    operand = anchor.(RegexExecution).getRegex() and model = "RegexExecution"
    or
    operand = anchor.(Logging).getAnInput() and model = "Logging"
    or
    // A response body is only an HTML sink for some content types, so it stays unclassified.
    operand = anchor.(Http::Server::HttpResponse).getBody() and
    not anchor instanceof Http::Server::HttpRedirectResponse and
    model = "HttpResponse"
    or
    // The deserialization sink is the argument; the call that receives it is the sink expression.
    operand instanceof UnsafeDeserialization::Sink and
    model = "UnsafeDeserialization" and
    (
      anchor.(DataFlow::CallNode).getArgument(_) = operand
      or
      not exists(DataFlow::CallNode c | c.getArgument(_) = operand) and anchor = operand
    )
  }

  /**
   * A sink candidate: `sinkExpr` (the concept call) uses `operand` at argument `arg` (-1 when the
   * operand is the receiver, a keyword argument or not a call argument). `model` is the concept
   * name; `api` the called method name ("" when the sink is not a method call).
   */
  predicate sink(Expr sinkExpr, Expr operand, int arg, string model, string api) {
    exists(DataFlow::Node anchor, DataFlow::Node operandNode, DataFlow::Node site |
      conceptSink(anchor, operandNode, model) and
      site = sinkSite(anchor, operandNode) and
      sinkExpr = site.asExpr().getExpr() and
      operand = operandNode.asExpr().getExpr() and
      inSource(sinkExpr.getLocation()) and
      exportedExpr(sinkExpr)
    |
      (
        site.(DataFlow::CallNode).getArgument(arg) = operandNode
        or
        not site.(DataFlow::CallNode).getArgument(_) = operandNode and arg = -1
      ) and
      (
        api = sinkExpr.(MethodCall).getMethodName()
        or
        not sinkExpr instanceof MethodCall and api = ""
      )
    )
  }

  /**
   * The sink expression for a concept anchored at `anchor`. Some models anchor the concept at
   * its own operand (ActiveRecord's `SqlExecution` is the SQL argument of `find_by_sql`); the
   * call receiving that argument is then the sink, so `api` names the called method.
   */
  private DataFlow::Node sinkSite(DataFlow::Node anchor, DataFlow::Node operand) {
    conceptSink(anchor, operand, _) and
    (
      anchor = operand and result.(DataFlow::CallNode).getArgument(_) = anchor
      or
      not (anchor = operand and exists(DataFlow::CallNode c | c.getArgument(_) = anchor)) and
      result = anchor
    )
  }

  /**
   * A catalog sanitizer call propagates taint from its arguments to its result, so a flow through
   * it is exported (and the sanitizer listed) rather than lost where no library summary exists.
   */
  predicate sanitizerStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DataFlow::CallNode call |
      sanitizerApi(call.getMethodName()) and
      pred = call.getArgument(_) and
      succ = call
    )
  }

  /** The dataflow node that reaches the sink operand. */
  predicate sinkNode(DataFlow::Node n, Expr sinkExpr, int arg) {
    exists(Expr operand | sink(sinkExpr, operand, arg, _, _) | n.asExpr().getExpr() = operand)
  }

  /** `a` is evaluated on every path to `b` before `b` (control-flow dominance). */
  predicate astDominates(AstNode a, AstNode b) {
    exists(CfgNodes::AstCfgNode x, CfgNodes::AstCfgNode y |
      x.getAstNode() = a and y.getAstNode() = b and x.strictlyDominates(y)
    )
  }

  /** Number of catalog sanitizer calls that dominate `sinkExpr` in its method. */
  int dominatingSanitizerCount(Expr sinkExpr) {
    result =
      count(MethodCall sanitizer |
        sanitizerApi(sanitizer.getMethodName()) and
        sanitizer.getEnclosingMethod() = sinkExpr.getEnclosingMethod() and
        astDominates(sanitizer, sinkExpr) and
        sanitizer != sinkExpr
      )
  }

  /**
   * A local (process) source the Ruby model library does not model as a flow source: a method
   * call on the `ARGV` or `ENV` constant (`ARGV[0]`, `ARGV.first`, `ENV["X"]`, `ENV.fetch("X")`).
   * `sourceType` follows the C/C++ library's wording so the catalog rules read alike.
   */
  private predicate processSource(DataFlow::Node n, string sourceType) {
    exists(MethodCall call | n.asExpr().getExpr() = call |
      receiverConstant(call) = "ARGV" and sourceType = "a command-line argument"
      or
      receiverConstant(call) = "ENV" and sourceType = "an environment variable"
    )
  }

  /**
   * How a source node relates to the code: `kind` is "return_value" of a call to `api`
   * (`index` -1), "parameter" (`index` the parameter position), or "expression".
   */
  private predicate nodeShape(DataFlow::Node n, string kind, string api, int index) {
    exists(MethodCall call | n.asExpr().getExpr() = call |
      kind = "return_value" and api = call.getMethodName() and index = -1
    )
    or
    exists(Parameter p | n.asParameter() = p |
      kind = "parameter" and api = "" and index = p.getPosition()
    )
    or
    not n.asExpr().getExpr() instanceof MethodCall and
    not exists(n.asParameter()) and
    kind = "expression" and
    api = "" and
    index = -1
  }

  /**
   * A source candidate: `model` is "RemoteFlowSource" (CodeQL's modeled remote sources, with its
   * `getSourceType()`) or "LocalFlowSource" (an `ARGV` or `ENV` read).
   */
  predicate source(
    DataFlow::Node n, string model, string sourceType, string kind, string api, int index
  ) {
    inSource(n.getLocation()) and
    exportedNode(n) and
    nodeShape(n, kind, api, index) and
    (
      model = "RemoteFlowSource" and sourceType = n.(RemoteFlowSource).getSourceType()
      or
      not n instanceof RemoteFlowSource and
      model = "LocalFlowSource" and
      processSource(n, sourceType)
    )
  }
}
