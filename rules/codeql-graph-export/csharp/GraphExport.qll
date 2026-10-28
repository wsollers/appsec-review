/**
 * Shared definitions for the appsec-review C# code-graph export pack.
 *
 * LIVE-UNVERIFIED: written against the `codeql/csharp-all` library bundled with the pinned CodeQL
 * 2.27.0 CLI, but not compiled in the repository's offline CI. The live tier
 * (tests/live/test_codeql_graph_export_csharp_live.py) compiles and runs the pack on the pinned
 * image.
 *
 * Export conventions (the column contract is ../columns.json, identical to the C/C++ pack):
 * - every exported column is a primitive `string` or `int`; no query exports an entity column, so
 *   no database-internal element id leaves the database;
 * - a location is five columns `<p>_path, <p>_start_line, <p>_start_column, <p>_end_line,
 *   <p>_end_column`: the path is relative to the database source root
 *   (`File.getRelativePath()`), lines and columns are 1-based and the end column is inclusive;
 *   an element outside the source root (a referenced assembly) exports path "" and zero
 *   positions;
 * - booleans are the strings "true" and "false";
 * - a function name is the fully qualified `Namespace.Type.Member` of the unbound declaration;
 *   `declared_in` is the fully qualified name of the declaring type;
 * - classification into sink and source classes is not done here: rows carry the CodeQL model
 *   identity and the API name, and ../catalog.json classifies them downstream.
 *
 * Property accessor calls (`x.P`, `x.P = v`, indexers, events) and compiler-generated calls are not
 * call sites; a sink on a property setter is reported on the assignment.
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.dataflow.internal.ExternalFlow as ExternalFlow
import semmle.code.csharp.security.dataflow.flowsources.FlowSources
import semmle.code.csharp.security.dataflow.SqlInjectionQuery as SqlInjection
import semmle.code.csharp.security.dataflow.CommandInjectionQuery as CommandInjection
import semmle.code.csharp.security.dataflow.TaintedPathQuery as TaintedPath
import semmle.code.csharp.security.dataflow.UnsafeDeserializationQuery as UnsafeDeserialization
import semmle.code.csharp.security.dataflow.CodeInjectionQuery as CodeInjection
import semmle.code.csharp.security.dataflow.LDAPInjectionQuery as LdapInjection
import semmle.code.csharp.security.dataflow.XPathInjectionQuery as XPathInjection
import semmle.code.csharp.security.dataflow.XSSSinks as Xss
import semmle.code.csharp.security.dataflow.UrlRedirectQuery as UrlRedirect
import semmle.code.csharp.security.dataflow.RegexInjectionQuery as RegexInjection
import semmle.code.csharp.security.dataflow.LogForgingQuery as LogForging
import semmle.code.csharp.security.dataflow.XMLEntityInjectionQuery as XmlEntityInjection
import semmle.code.csharp.security.dataflow.ResourceInjectionQuery as ResourceInjection

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

  /** A callable with a body inside the source root (unbound declarations only). */
  class SourceFunction extends Callable {
    SourceFunction() {
      this.isUnboundDeclaration() and this.fromSource() and this.hasBody() and inSource(this)
    }
  }

  /** The source-root callable `c` belongs to (its unbound declaration). */
  SourceFunction sourceFunction(Callable c) { result = c.getUnboundDeclaration() }

  /** Holds in "whole_program" mode, where every function is exported. */
  predicate wholeProgram() { exportScope("whole_program", _) }

  /** The call-graph radius of the neighborhood in "seeded" mode. */
  private int scopeDepth() { exportScope("seeded", result) }

  /** Holds when `call` dispatches on the run-time type of its receiver (virtual or interface). */
  predicate isVirtual(Call call) {
    call instanceof VirtualMethodCall
    or
    call.(MethodCall).getTarget().getDeclaringType() instanceof Interface
  }

  /** Every source-root override or implementation a virtual or interface call may dispatch to. */
  SourceFunction virtualCandidate(Call call) {
    isVirtual(call) and result = sourceFunction(call.getARuntimeTarget())
  }

  /** Every source-root callable a delegate call may invoke (CodeQL delegate-flow dispatch). */
  SourceFunction delegateCandidate(Call call) {
    call instanceof DelegateLikeCall and result = sourceFunction(call.getARuntimeTarget())
  }

  /** A call that is a call site: an invocation written in the source, not an accessor call. */
  class SiteCall extends Call {
    SiteCall() { not this instanceof AccessorCall and not this.isImplicit() and inSource(this) }
  }

  /** `caller` contains a call to `callee`, directly or as a dispatch candidate. */
  private predicate callEdge(SourceFunction caller, SourceFunction callee) {
    exists(SiteCall call | sourceFunction(call.getEnclosingCallable()) = caller |
      callee = sourceFunction(call.getTarget())
      or
      callee = virtualCandidate(call)
      or
      callee = delegateCandidate(call)
    )
  }

  /**
   * `f` is a source-root callable whose declaration (name through closing brace) overlaps the
   * seed lines `[startLine, endLine]` of `path`. Every overlapping callable matches, so a lambda
   * and the method enclosing it both seed.
   */
  predicate seedMatch(string path, int startLine, int endLine, SourceFunction f) {
    exportSeed(path, startLine, endLine) and
    f.getLocation().getFile().getRelativePath() = path and
    startLine <= f.getBody().getLocation().getEndLine() and
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
  predicate exported(Callable f) { wholeProgram() or near(sourceFunction(f), _) }

  /** `e` lies in an exported function, or outside any function in "whole_program" mode. */
  predicate exportedExpr(Expr e) { wholeProgram() or exported(e.getEnclosingCallable()) }

  /** The dataflow node lies in an exported function. */
  predicate exportedNode(DataFlow::Node n) { wholeProgram() or exported(n.getEnclosingCallable()) }

  /** The fully qualified `Namespace.Type.Member` name of a declaration's unbound declaration. */
  string qualifiedName(Declaration d) {
    exists(string qualifier, string name |
      d.getUnboundDeclaration().hasFullyQualifiedName(qualifier, name)
    |
      if qualifier = "" then result = name else result = qualifier + "." + name
    )
    or
    not d.getUnboundDeclaration().hasFullyQualifiedName(_, _) and result = d.getName()
  }

  /** The fully qualified name of the type declaring `c` (the catalog `declared_in`), else "". */
  string declaredIn(Callable c) {
    result = qualifiedName(c.getUnboundDeclaration().getDeclaringType())
    or
    not exists(c.getUnboundDeclaration().getDeclaringType()) and result = ""
  }

  /** "true" or "false". */
  bindingset[b]
  string flag(boolean b) { b = true and result = "true" or b = false and result = "false" }

  /**
   * Catalog API sinks: method `name` of the type `type` and the dangerous argument `arg`
   * (-1: the call expression itself). Kept equal to the `api` sink rules of ../catalog.json by
   * tests/graph/test_csharp_export.py. csharp-all 7.3.0 has no server-side request forgery sink
   * model, so the HTTP client entry points are catalog APIs.
   */
  predicate apiSinkArgument(string type, string name, int arg) {
    name = "GetStringAsync" and arg = 0 and type = "System.Net.Http.HttpClient"
    or
    name = "GetAsync" and arg = 0 and type = "System.Net.Http.HttpClient"
    or
    name = "GetByteArrayAsync" and arg = 0 and type = "System.Net.Http.HttpClient"
    or
    name = "GetStreamAsync" and arg = 0 and type = "System.Net.Http.HttpClient"
    or
    name = "PostAsync" and arg = 0 and type = "System.Net.Http.HttpClient"
    or
    name = "Create" and arg = 0 and type = "System.Net.WebRequest"
    or
    name = "CreateInstance" and arg = 0 and type = "System.Activator"
    or
    name = "LoadFrom" and arg = 0 and type = "System.Reflection.Assembly"
    or
    name = "Next" and arg = -1 and type = "System.Random"
  }

  /**
   * Catalog API sources: `arg` -1 is the return value. Kept equal to the `api` source rules of
   * ../catalog.json. Emitted only where csharp-all models no source on the node.
   */
  predicate apiSourceArgument(string type, string name, int arg) {
    name = "GetEnvironmentVariable" and arg = -1 and type = "System.Environment"
    or
    name = "GetCommandLineArgs" and arg = -1 and type = "System.Environment"
    or
    name = "ReadLine" and arg = -1 and type = "System.Console"
    or
    name = "ReadAllText" and arg = -1 and type = "System.IO.File"
  }

  /** Catalog sanitizer APIs. Kept equal to the `sanitizers` of ../catalog.json. */
  predicate sanitizerApi(string name) {
    name = ["GetFileName", "HtmlEncode", "UrlEncode", "EscapeDataString"]
  }

  /** `call` is a call to the catalog API `name` declared in `type`. */
  private predicate apiCall(Call call, string type, string name) {
    name = call.getTarget().getName() and
    type = declaredIn(call.getTarget()) and
    apiSinkArgument(type, name, _)
  }

  private predicate apiCallSink(Call call, Expr operand, int arg, string api) {
    exists(string type | apiCall(call, type, api) and apiSinkArgument(type, api, arg)) and
    (
      arg >= 0 and operand = call.getArgument(arg)
      or
      arg = -1 and operand = call
    )
  }

  /** The csharp-all security sink model class `n` belongs to. */
  private string sinkModel(DataFlow::Node n) {
    n instanceof SqlInjection::Sink and result = "SqlInjection.Sink"
    or
    n instanceof CommandInjection::Sink and result = "CommandInjection.Sink"
    or
    n instanceof TaintedPath::Sink and result = "TaintedPath.Sink"
    or
    n instanceof UnsafeDeserialization::Sink and result = "UnsafeDeserialization.Sink"
    or
    n instanceof CodeInjection::Sink and result = "CodeInjection.Sink"
    or
    n instanceof LdapInjection::Sink and result = "LdapInjection.Sink"
    or
    n instanceof XPathInjection::Sink and result = "XPathInjection.Sink"
    or
    n instanceof Xss::Sink and result = "Xss.Sink"
    or
    n instanceof UrlRedirect::Sink and result = "UrlRedirect.Sink"
    or
    n instanceof RegexInjection::Sink and result = "RegexInjection.Sink"
    or
    n instanceof LogForging::Sink and result = "LogForging.Sink"
    or
    n instanceof XmlEntityInjection::Sink and result = "XmlEntityInjection.Sink"
    or
    n instanceof ResourceInjection::Sink and result = "ResourceInjection.Sink"
  }

  /**
   * The expression a model sink operand is reported on: the call it is an argument of (`arg` its
   * position), the assignment it is the value of (a property setter such as `CommandText`,
   * `arg` -1), or the operand itself (`arg` -1).
   */
  private predicate sinkShape(Expr operand, Expr sinkExpr, int arg) {
    exists(SiteCall call | operand = call.getArgument(arg) | sinkExpr = call)
    or
    not operand = any(SiteCall call).getAnArgument() and
    (
      exists(Assignment a | operand = a.getRightOperand() | sinkExpr = a and arg = -1)
      or
      not operand = any(Assignment a).getRightOperand() and sinkExpr = operand and arg = -1
    )
  }

  /** Model-based sinks; a catalog API match suppresses every model match on the same call. */
  private predicate modelSink(Expr sinkExpr, Expr operand, int arg, string model) {
    exists(DataFlow::Node n | model = sinkModel(n) and operand = n.asExpr()) and
    sinkShape(operand, sinkExpr, arg) and
    not apiCall(sinkExpr, _, _)
  }

  /**
   * A sink candidate: `sinkExpr` (a call, a property assignment, an array creation or the operand
   * itself) uses `operand` at argument `arg` (-1 when the operand is not a call argument).
   * `model` is "api" for a catalog API match, otherwise the csharp-all sink model; `api` is the
   * target's name ("" when `sinkExpr` is not a call).
   */
  predicate sink(Expr sinkExpr, Expr operand, int arg, string model, string api) {
    inSource(sinkExpr) and
    exportedExpr(sinkExpr) and
    (
      apiCallSink(sinkExpr, operand, arg, api) and model = "api"
      or
      modelSink(sinkExpr, operand, arg, model) and
      (
        api = sinkExpr.(Call).getTarget().getName()
        or
        not exists(sinkExpr.(Call).getTarget()) and api = ""
      )
      or
      exists(ArrayCreation creation | sinkExpr = creation |
        operand = creation.getALengthArgument() and
        arg = -1 and
        model = "ArrayCreation.length" and
        api = ""
      )
    )
  }

  /** The dataflow node that reaches the sink operand. */
  predicate sinkNode(DataFlow::Node n, Expr sinkExpr, int arg) {
    exists(Expr operand | sink(sinkExpr, operand, arg, _, _) | n.asExpr() = operand)
  }

  /** `a` executes before `b` on every path to `b` (control-flow dominance, `a` != `b`). */
  predicate cfDominates(ControlFlowElement a, ControlFlowElement b) {
    a.getBasicBlock().strictlyDominates(b.getBasicBlock())
    or
    exists(BasicBlock bb, int i, int j |
      bb.getNode(i) = a.getControlFlowNode() and
      bb.getNode(j) = b.getControlFlowNode() and
      i < j
    )
  }

  /** Number of catalog sanitizer calls that dominate `sinkExpr` in its callable. */
  int dominatingSanitizerCount(Expr sinkExpr) {
    result =
      count(Call sanitizer |
        sanitizerApi(sanitizer.getTarget().getName()) and
        sanitizer.getEnclosingCallable() = sinkExpr.getEnclosingCallable() and
        cfDominates(sanitizer, sinkExpr)
      )
  }

  /** The csharp-all model class of a modeled flow source node. */
  private string modelClass(SourceNode n) {
    if n instanceof RemoteFlowSource
    then result = "RemoteFlowSource"
    else
      if n instanceof LocalFlowSource
      then result = "LocalFlowSource"
      else
        if n instanceof StoredFlowSource
        then result = "StoredFlowSource"
        else result = "SourceNode"
  }

  /**
   * How a source node relates to the code: `kind` is "return_value" of a call to `api` (`index`
   * -1), "parameter" (`index` the parameter position), or "expression".
   */
  private predicate nodeShape(DataFlow::Node n, string kind, string api, int index) {
    exists(Call call | n.asExpr() = call |
      kind = "return_value" and api = call.getTarget().getName() and index = -1
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

  /** The declaring type of the target of the call a source node is the value of, else "". */
  string sourceDeclaredIn(DataFlow::Node n) {
    result = declaredIn(n.asExpr().(Call).getTarget())
    or
    not exists(n.asExpr().(Call).getTarget()) and result = ""
  }

  /**
   * A source candidate: `model` is the csharp-all model class ("ExternalSource" for a
   * models-as-data source kind that no `SourceNode` class covers, "api" for a catalog API source
   * the model library does not cover), `sourceType` CodeQL's `getSourceType()` (the
   * models-as-data kind for "ExternalSource", "" for "api").
   */
  predicate source(
    DataFlow::Node n, string model, string sourceType, string kind, string api, int index
  ) {
    (inSource(n.asExpr()) or inSource(n.asParameter())) and
    exportedNode(n) and
    (
      model = modelClass(n) and
      sourceType = n.(SourceNode).getSourceType() and
      nodeShape(n, kind, api, index)
      or
      not n instanceof SourceNode and
      ExternalFlow::sourceNode(n, sourceType) and
      model = "ExternalSource" and
      nodeShape(n, kind, api, index)
      or
      not n instanceof SourceNode and
      not ExternalFlow::sourceNode(n, _) and
      model = "api" and
      sourceType = "" and
      exists(Call call, string type |
        n.asExpr() = call and
        api = call.getTarget().getName() and
        type = declaredIn(call.getTarget()) and
        apiSourceArgument(type, api, index) and
        index = -1 and
        kind = "return_value"
      )
    )
  }
}
