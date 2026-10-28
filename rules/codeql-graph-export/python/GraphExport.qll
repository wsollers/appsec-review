/**
 * Shared definitions for the appsec-review Python code-graph export pack.
 *
 * LIVE-UNVERIFIED: written against the `codeql/python-all` library bundled with the pinned CodeQL
 * 2.27.0 CLI, but not compiled in the repository's offline CI. The live tier
 * (tests/live/test_codeql_graph_export_python_live.py) compiles and runs the pack on the pinned
 * image.
 *
 * Export conventions (the column contract is ../columns.json):
 * - every exported column is a primitive `string` or `int`; no query exports an entity column, so
 *   no database-internal element id leaves the database;
 * - a location is five columns `<p>_path, <p>_start_line, <p>_start_column, <p>_end_line,
 *   <p>_end_column`: the path is relative to the database source root
 *   (`File.getRelativePath()`), lines and columns are 1-based and the end column is inclusive;
 *   an element outside the source root exports path "" and zero positions;
 * - a function is located at its defining name token (`def <name>`), and named by
 *   `Function.getQualifiedName()` (`Class.method`); module-level code has no function and exports
 *   function name "" and an empty location;
 * - booleans are the strings "true" and "false";
 * - classification into sink and source classes is not done here: rows carry the CodeQL concept
 *   (model) identity and the API name, and ../catalog.json classifies them downstream.
 *
 * Python has no integer range semantics that bound a sink: every `ranges` row is
 * "not_applicable" and `range_conversions` is always empty (a named gap, never a clean result).
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.Frameworks
import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.internal.DataFlowDispatch as DataFlowDispatch

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

  /** Holds when `n` lies inside the database source root (an accepted source file). */
  predicate nodeInSource(DataFlow::Node n) { exists(n.getLocation().getFile().getRelativePath()) }

  /** A function (or lambda) defined inside the source root. */
  class SourceFunction extends Function {
    SourceFunction() { exists(this.getLocation().getFile().getRelativePath()) }
  }

  /** The defining name token of `f` (`def <name>`); a lambda has none and uses its own location. */
  Location functionLocation(Function f) {
    exists(FunctionDef def | def.getDefinedFunction() = f | result = def.getATarget().getLocation())
    or
    not exists(FunctionDef def | def.getDefinedFunction() = f) and result = f.getLocation()
  }

  /**
   * The name and defining-name location of the function `s`; module or class level code (no
   * source function) exports name "" and an empty location.
   */
  predicate functionColumns(Scope s, string name, string path, int line, int column) {
    exists(SourceFunction f | f = s |
      name = f.getQualifiedName() and
      locationColumns(functionLocation(f), path, line, column, _, _)
    )
    or
    not s instanceof SourceFunction and
    name = "" and
    path = "" and
    line = 0 and
    column = 0
  }

  /** Holds in "whole_program" mode, where every function is exported. */
  predicate wholeProgram() { exportScope("whole_program", _) }

  /** The call-graph radius of the neighborhood in "seeded" mode. */
  private int scopeDepth() { exportScope("seeded", result) }

  /** Every function CodeQL's call resolution gives for `call`. */
  predicate resolvedTarget(DataFlow::CallCfgNode call, Function target) {
    DataFlowDispatch::resolveCall(call.getNode(), target, _)
  }

  /** `call` resolves to `target` as a plain (non-method, non-class) function call. */
  predicate plainFunctionTarget(DataFlow::CallCfgNode call, Function target) {
    DataFlowDispatch::resolveCall(call.getNode(), target,
      any(DataFlowDispatch::CallTypePlainFunction t))
  }

  /** `caller` contains a call CodeQL resolves to `callee` (every override candidate included). */
  private predicate callEdge(SourceFunction caller, SourceFunction callee) {
    exists(DataFlow::CallCfgNode call | call.getScope() = caller | resolvedTarget(call, callee))
  }

  private int functionEndLine(SourceFunction f) {
    result =
      max(int line |
        line = f.getLocation().getEndLine()
        or
        exists(Stmt s | s.getScope() = f and line = s.getLocation().getEndLine())
        or
        exists(Expr e | e.getScope() = f and line = e.getLocation().getEndLine())
      )
  }

  /**
   * `f` is a source-root function whose definition (def line through its last statement) overlaps
   * the seed lines `[startLine, endLine]` of `path`. Every overlapping function matches, so a
   * nested function and the function enclosing it both seed.
   */
  predicate seedMatch(string path, int startLine, int endLine, SourceFunction f) {
    exportSeed(path, startLine, endLine) and
    f.getLocation().getFile().getRelativePath() = path and
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
  predicate exported(Function f) { wholeProgram() or near(f, _) }

  /**
   * The dataflow node lies in an exported function, or anywhere (module level included) in
   * "whole_program" mode.
   */
  predicate exportedNode(DataFlow::Node n) { wholeProgram() or exported(n.getScope()) }

  /** "true" or "false". */
  bindingset[b]
  string flag(boolean b) { b = true and result = "true" or b = false and result = "false" }

  /**
   * Catalog API sinks: function `name` of module `mod` ("builtins" for a builtin) and the
   * dangerous positional argument `arg` (-1: the call itself). Kept equal to the `api` sink rules
   * of ../catalog.json by tests/graph/test_python_export.py.
   */
  predicate apiSinkArgument(string mod, string name, int arg) {
    mod = "os" and name = "system" and arg = 0
    or
    mod = "os" and name = "popen" and arg = 0
    or
    mod = "os" and name = "remove" and arg = 0
    or
    mod = "pickle" and name = "loads" and arg = 0
    or
    mod = "requests" and name = "get" and arg = 0
    or
    mod = "urllib.request" and name = "urlopen" and arg = 0
    or
    mod = "builtins" and name = "open" and arg = 0
    or
    mod = "builtins" and name = "eval" and arg = 0
    or
    mod = "builtins" and name = "exec" and arg = 0
  }

  /**
   * Catalog API sources the threat-model sources do not cover: `arg` -1 is the return value.
   * Kept equal to the `api` source rules of ../catalog.json.
   */
  predicate apiSourceArgument(string mod, string name, int arg) {
    mod = "getpass" and name = "getpass" and arg = -1
    or
    mod = "builtins" and name = "input" and arg = -1
  }

  /** Catalog sanitizer APIs. Kept equal to the `sanitizers` of ../catalog.json. */
  predicate sanitizerApi(string mod, string name) {
    mod = "os.path" and name = "realpath"
    or
    mod = "shlex" and name = "quote"
    or
    mod = "werkzeug.utils" and name = "secure_filename"
    or
    mod = "html" and name = "escape"
  }

  private predicate catalogApi(string mod, string name) {
    apiSinkArgument(mod, name, _) or apiSourceArgument(mod, name, _) or sanitizerApi(mod, name)
  }

  /** The API graph node of a dotted module path of one or two components. */
  bindingset[mod]
  private API::Node moduleNode(string mod) {
    result = API::moduleImport(mod)
    or
    result =
      API::moduleImport(mod.regexpCapture("([^.]+)\\.([^.]+)", 1))
          .getMember(mod.regexpCapture("([^.]+)\\.([^.]+)", 2))
  }

  /** `call` calls the catalog API `mod`.`name` (through any import form API graphs follow). */
  predicate apiCallName(DataFlow::CallCfgNode call, string mod, string name) {
    catalogApi(mod, name) and
    (
      mod = "builtins" and call = API::builtin(name).getACall()
      or
      mod != "builtins" and call = moduleNode(mod).getMember(name).getACall()
    )
  }

  /** Comma-joined sorted catalog modules `n` is a call into ("" when none). */
  string declaredIn(DataFlow::Node n) {
    result = concat(string mod | apiCallName(n, mod, _) | mod, "," order by mod)
  }

  /** The syntactic callee name of `call`: a `Name` id or an `Attribute` name, else "". */
  string callName(DataFlow::CallCfgNode call) {
    result = call.getFunction().asExpr().(Name).getId()
    or
    result = call.getFunction().asExpr().(Attribute).getName()
    or
    not call.getFunction().asExpr() instanceof Name and
    not call.getFunction().asExpr() instanceof Attribute and
    result = ""
  }

  /** `callName` for a call node, "" for any other node. */
  string nodeCallName(DataFlow::Node n) {
    result = callName(n)
    or
    not n instanceof DataFlow::CallCfgNode and result = ""
  }

  private predicate apiCallSink(DataFlow::CallCfgNode call, DataFlow::Node operand, int arg, string api) {
    exists(string mod |
      apiCallName(call, mod, api) and
      apiSinkArgument(mod, api, arg)
    |
      arg >= 0 and operand = call.getArg(arg)
      or
      arg = -1 and operand = call
    )
  }

  private predicate apiSinkCall(DataFlow::Node n) {
    exists(string mod, string api | apiCallName(n, mod, api) and apiSinkArgument(mod, api, _))
  }

  /**
   * Model-based sinks from python-all Concepts. `model` names the concept; "Decoding.mayExecuteInput"
   * is a `Decoding` that may execute its input (unsafe deserialization). NoSqlExecution has no
   * contract sink class and is emitted unclassified on purpose.
   */
  private predicate modelSink(DataFlow::Node sinkNode, DataFlow::Node operand, string model) {
    exists(SqlExecution e | sinkNode = e and operand = e.getSql()) and model = "SqlExecution"
    or
    exists(SystemCommandExecution e | sinkNode = e and operand = e.getCommand()) and
    model = "SystemCommandExecution"
    or
    exists(FileSystemAccess e | sinkNode = e and operand = e.getAPathArgument()) and
    model = "FileSystemAccess"
    or
    exists(Http::Client::Request e | sinkNode = e and operand = e.getAUrlPart()) and
    model = "HttpClientRequest"
    or
    exists(Decoding e | e.mayExecuteInput() and sinkNode = e and operand = e.getAnInput()) and
    model = "Decoding.mayExecuteInput"
    or
    exists(CodeExecution e | sinkNode = e and operand = e.getCode()) and model = "CodeExecution"
    or
    exists(Ldap::LdapExecution e | sinkNode = e and operand = e.getFilter()) and
    model = "LdapExecution"
    or
    exists(XML::XPathExecution e | sinkNode = e and operand = e.getXPath()) and
    model = "XPathExecution"
    or
    exists(XML::XmlParsing e | e.vulnerableTo(_) and sinkNode = e and operand = e.getAnInput()) and
    model = "XmlParsing"
    or
    exists(TemplateConstruction e | sinkNode = e and operand = e.getSourceArg()) and
    model = "TemplateConstruction"
    or
    exists(Http::Server::HttpRedirectResponse e |
      sinkNode = e and operand = e.getRedirectLocation()
    ) and
    model = "HttpRedirectResponse"
    or
    exists(Http::Server::ResponseHeaderWrite e | sinkNode = e and operand = e.getValueArg()) and
    model = "ResponseHeaderWrite"
    or
    exists(RegexExecution e | sinkNode = e and operand = e.getRegex()) and model = "RegexExecution"
    or
    exists(Logging e | sinkNode = e and operand = e.getAnInput()) and model = "Logging"
    or
    exists(Http::Server::HttpResponse e | sinkNode = e and operand = e.getBody()) and
    model = "HttpResponse"
    or
    exists(NoSqlExecution e | sinkNode = e and operand = e.getQuery()) and model = "NoSqlExecution"
  }

  /** The positional index of `operand` in the call `sinkNode`, else -1 (keyword or not a call). */
  int argumentIndex(DataFlow::Node sinkNode, DataFlow::Node operand) {
    result = min(int i | operand = sinkNode.(DataFlow::CallCfgNode).getArg(i))
    or
    not operand = sinkNode.(DataFlow::CallCfgNode).getArg(_) and result = -1
  }

  /**
   * A sink candidate: `sinkNode` (usually a call) uses `operand` at positional argument `arg` (-1
   * when the operand is a keyword argument, the call itself or not a call argument). `model` is
   * "api" for a catalog API match, otherwise the Concepts class; `api` is the callee name ("" when
   * the sink is not a call). A catalog API match suppresses every model match on the same call.
   */
  predicate sink(DataFlow::Node sinkNode, DataFlow::Node operand, int arg, string model, string api) {
    nodeInSource(sinkNode) and
    exportedNode(sinkNode) and
    (
      apiCallSink(sinkNode, operand, arg, api) and model = "api"
      or
      not apiSinkCall(sinkNode) and
      modelSink(sinkNode, operand, model) and
      arg = argumentIndex(sinkNode, operand) and
      api = nodeCallName(sinkNode)
    )
  }

  /** The dataflow node that reaches the sink operand (the operand node itself in Python). */
  predicate sinkNode(DataFlow::Node n, DataFlow::Node sinkNode, int arg) { sink(sinkNode, n, arg, _, _) }

  /** A call of a catalog sanitizer API. */
  predicate sanitizerCall(DataFlow::CallCfgNode call, string api) {
    exists(string mod | apiCallName(call, mod, api) and sanitizerApi(mod, api))
  }

  /** Number of catalog sanitizer calls that strictly dominate `sinkNode` in its scope. */
  int dominatingSanitizerCount(DataFlow::Node sinkNode) {
    result =
      count(Call sanitizer |
        exists(DataFlow::CallCfgNode call |
          sanitizerCall(call, _) and
          call.getNode().getNode() = sanitizer and
          call.getScope() = sinkNode.getScope() and
          call.asCfgNode().strictlyDominates(sinkNode.asCfgNode())
        )
      )
  }

  /**
   * How a source node relates to the code: `kind` is "return_value" of a call to `api` (`index`
   * -1), "parameter" (`index` the parameter position), or "expression".
   */
  private predicate nodeShape(DataFlow::Node n, string kind, string api, int index) {
    n instanceof DataFlow::CallCfgNode and
    kind = "return_value" and
    api = callName(n) and
    index = -1
    or
    exists(Parameter p | p = n.(DataFlow::ParameterNode).getParameter() |
      kind = "parameter" and api = "" and index = p.getPosition()
    )
    or
    not n instanceof DataFlow::CallCfgNode and
    not n instanceof DataFlow::ParameterNode and
    kind = "expression" and
    api = "" and
    index = -1
  }

  /**
   * An export source. Threat-model sources are taken unfiltered (`ThreatModelSource::Range`, not
   * the configured threat models) so local sources are exported too; `sourceType` is the threat
   * model ("remote", "commandargs", "environment", "stdin", "file", "database", ...) and `model` is
   * "RemoteFlowSource" for "remote", else "ThreatModelSource". Catalog API sources (`model` "api")
   * apply only where no threat-model source exists on the node.
   */
  predicate source(
    DataFlow::Node n, string model, string sourceType, string nodeKind, string api, int index
  ) {
    nodeInSource(n) and
    exportedNode(n) and
    (
      sourceType = n.(ThreatModelSource::Range).getThreatModel() and
      (if sourceType = "remote" then model = "RemoteFlowSource" else model = "ThreatModelSource") and
      nodeShape(n, nodeKind, api, index)
      or
      not n instanceof ThreatModelSource::Range and
      exists(string mod |
        apiCallName(n, mod, api) and apiSourceArgument(mod, api, index) and index = -1
      ) and
      model = "api" and
      sourceType = "" and
      nodeKind = "return_value"
    )
  }
}
