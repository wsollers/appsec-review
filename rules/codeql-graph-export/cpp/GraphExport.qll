/**
 * Shared definitions for the appsec-review C/C++ code-graph export pack.
 *
 * LIVE-UNVERIFIED: written against the `codeql/cpp-all` library bundled with the pinned CodeQL
 * 2.27.0 CLI, but not compiled in the repository's offline CI. The live tier
 * (tests/live/test_codeql_graph_export_live.py) compiles and runs the pack on the pinned image.
 *
 * Export conventions (the column contract is ../columns.json):
 * - every exported column is a primitive `string` or `int`; no query exports an entity column, so
 *   no database-internal element id leaves the database;
 * - a location is five columns `<p>_path, <p>_start_line, <p>_start_column, <p>_end_line,
 *   <p>_end_column`: the path is relative to the database source root
 *   (`File.getRelativePath()`), lines and columns are 1-based and the end column is inclusive;
 *   an element outside the source root exports path "" and zero positions;
 * - booleans are the strings "true" and "false";
 * - classification into sink and source classes is not done here: rows carry the CodeQL model
 *   identity and the API name, and ../catalog.json classifies them downstream.
 */

import cpp
import semmle.code.cpp.ir.dataflow.DataFlow
import semmle.code.cpp.controlflow.Dominance
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.models.interfaces.FormattingFunction
import semmle.code.cpp.models.interfaces.Allocation
import semmle.code.cpp.models.interfaces.ArrayFunction
import semmle.code.cpp.models.interfaces.CommandExecution
import semmle.code.cpp.models.interfaces.FlowSource

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

  /** A function whose definition lies inside the source root. */
  class SourceFunction extends Function {
    SourceFunction() { this.hasDefinition() and inSource(this.getDefinition()) }
  }

  /** Holds in "whole_program" mode, where every function is exported. */
  predicate wholeProgram() { exportScope("whole_program", _) }

  /** The call-graph radius of the neighborhood in "seeded" mode. */
  private int scopeDepth() { exportScope("seeded", result) }

  /** Every defined override (including the static target) a virtual call may dispatch to. */
  Function virtualCandidate(FunctionCall call) {
    call.isVirtual() and
    (
      result = call.getTarget()
      or
      result = call.getTarget().(MemberFunction).getAnOverridingFunction+()
    ) and
    result.hasDefinition()
  }

  /** `caller` contains a call to `callee`, directly or as a virtual override candidate. */
  private predicate callEdge(SourceFunction caller, SourceFunction callee) {
    exists(Call call | call.getEnclosingFunction() = caller |
      callee = call.getTarget()
      or
      callee = virtualCandidate(call)
    )
  }

  /**
   * `f` is a source-root function whose definition (declarator through closing brace) overlaps
   * the seed lines `[startLine, endLine]` of `path`. Every overlapping function matches, so a
   * lambda and the function enclosing it both seed.
   */
  predicate seedMatch(string path, int startLine, int endLine, SourceFunction f) {
    exportSeed(path, startLine, endLine) and
    f.getDefinition().getFile().getRelativePath() = path and
    startLine <= functionEndLine(f) and
    endLine >= f.getDefinition().getLocation().getStartLine()
  }

  private int functionEndLine(SourceFunction f) {
    result = f.getBlock().getLocation().getEndLine()
    or
    not exists(f.getBlock()) and result = f.getDefinition().getLocation().getEndLine()
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

  /** `e` lies in an exported function, or outside any function in "whole_program" mode. */
  predicate exportedExpr(Expr e) { wholeProgram() or exported(e.getEnclosingFunction()) }

  /** The dataflow node lies in an exported function. */
  predicate exportedNode(DataFlow::Node n) {
    wholeProgram() or exported(n.getEnclosingCallable().getUnderlyingCallable().(Function))
  }

  /** Comma-joined sorted basenames of every file that declares `f` (the catalog `declared_in`). */
  string declaredIn(Function f) {
    result =
      concat(string name | name = f.getADeclarationEntry().getFile().getBaseName() | name, ","
        order by name)
  }

  /** `declaredIn` over every global or `std` function named `api` (overloads merged). */
  bindingset[api]
  string declaredInName(string api) {
    result =
      concat(string name |
        exists(Function f |
          f.hasGlobalOrStdName(api) and name = f.getADeclarationEntry().getFile().getBaseName()
        )
      |
        name, "," order by name
      )
  }

  /** "true" or "false". */
  bindingset[b]
  string flag(boolean b) { b = true and result = "true" or b = false and result = "false" }

  /**
   * Catalog API sinks: global or `std` function `name` and the dangerous argument `arg`
   * (-1: the call expression itself). Kept equal to the `api` sink rules of ../catalog.json by
   * tests/test_codeql_export_runner.py.
   */
  predicate apiSinkArgument(string name, int arg) {
    name = "strcpy" and arg = 1
    or
    name = "strcat" and arg = 1
    or
    name = "strncpy" and arg = 2
    or
    name = "strncat" and arg = 2
    or
    name = "memcpy" and arg = 2
    or
    name = "memmove" and arg = 2
    or
    name = "memset" and arg = 2
    or
    name = "gets" and arg = 0
    or
    name = "system" and arg = 0
    or
    name = "popen" and arg = 0
    or
    name = "execv" and arg = 0
    or
    name = "execvp" and arg = 0
    or
    name = "fopen" and arg = 0
    or
    name = "open" and arg = 0
    or
    name = "unlink" and arg = 0
    or
    name = "sqlite3_exec" and arg = 1
    or
    name = "mysql_query" and arg = 1
    or
    name = "dlopen" and arg = 0
    or
    name = "syslog" and arg = 1
    or
    name = "rand" and arg = -1
  }

  /**
   * Catalog API sources: `arg` -1 is the return value, n >= 0 the buffer written through
   * argument n. Kept equal to the `api` source rules of ../catalog.json.
   */
  predicate apiSourceArgument(string name, int arg) {
    name = "getenv" and arg = -1
    or
    name = "secure_getenv" and arg = -1
    or
    name = "fgets" and arg = 0
    or
    name = "fread" and arg = 0
    or
    name = "read" and arg = 1
    or
    name = "recv" and arg = 1
    or
    name = "recvfrom" and arg = 1
    or
    name = "getchar" and arg = -1
    or
    name = "msgrcv" and arg = 1
    or
    name = "mq_receive" and arg = 1
    or
    name = "sqlite3_column_text" and arg = -1
    or
    name = "mysql_fetch_row" and arg = -1
  }

  /** Catalog sanitizer APIs. Kept equal to the `sanitizers` of ../catalog.json. */
  predicate sanitizerApi(string name) {
    name = ["realpath", "canonicalize_file_name", "mysql_real_escape_string", "sqlite3_bind_text"]
  }

  private predicate apiCallSink(Call call, Expr operand, int arg, string api) {
    call.getTarget().hasGlobalOrStdName(api) and
    apiSinkArgument(api, arg) and
    (
      arg >= 0 and operand = call.getArgument(arg)
      or
      arg = -1 and operand = call
    )
  }

  private predicate argumentInput(FunctionInput input, int arg) {
    input.isParameter(arg) or input.isParameterDeref(arg)
  }

  /** Model-based sinks; a catalog API match suppresses every model match on the same call. */
  private predicate modelCallSink(Call call, Expr operand, int arg, string model) {
    not apiSinkArgument(call.getTarget().getName(), _) and
    operand = call.getArgument(arg) and
    (
      call.getTarget().(FormattingFunction).getFormatParameterIndex() = arg and
      model = "FormattingFunction"
      or
      call.getTarget().(AllocationFunction).getSizeArg() = arg and model = "AllocationFunction"
      or
      call.getTarget().(ArrayFunction).hasArrayOutput(arg) and model = "ArrayFunction.output"
      or
      exists(FunctionInput input |
        call.getTarget().(CommandExecutionFunction).hasCommandArgument(input) and
        argumentInput(input, arg) and
        model = "CommandExecutionFunction"
      )
      or
      exists(FunctionInput input |
        call.getTarget().(RemoteFlowSinkFunction).hasRemoteFlowSink(input, _) and
        argumentInput(input, arg) and
        model = "RemoteFlowSinkFunction"
      )
    )
  }

  /**
   * A sink candidate: `sinkExpr` (a call or an array write) uses `operand` at argument `arg`
   * (-1 when the operand is not a call argument). `model` is "api" for a catalog API match,
   * otherwise the CodeQL model class; `api` is the target's name ("" for an array write).
   */
  predicate sink(Expr sinkExpr, Expr operand, int arg, string model, string api) {
    inSource(sinkExpr) and
    exportedExpr(sinkExpr) and
    (
      exists(Call call | sinkExpr = call |
        apiCallSink(call, operand, arg, api) and model = "api"
        or
        modelCallSink(call, operand, arg, model) and api = call.getTarget().getName()
      )
      or
      exists(ArrayExpr write, Assignment assignment |
        assignment.getLValue() = write and sinkExpr = write
      |
        operand = write.getArrayOffset() and arg = -1 and model = "ArrayExprWrite" and api = ""
      )
    )
  }

  /** The dataflow node that reaches the sink operand (its value or, for pointers, its pointee). */
  predicate sinkNode(DataFlow::Node n, Expr sinkExpr, int arg) {
    exists(Expr operand | sink(sinkExpr, operand, arg, _, _) |
      n.asExpr() = operand or n.asIndirectExpr() = operand
    )
  }

  /** Number of catalog sanitizer calls that dominate `sinkExpr` in its function. */
  int dominatingSanitizerCount(Expr sinkExpr) {
    result =
      count(Call sanitizer |
        sanitizerApi(sanitizer.getTarget().getName()) and
        sanitizer.getEnclosingFunction() = sinkExpr.getEnclosingFunction() and
        dominates(sanitizer, sinkExpr) and
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
   * How a source node relates to the code: `kind` is "return_value" or "output_argument" of a
   * call to `api` (`index` the argument, -1 for the return value), "parameter" (`index` the
   * parameter position), or "expression".
   */
  private predicate nodeShape(DataFlow::Node n, string kind, string api, int index) {
    exists(Call call | n.asExpr() = call |
      kind = "return_value" and api = call.getTarget().getName() and index = -1
    )
    or
    exists(Call call, int i | n.asDefiningArgument() = call.getArgument(i) |
      kind = "output_argument" and api = call.getTarget().getName() and index = i
    )
    or
    exists(Parameter p | n.asParameter() = p or n.asParameter(_) = p |
      kind = "parameter" and api = "" and index = p.getIndex()
    )
    or
    not exists(Call call | n.asExpr() = call) and
    not exists(n.asDefiningArgument()) and
    not exists(n.asParameter(_)) and
    kind = "expression" and
    api = "" and
    index = -1
  }

  /**
   * A source candidate: `model` is the CodeQL model class ("api" for a catalog API source the
   * model library does not cover), `sourceType` CodeQL's `getSourceType()` ("" for "api").
   */
  predicate source(
    DataFlow::Node n, string model, string sourceType, string kind, string api, int index
  ) {
    (inSource(n.asExpr()) or inSource(n.asParameter(_)) or inSource(n.asDefiningArgument())) and
    exportedNode(n) and
    (
      model = modelClass(n) and
      sourceType = n.(FlowSource).getSourceType() and
      nodeShape(n, kind, api, index)
      or
      not n instanceof FlowSource and
      model = "api" and
      sourceType = "" and
      exists(Call call, string name |
        call.getTarget().hasGlobalOrStdName(name) and apiSourceArgument(name, index)
      |
        index = -1 and n.asExpr() = call and kind = "return_value" and api = name
        or
        index >= 0 and
        n.asDefiningArgument() = call.getArgument(index) and
        kind = "output_argument" and
        api = name
      )
    )
  }
}
