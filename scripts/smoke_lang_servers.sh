#!/usr/bin/env bash
# smoke_lang_servers.sh IMAGE_ID            (inside the image)
# smoke_lang_servers.sh --docker IMAGE_ID   (from the repo root on the host: runs the line below)
#
# Proves a compiler image's language tooling before it is pointed at a target (brief C step 7,
# docs/language-servers.md §8). Inside the container the repository is mounted read-only at
# /workspace and /scratch is writable, with no network:
#
#   images/audit-buildenv-common/run.sh IMAGE:local . scratch/lsp-smoke/IMAGE -- \
#     bash /workspace/scripts/smoke_lang_servers.sh IMAGE
#
# For each language server of the image it copies images/test/lsp/<lang> to /scratch, runs
# appsec-review-process/lsp_driver.py (documentSymbol, definition, references, incomingCalls) and
# checks that the helper symbol is listed and its call site resolves to its definition line. It then
# checks the tree-sitter CLI and runs treesitter_ast.py over the fixtures, and on the CodeQL images
# checks the bundle, the .NET SDK (audit-codeql) or a traced replay plus the graph queries
# (audit-codeql-native). One line per check: PASS, FAIL or INFO. Exit status 1 if any check FAILs.
set -uo pipefail

if [ "${1:-}" = "--docker" ]; then
  image=${2:?usage: $0 --docker IMAGE_ID}
  repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
  mkdir -p "$repo/scratch/lsp-smoke/$image"
  exec "$repo/images/audit-buildenv-common/run.sh" "$image:local" "$repo" "$repo/scratch/lsp-smoke/$image" -- \
    bash /workspace/scripts/smoke_lang_servers.sh "$image"
fi

image=${1:?usage: $0 IMAGE_ID | --docker IMAGE_ID}
REPO=${SMOKE_REPO:-/workspace}
OUT=${SMOKE_OUT:-/scratch/lsp-smoke}
DRIVER="$REPO/appsec-review-process/lsp_driver.py"
AST="$REPO/appsec-review-process/treesitter_ast.py"
FIXTURES="$REPO/images/test/lsp"
PY=$(command -v python3 || command -v python)
TSPY=${SMOKE_TS_PYTHON:-/opt/treesitter/bin/python}
mkdir -p "$OUT"
failures=0
report() {  # STATUS NAME DETAIL
  printf '%-4s %-34s %s\n' "$1" "$2" "$3"
  [ "$1" = FAIL ] && failures=$((failures + 1))
  return 0
}

# server  fixture-dir  file  def-line def-char(call site)  helper-line helper-char
servers_for() {
  case "$1" in
    audit-buildenv-cpp|audit-buildenv-cpp-resolute)
      echo "clangd cpp main.cpp 6 11 1 11" ;;
    audit-buildenv-dotnet) echo "csharp-ls csharp Program.cs 7 32 5 15" ;;
    audit-buildenv-go) echo "gopls go main.go 8 5 3 5" ;;
    audit-buildenv-java) echo "jdtls java src/main/java/smoke/Main.java 9 20 4 15" ;;
    audit-buildenv-php) echo "phpactor php main.php 10 11 3 9" ;;
    audit-buildenv-python)
      echo "pylsp python main.py 6 11 1 4"
      echo "basedpyright python main.py 6 11 1 4" ;;
    audit-buildenv-rust) echo "rust-analyzer rust src/main.rs 6 26 1 3" ;;
    audit-buildenv-typescript)
      echo "typescript-language-server typescript main.ts 6 9 1 16"
      echo "vscode-json-language-server json data.json 0 0 0 0" ;;
    audit-codeql|audit-codeql-native) ;;
    *) return 1 ;;
  esac
}

check_server() {  # server lang file call_line call_char helper_line helper_char
  local server=$1 lang=$2 file=$3 call_line=$4 call_char=$5 line=$6 char=$7
  local root="$OUT/fixtures/$server" result="$OUT/$server.json"
  rm -rf "$root"; mkdir -p "$(dirname "$root")"; cp -r "$FIXTURES/$lang" "$root"
  local queries=(--query "{\"method\":\"documentSymbol\",\"path\":\"$file\"}")
  if [ "$line" != 0 ]; then
    queries+=(--query "{\"method\":\"definition\",\"path\":\"$file\",\"line\":$call_line,\"character\":$call_char}"
              --query "{\"method\":\"references\",\"path\":\"$file\",\"line\":$line,\"character\":$char}"
              --query "{\"method\":\"incomingCalls\",\"path\":\"$file\",\"line\":$line,\"character\":$char}")
  fi
  "$PY" "$DRIVER" --server "$server" --root "$root" --state-dir "$OUT/state/$server" \
    --total-seconds "${SMOKE_TOTAL_SECONDS:-240}" --request-seconds "${SMOKE_REQUEST_SECONDS:-90}" \
    "${queries[@]}" --out "$result" 2>/dev/null
  "$PY" - "$result" "$server" "$line" <<'PY'
import json, sys
path, server, line = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    document = json.load(open(path, encoding="utf-8"))
except (OSError, ValueError):
    print(f"FAIL {server:<34} no driver output"); sys.exit(1)
gaps = "; ".join(f"{g['kind']}: {g['detail']}" for g in document["gaps"])[:300]
results = document["results"]
info = document["server"].get("info") or {}
version = (info.get("version") or "?")[:40]
problems = []
if document["status"] == "FAILED" or not results:
    problems.append(f"status {document['status']} ({gaps or 'no results'})")
else:
    symbols = results[0]
    names = {row.get("name") for row in symbols["results"]}
    if symbols["status"] != "OK" or (line and not names & {"helper", "Helper"}) or not names:
        problems.append(f"documentSymbol {symbols['status']} {sorted(n for n in names if n)[:5]}")
    if line:
        definition = results[1]
        lines = [row["start_line"] for row in definition["results"]]
        if definition["status"] != "OK" or line not in lines:
            problems.append(f"definition {definition['status']} {lines[:5]} (want {line})")
if problems:
    print(f"FAIL {server:<34} " + "; ".join(problems)); sys.exit(1)
extra = ""
if line:
    references, incoming = results[2], results[3]
    extra = (f" references={len(references['results']) if references['status'] == 'OK' else 'gap'}"
             f" incomingCalls={len(incoming['results']) if incoming['status'] == 'OK' else 'gap'}")
print(f"PASS {server:<34} version={version}{extra}")
PY
  [ $? -eq 0 ] || failures=$((failures + 1))
}

check_treesitter() {
  if ! command -v tree-sitter >/dev/null; then report FAIL tree-sitter-cli "not on PATH"; return; fi
  local version; version=$(tree-sitter --version 2>&1 | head -1)
  if [ "$version" = "tree-sitter 0.26.13" ]; then report PASS tree-sitter-cli "$version"
  else report FAIL tree-sitter-cli "unexpected version: $version"; fi
  if [ ! -x "$TSPY" ]; then report FAIL treesitter_ast.py "$TSPY missing"; return; fi
  if "$TSPY" "$AST" --root "$FIXTURES" --label lsp-fixtures --out "$OUT/treesitter-ast.json" \
       --stats "$OUT/treesitter-ast.stats.json" 2>"$OUT/treesitter-ast.log"; then
    "$TSPY" - "$OUT/treesitter-ast.json" "$REPO/appsec-review-process" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[2])
import treesitter_ast
document = json.load(open(sys.argv[1], encoding="utf-8"))
languages = sorted({row["language"] for row in document["files"]})
helpers = sum(1 for row in document["files"] for fn in row["functions"] if (fn["name"] or "").lower() == "helper")
ok = treesitter_ast.verify(document) and helpers >= 8 and not document["totals"]["error_nodes"]
print(f"{'PASS' if ok else 'FAIL'} {'treesitter_ast.py':<34} files={document['totals']['files']} "
      f"helpers={helpers} languages={','.join(languages)} grammars={len(document['generator']['grammars'])}")
sys.exit(0 if ok else 1)
PY
    [ $? -eq 0 ] || failures=$((failures + 1))
  else
    report FAIL treesitter_ast.py "$(tail -1 "$OUT/treesitter-ast.log")"
  fi
}

check_codeql() {
  local codeql=/opt/codeql/codeql
  [ -x "$codeql" ] || return 0
  export HOME=${HOME:-/tmp/home}
  local version; version=$("$codeql" version --format=terse 2>/dev/null)
  if [ "$version" = 2.27.0 ]; then report PASS codeql "version $version"; else report FAIL codeql "version '$version'"; fi
  if "$codeql" resolve languages --format=json >"$OUT/codeql-languages.json" 2>/dev/null; then
    report PASS codeql-languages "$("$PY" -c 'import json,sys; print(",".join(sorted(json.load(open(sys.argv[1])))))' "$OUT/codeql-languages.json")"
  else report FAIL codeql-languages "codeql resolve languages failed"; fi
  if [ "$image" = audit-codeql ]; then
    if dotnet --list-sdks 2>/dev/null | grep -q '^9\.0\.318 '; then report PASS dotnet-sdk "9.0.318 (C# build-mode none)"
    else report FAIL dotnet-sdk "dotnet 9.0.318 SDK not found"; fi
    rm -rf "$OUT/codeql-cs"; mkdir -p "$OUT/codeql-cs"
    if (cd "$OUT/codeql-cs" && "$codeql" database create db --language=csharp --build-mode=none \
          --source-root="$FIXTURES/csharp" >create.log 2>&1); then
      report PASS codeql-csharp-none "database created from images/test/lsp/csharp"
    else report FAIL codeql-csharp-none "see $OUT/codeql-cs/create.log"; fi
    rm -rf "$OUT/codeql-cs/db"
  fi
  if [ "$image" = audit-codeql-native ]; then
    local work="$OUT/codeql-traced"; rm -rf "$work"; mkdir -p "$work/db-input/unit" "$work/queries"
    cp "$REPO"/queries/appsec-graph-cpp/* "$work/queries/"
    printf '[{"file": "%s", "directory": "%s", "arguments": ["/opt/llvm/bin/clang++", "-std=c++17", "-c", "%s"]}]\n' \
      "$FIXTURES/cpp/main.cpp" "$FIXTURES/cpp" "$FIXTURES/cpp/main.cpp" > "$work/db-input/unit/compile_commands.json"
    for query in CallEdges EntryPoints FlowSources; do
      if "$codeql" query compile --additional-packs=/opt/codeql/qlpacks --check-only "$work/queries/$query.ql" \
           >"$work/compile-$query.log" 2>&1; then report PASS "codeql-graph-compile:$query" "compiles"
      else report FAIL "codeql-graph-compile:$query" "see $work/compile-$query.log"; fi
    done
    # The lane writes /scratch/db, /scratch/codeql.sarif, /scratch/replay.json and /scratch/graph.
    if bash /opt/scripts/codeql-sast-lane.sh cpp traced codeql/cpp-queries:codeql-suites/cpp-security-extended.qls \
         2 2048 "$work/db-input/unit/compile_commands.json" "$work/queries" >"$work/lane.log" 2>&1; then
      report PASS codeql-traced-lane "replay $(cat /scratch/replay.json 2>/dev/null)"
      for query in CallEdges EntryPoints FlowSources; do
        if [ -s "/scratch/graph/$query.csv" ]; then
          report PASS "codeql-graph-run:$query" "$(($(wc -l < "/scratch/graph/$query.csv") - 1)) row(s)"
        else report FAIL "codeql-graph-run:$query" "see /scratch/graph/$query.log"; fi
      done
    else report FAIL codeql-traced-lane "see $work/lane.log"; fi
  fi
}

if ! listing=$(servers_for "$image"); then
  echo "unknown image id: $image" >&2; exit 2
fi
echo "== $image language tooling smoke ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
if [ -n "$listing" ]; then
  while read -r server lang file call_line call_char line char; do
    executable=$server
    [ "$server" = basedpyright ] && executable=basedpyright-langserver
    if command -v "$executable" >/dev/null; then
      check_server "$server" "$lang" "$file" "$call_line" "$call_char" "$line" "$char"
    else
      report FAIL "$server" "executable not on PATH"
    fi
  done <<< "$listing"
fi
check_treesitter
check_codeql
echo "== $image: $failures failure(s); driver outputs under $OUT"
[ "$failures" -eq 0 ]
