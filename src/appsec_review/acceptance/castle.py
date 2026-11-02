"""CASTLE-C250 as a pinned, blind, buildable public C regression corpus (scoring design decision 12).

``prepare`` turns a clone of the upstream CASTLE-Benchmark repository, checked out at the commit pinned
in ``data/reference/castle/castle-c250.lock.json``, into a blind git repository outside this repository:
renamed sources with comment text blanked (line numbers unchanged), a neutral ``CMakeLists.txt`` and
``README.md``, one deterministic commit and the tag ``castle-c250-v1``. ``key`` (or ``prepare --key``)
writes the scoring key, which lives only in this repository and never in the target.

Pure standard library plus ``git``; no network access.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.acceptance.scoring_model import FILE_SCOPE, normalize_cwe

LOCK_SCHEMA = "appsec-review/castle-lock/1"
REPOSITORY = Path(__file__).resolve().parents[3]
LOCK_PATH = REPOSITORY / "data" / "reference" / "castle" / "castle-c250.lock.json"
KEY_PATH = REPOSITORY / "test" / "acceptance" / "castle-c250-v1" / "expectations.toml"
SOURCE_DIR = "src"
BUILD_LINE = "cmake -S . -B build && cmake --build build"
PAPER_REFERENCE_KEYS = frozenset({"tool", "version", "producer", "tp", "tn", "fp", "fn", "castle_score"})

# Same expression as ANSWER_MARKER in tests/test_blind_target_isolation.py (a test module, which this
# package must not import); tests/test_castle_corpus.py asserts the two stay equal.
ANSWER_MARKER = re.compile(
    r"(?:cwe[-_ ]?\d+|vulnerab(?:le|ility)|exploit|answer[-_ ]?key|"
    r"ground[-_ ]?truth|oracle|expected[-_ ]?findings?|remediation)",
    re.IGNORECASE,
)

_UPSTREAM_NAME = re.compile(r"^CASTLE-(\d+)-(\d+)\.c$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CastleError(RuntimeError):
    """Preparation or key generation refused; the message names the reason."""


# --- comment blanking ---------------------------------------------------------------------------

def _splice(text: str, index: int) -> int:
    """Length of a backslash-newline line splice at ``index`` (0 when there is none)."""

    if text.startswith("\\\n", index):
        return 2
    if text.startswith("\\\r\n", index):
        return 3
    return 0


def _logical(text: str, index: int) -> int:
    """First index at or after ``index`` that is not part of a line splice."""

    while (length := _splice(text, index)):
        index += length
    return index


def strip_comments(code: str) -> str:
    """Replace every C comment character with a space, keeping every newline.

    The lexer follows translation phases 2-3: line splices are invisible (a ``//`` comment continued
    by a backslash-newline goes on to the next line, and a comment delimiter may be split by one),
    and string and character literals are copied verbatim, so ``"//"`` or ``'/*'`` stay code. Lines
    whose comment was blanked lose trailing blanks; every other byte keeps its line and column.
    """

    out = list(code)
    changed: set[int] = set()  # indices of blanked characters, to trim only lines a comment touched

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if out[position] not in "\r\n":
                out[position] = " "
                changed.add(position)

    size = len(code)
    index = 0
    while index < size:
        index = _logical(code, index)
        if index >= size:
            break
        char = code[index]
        if char in "\"'":
            index += 1
            while index < size:
                index = _logical(code, index)
                if index >= size or code[index] == char:
                    index += 1
                    break
                if code[index] == "\\":
                    index += 1
                elif code[index] == "\n":
                    break  # an unterminated literal ends at the line end, as the preprocessor treats it
                index += 1
            continue
        if char == "/":
            follower = _logical(code, index + 1)
            kind = code[follower] if follower < size else ""
            if kind == "/":
                end = follower + 1
                while end < size:
                    if (length := _splice(code, end)):
                        end += length
                        continue
                    if code[end] == "\n":
                        break
                    end += 1
                blank(index, end)
                index = end
                continue
            if kind == "*":
                end = follower + 1
                while True:
                    end = _logical(code, end)
                    if end >= size:
                        raise CastleError("unterminated block comment")
                    if code[end] == "*":
                        closer = _logical(code, end + 1)
                        if closer < size and code[closer] == "/":
                            end = closer + 1
                            break
                    end += 1
                blank(index, end)
                index = end
                continue
        index += 1

    lines: list[str] = []
    start = 0
    for line in "".join(out).split("\n"):
        body = line.removesuffix("\r")
        ending = line[len(body):]
        if any(position in changed for position in range(start, start + len(body))):
            body = body.rstrip(" \t")
        lines.append(body + ending)
        start += len(line) + 1
    result = "\n".join(lines)
    if result.count("\n") != code.count("\n"):
        raise CastleError("comment blanking changed the line count")
    return result


# --- naming, build mapping and marker scan ------------------------------------------------------

def blind_name(salt: str, upstream_name: str) -> str:
    """``t`` + first 10 hex of ``sha256(salt + upstream name)`` + ``.c``: no CWE, no order."""

    return "t" + hashlib.sha256((salt + upstream_name).encode("utf-8")).hexdigest()[:10] + ".c"


@dataclass(frozen=True)
class BuildSpec:
    """Per-target build settings derived from one upstream ``compile`` line."""

    libraries: tuple[str, ...]  # keys of _LIBRARIES, in compile-line order
    compile_options: tuple[str, ...]
    link_options: tuple[str, ...]


# compile-line token -> (library key, CMake link item); the key selects the find step in _FIND.
_LIBRARIES: Mapping[str, tuple[str, str]] = {
    "-lssl": ("openssl", "OpenSSL::SSL"),
    "-lcrypto": ("openssl", "OpenSSL::Crypto"),
    "-lsqlite3": ("sqlite3", "SQLite::SQLite3"),
    "-lcurl": ("curl", "CURL::libcurl"),
    "-lmysqlclient": ("mysqlclient", "PkgConfig::MYSQLCLIENT"),
    "-lm": ("m", "m"),
    "-lpthread": ("threads", "Threads::Threads"),
    "-pthread": ("threads", "Threads::Threads"),
}
_FIND: Mapping[str, tuple[str, ...]] = {
    "openssl": ("find_package(OpenSSL REQUIRED)",),
    "sqlite3": ("find_package(SQLite3 REQUIRED)",),
    "curl": ("find_package(CURL REQUIRED)",),
    "mysqlclient": ("find_package(PkgConfig REQUIRED)",
                    "pkg_check_modules(MYSQLCLIENT REQUIRED IMPORTED_TARGET mysqlclient)"),
    "threads": ("find_package(Threads REQUIRED)",),
    "m": (),
}
_FIND_ORDER = ("openssl", "sqlite3", "curl", "mysqlclient", "threads", "m")
_LINK_ONLY = {"-no-pie"}
_COMPILE_FLAG = re.compile(r"^-(?:W[\w=,+-]*|f[\w=,+-]+|O[0-3sgz]?|g\d?|std=[\w+]+|D\w+(?:=\S*)?)$")


def parse_compile(compile_line: str, upstream_name: str) -> BuildSpec:
    """Map ``gcc <name>.c -o <stem> [flags]`` to libraries and per-target flags; unknown tokens fail."""

    tokens = compile_line.split()
    stem = upstream_name.removesuffix(".c")
    if tokens[:4] != ["gcc", upstream_name, "-o", stem]:
        raise CastleError(f"{upstream_name}: unexpected compile line {compile_line!r}")
    libraries: list[str] = []
    compile_options: list[str] = []
    link_options: list[str] = []
    rest = tokens[4:]
    index = 0
    while index < len(rest):
        token = rest[index]
        if token in _LIBRARIES:
            libraries.append(token)
        elif token in _LINK_ONLY:
            link_options.append(token)
        elif token == "-z" and index + 1 < len(rest):
            link_options.append(f"LINKER:-z,{rest[index + 1]}")
            index += 1
        elif _COMPILE_FLAG.match(token):
            compile_options.append(token)
        else:
            raise CastleError(f"{upstream_name}: unmapped compile token {token!r}")
        index += 1
    return BuildSpec(tuple(libraries), tuple(compile_options), tuple(link_options))


def link_items(spec: BuildSpec) -> tuple[str, ...]:
    items: list[str] = []
    for token in spec.libraries:
        item = _LIBRARIES[token][1]
        if item not in items:
            items.append(item)
    return tuple(items)


def render_cmake(targets: Sequence[tuple[str, BuildSpec]]) -> str:
    """A neutral CMakeLists.txt: one executable per ``src/<name>.c``; missing libraries fail configure."""

    used = {_LIBRARIES[token][0] for _, spec in targets for token in spec.libraries}
    lines = ["cmake_minimum_required(VERSION 3.16)", "project(samples LANGUAGES C)", ""]
    finds = [line for library in _FIND_ORDER if library in used for line in _FIND[library]]
    if finds:
        lines += [*finds, ""]
    for name, spec in sorted(targets):
        target = name.removesuffix(".c")
        lines.append(f"add_executable({target} {SOURCE_DIR}/{name})")
        if spec.compile_options:
            lines.append(f"target_compile_options({target} PRIVATE {' '.join(spec.compile_options)})")
        if spec.link_options:
            lines.append(f"target_link_options({target} PRIVATE {' '.join(spec.link_options)})")
        if spec.libraries:
            lines.append(f"target_link_libraries({target} PRIVATE {' '.join(link_items(spec))})")
    return "\n".join(lines) + "\n"


def render_readme() -> str:
    return f"Build: `{BUILD_LINE}`\n"


def marker_hits(files: Mapping[str, str], origins: Mapping[str, str] | None = None) -> list[str]:
    """Every ANSWER_MARKER hit in an output path or content line, as ``path[:line] (origin): text``."""

    hits: list[str] = []
    for path in sorted(files):
        origin = f" ({origins[path]})" if origins and path in origins else ""
        if (match := ANSWER_MARKER.search(path)):
            hits.append(f"{path}{origin}: path matches {match.group(0)!r}")
        for number, line in enumerate(files[path].split("\n"), start=1):
            for match in ANSWER_MARKER.finditer(line):
                hits.append(f"{path}:{number}{origin}: {match.group(0)!r} in {line.strip()!r}")
    return hits


# --- lock, upstream and dataset -----------------------------------------------------------------

def load_lock(path: Path = LOCK_PATH) -> dict[str, Any]:
    lock = json.loads(path.read_text(encoding="utf-8"))
    if lock.get("schema") != LOCK_SCHEMA:
        raise CastleError(f"{path}: schema must be {LOCK_SCHEMA}")
    upstream, dataset, blind = lock.get("upstream"), lock.get("dataset"), lock.get("blind")
    if not all(isinstance(value, dict) for value in (upstream, dataset, blind)):
        raise CastleError(f"{path}: upstream, dataset and blind sections are required")
    if not _SHA1.match(str(upstream.get("commit"))) or not _SHA256.match(str(dataset.get("sha256"))):
        raise CastleError(f"{path}: upstream commit and dataset sha256 must be full hex digests")
    if blind.get("commit") is not None and not _SHA1.match(str(blind["commit"])):
        raise CastleError(f"{path}: blind commit must be a full SHA-1 or null")
    for field in ("salt", "tag", "message"):
        if not isinstance(blind.get(field), str) or not blind[field]:
            raise CastleError(f"{path}: blind.{field} is required")
    author = blind.get("author")
    if not isinstance(author, dict) or not all(isinstance(author.get(key), str) and author[key]
                                               for key in ("name", "email", "date")):
        raise CastleError(f"{path}: blind.author needs name, email and date")
    for row in lock.get("paper_reference", ()):
        if set(row) != PAPER_REFERENCE_KEYS:
            raise CastleError(f"{path}: paper_reference rows need exactly {sorted(PAPER_REFERENCE_KEYS)}")
    return lock


def _git_env() -> dict[str, str]:
    """Isolate git from user and system configuration (hooks, signing, filters, templates)."""

    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"})
    return env


def _git(cwd: Path, *args: str, env: Mapping[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
         *args], cwd=cwd, env=dict(env or _git_env()), capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise CastleError(f"git {' '.join(args)} failed in {cwd}: {result.stderr.strip()}")
    return result.stdout.strip()


@dataclass(frozen=True)
class CastleTest:
    name: str
    cwe: str
    number: int
    vulnerable: bool
    lines: tuple[int, ...]
    description: str
    compile: str
    code: str

    @property
    def id(self) -> str:
        return f"castle-{self.cwe.removeprefix('CWE-')}-{self.number}"

    @property
    def line_count(self) -> int:
        return line_count(self.code)


def line_count(text: str) -> int:
    """Lines as a compiler numbers them: newline-terminated, plus a final unterminated line."""

    return text.count("\n") + (1 if text and not text.endswith("\n") else 0)


def load_upstream(upstream: Path, lock: Mapping[str, Any]) -> list[CastleTest]:
    """Verify the clone's commit, the dataset hash and every source file; return tests by name."""

    upstream = upstream.resolve()
    if not upstream.is_dir():
        raise CastleError(f"upstream clone not found: {upstream}")
    head = _git(upstream, "rev-parse", "HEAD")
    if head != lock["upstream"]["commit"]:
        raise CastleError(f"upstream HEAD {head} is not the pinned commit {lock['upstream']['commit']}")
    dataset_path = upstream / lock["dataset"]["path"]
    data = dataset_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != lock["dataset"]["sha256"]:
        raise CastleError(f"{lock['dataset']['path']} sha256 {digest} differs from the lock")
    document = json.loads(data.decode("utf-8"))
    rows = document.get("tests")
    if not isinstance(rows, list) or len(rows) != lock["dataset"]["test_count"]:
        raise CastleError(f"dataset must hold {lock['dataset']['test_count']} tests")
    source_dir = upstream / lock["dataset"]["source_dir"]
    tests: list[CastleTest] = []
    for row in rows:
        name = str(row["name"])
        match = _UPSTREAM_NAME.match(name)
        cwe = normalize_cwe(row["cwe"])
        # Upstream ``number`` is the global sequence (1..250); the per-CWE index is ``id``'s suffix.
        if match is None or cwe is None or int(match.group(1)) != int(row["cwe"]) \
                or str(row["id"]) != f"{int(match.group(1))}-{int(match.group(2))}":
            raise CastleError(f"{name}: name, cwe and id disagree")
        if (source_dir / name).read_bytes() != str(row["code"]).encode("utf-8"):
            raise CastleError(f"{name}: source file differs from the dataset code")
        lines = tuple(sorted({int(line) for line in row["lines"]}))
        test = CastleTest(name, cwe, int(match.group(2)), bool(row["vulnerable"]), lines,
                    str(row["description"]), str(row["compile"]), str(row["code"]))
        if test.vulnerable and not lines:
            raise CastleError(f"{name}: a vulnerable test needs lines")
        if lines and (lines[0] < 1 or lines[-1] > test.line_count):
            raise CastleError(f"{name}: lines {list(lines)} fall outside the file")
        tests.append(test)
    if len({test.name for test in tests}) != len(tests):
        raise CastleError("dataset test names are not unique")
    if sorted(int(row["number"]) for row in rows) != list(range(1, len(rows) + 1)):
        raise CastleError("dataset sequence numbers are not 1..test_count")
    return sorted(tests, key=lambda test: test.name)


# --- preparation ----------------------------------------------------------------------------------

def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def blind_files(tests: Iterable[CastleTest], salt: str) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """``(files, origins, blind paths by upstream name)`` of the blind repository, in memory."""

    files: dict[str, str] = {}
    origins: dict[str, str] = {}
    paths: dict[str, str] = {}
    targets: list[tuple[str, BuildSpec]] = []
    for test in tests:
        name = blind_name(salt, test.name)
        path = f"{SOURCE_DIR}/{name}"
        if path in files:
            raise CastleError(f"blind name collision: {test.name} and {origins[path]}")
        stripped = strip_comments(test.code)
        if line_count(stripped) != test.line_count:
            raise CastleError(f"{test.name}: comment blanking changed the line count")
        files[path], origins[path], paths[test.name] = stripped, test.name, path
        targets.append((name, parse_compile(test.compile, test.name)))
    files["CMakeLists.txt"] = render_cmake(targets)
    files["README.md"] = render_readme()
    return files, origins, paths


def _commit(output: Path, files: Mapping[str, str], blind: Mapping[str, Any]) -> str:
    for relative, content in sorted(files.items()):
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))
        path.chmod(0o644)
    env = _git_env()
    author = blind["author"]
    env.update({"GIT_AUTHOR_NAME": author["name"], "GIT_AUTHOR_EMAIL": author["email"],
                "GIT_AUTHOR_DATE": author["date"], "GIT_COMMITTER_NAME": author["name"],
                "GIT_COMMITTER_EMAIL": author["email"], "GIT_COMMITTER_DATE": author["date"]})
    _git(output, "init", "-q", "-b", "main", env=env)
    _git(output, "add", "--all", env=env)
    _git(output, "commit", "-q", "--no-verify", "-m", blind["message"], env=env)
    _git(output, "tag", blind["tag"], env=env)
    return _git(output, "rev-parse", "HEAD", env=env)


def write_lock(lock: Mapping[str, Any], path: Path) -> None:
    path.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def prepare(upstream: Path, output: Path, *, key: Path | None = None, record: bool = False,
            lock_path: Path = LOCK_PATH, repository: Path = REPOSITORY) -> str:
    """Write the blind repository to ``output`` and return its commit SHA (decision 12).

    ``repository`` is the tree the blind target must stay outside of (this repository by default).
    """

    lock = load_lock(lock_path)
    output = output.resolve()
    if _inside(output, repository.resolve()):
        raise CastleError(f"output {output} is inside this repository")
    if _inside(output, upstream.resolve()):
        raise CastleError(f"output {output} is inside the upstream clone")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise CastleError(f"output {output} is not an empty directory")
    if key is not None and _inside(key.resolve(), output):
        raise CastleError("the key must not be written inside the blind target")
    tests = load_upstream(upstream, lock)
    files, origins, paths = blind_files(tests, lock["blind"]["salt"])
    hits = marker_hits(files, origins)
    if hits:
        raise CastleError("answer markers in blind output:\n" + "\n".join(hits))
    output.mkdir(parents=True, exist_ok=True)
    sha = _commit(output, files, lock["blind"])
    expected = lock["blind"].get("commit")
    if sha != expected:
        if not record:
            raise CastleError(f"blind commit {sha} differs from the lock's {expected}; rerun with --record "
                              "only when the pinned inputs or preparation intentionally changed")
        lock = {**lock, "blind": {**lock["blind"], "commit": sha}}
        write_lock(lock, lock_path)
    if key is not None:
        write_key(tests, paths, lock, key)
    return sha


# --- key ----------------------------------------------------------------------------------------

def _toml(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml(item) for item in value) + "]"
    raise TypeError(f"unsupported TOML value {value!r}")


def render_key(tests: Sequence[CastleTest], paths: Mapping[str, str], lock: Mapping[str, Any],
               *, key_lock_path: str = "data/reference/castle/castle-c250.lock.json") -> str:
    """The scoring key: one ``[[defect]]`` per vulnerable test, one ``[[control]]`` per other test.

    Every case is ``scope = "file"`` (one CASTLE file is one case). A control's target lines are the
    whole file (``line = 1``, ``end_line`` = its last line): CASTLE gives controls no lines, and any
    report attributed to a control counts against it wherever it lands.
    """

    blind = lock["blind"]
    if not blind.get("commit"):
        raise CastleError("the lock has no blind commit; run prepare --record first")
    ordered = sorted(tests, key=lambda test: (int(test.cwe.removeprefix("CWE-")), test.number))
    corpus = [
        ("name", "castle-c250"), ("tag", blind["tag"]), ("commit", blind["commit"]),
        ("build", BUILD_LINE), ("upstream", lock["upstream"]["url"]),
        ("upstream_commit", lock["upstream"]["commit"]), ("reference_lock", key_lock_path),
        ("scored_paths", [SOURCE_DIR]),
    ]
    out = [
        "# Scoring key for the blind CASTLE-C250 corpus (docs/reviews/castle-style-detector-scoring.md).",
        "# Generated by `python -m appsec_review.acceptance.castle`; never edit by hand and never place it",
        "# in the target. Metadata derived from CASTLE-Benchmark (MIT License),",
        f"# {lock['license']['copyright']}; {lock['upstream']['url']}",
        "",
        "[corpus]",
        *(f"{name} = {_toml(value)}" for name, value in corpus),
    ]
    for kind, vulnerable in (("defect", True), ("control", False)):
        for test in (test for test in ordered if test.vulnerable is vulnerable):
            fields: list[tuple[str, object]] = [("id", test.id), ("path", paths[test.name]), ("cwe", test.cwe)]
            if vulnerable:
                fields += [("line", test.lines[0]), ("lines", list(test.lines))]
            else:
                fields += [("line", 1), ("end_line", test.line_count)]
            fields += [("scope", FILE_SCOPE), ("upstream", test.name), ("summary", test.description)]
            out += ["", f"[[{kind}]]", *(f"{name} = {_toml(value)}" for name, value in fields)]
    return "\n".join(out) + "\n"


def write_key(tests: Sequence[CastleTest], paths: Mapping[str, str], lock: Mapping[str, Any], key: Path) -> None:
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text(render_key(tests, paths, lock), encoding="utf-8")


def generate_key(upstream: Path, key: Path, *, lock_path: Path = LOCK_PATH) -> None:
    lock = load_lock(lock_path)
    tests = load_upstream(upstream, lock)
    _, _, paths = blind_files(tests, lock["blind"]["salt"])
    write_key(tests, paths, lock, key)


# --- CLI ----------------------------------------------------------------------------------------

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m appsec_review.acceptance.castle", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="write the blind repository (outside this repository)")
    prep.add_argument("--upstream", type=Path, required=True, help="CASTLE-Benchmark clone at the pinned commit")
    prep.add_argument("--output", type=Path, required=True, help="new or empty directory outside this repository")
    prep.add_argument("--key", type=Path, help="also write the scoring key here")
    prep.add_argument("--record", action="store_true", help="record a changed blind commit SHA in the lock")
    prep.add_argument("--lock", type=Path, default=LOCK_PATH)
    keys = commands.add_parser("key", help="write the scoring key for the lock's blind commit")
    keys.add_argument("--upstream", type=Path, required=True)
    keys.add_argument("--output", type=Path, default=KEY_PATH)
    keys.add_argument("--lock", type=Path, default=LOCK_PATH)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            sha = prepare(args.upstream, args.output, key=args.key, record=args.record, lock_path=args.lock)
            print(sha)
        else:
            generate_key(args.upstream, args.output, lock_path=args.lock)
            print(args.output)
    except (CastleError, OSError, ValueError, KeyError) as exc:
        print(f"castle: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
