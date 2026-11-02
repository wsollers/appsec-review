"""CASTLE-C250 corpus preparation and key generation (scoring design decision 12)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import shutil
import tomllib

import pytest

from appsec_review.acceptance import castle
from appsec_review.acceptance.scoring_model import FILE_SCOPE, EntryKind, KeyEntry

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "castle" / "upstream"
SALT = castle.load_lock()["blind"]["salt"]
FIXED = {"GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
         "GIT_AUTHOR_DATE": "2025-01-01T00:00:00+00:00", "GIT_COMMITTER_NAME": "Fixture",
         "GIT_COMMITTER_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_DATE": "2025-01-01T00:00:00+00:00"}


def _upstream(tmp_path: Path, mutate=None) -> tuple[Path, Path]:
    """A git clone of the fixture miniature upstream and a lock pinning it (blind commit unset)."""

    upstream = tmp_path / "upstream"
    shutil.copytree(FIXTURE, upstream)
    if mutate is not None:
        mutate(upstream)
    env = {**castle._git_env(), **FIXED}
    castle._git(upstream, "init", "-q", "-b", "main", env=env)
    castle._git(upstream, "add", "--all", env=env)
    castle._git(upstream, "commit", "-q", "--no-verify", "-m", "fixture", env=env)
    lock = json.loads(castle.LOCK_PATH.read_text(encoding="utf-8"))
    lock["upstream"]["commit"] = castle._git(upstream, "rev-parse", "HEAD", env=env)
    dataset = upstream / "datasets" / "MINI.json"
    lock["dataset"].update(path="datasets/MINI.json", source_dir="datasets/MINI", test_count=3,
                           sha256=castle.hashlib.sha256(dataset.read_bytes()).hexdigest())
    lock["blind"]["commit"] = None
    lock_path = tmp_path / "lock.json"
    castle.write_lock(lock, lock_path)
    return upstream, lock_path


def _prepare(tmp_path: Path, upstream: Path, lock_path: Path, output: str, **kwargs) -> str:
    return castle.prepare(upstream, tmp_path / output, lock_path=lock_path, repository=tmp_path / "repo", **kwargs)


# --- the marker expression ----------------------------------------------------------------------

def test_answer_marker_equals_the_blind_isolation_expression() -> None:
    spec = importlib.util.spec_from_file_location("_castle_isolation", ROOT / "tests" / "test_blind_target_isolation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert castle.ANSWER_MARKER.pattern == module.ANSWER_MARKER.pattern
    assert castle.ANSWER_MARKER.flags == module.ANSWER_MARKER.flags


# --- comment blanking ---------------------------------------------------------------------------

def test_strip_comments_blanks_comments_and_keeps_lines_columns_and_literals() -> None:
    code = (FIXTURE / "datasets" / "MINI" / "CASTLE-22-1.c").read_text(encoding="utf-8")
    stripped = castle.strip_comments(code)
    before, after = code.split("\n"), stripped.split("\n")
    assert len(after) == len(before) and castle.line_count(stripped) == castle.line_count(code)
    assert after[3] == "" and after[4] == ""  # the two-line block comment
    assert after[6] == '    const char *url = "http://example.invalid/a//b";'
    assert after[7] == "    char slash = '/';"
    assert after[8].index('printf("/* not a comment */') == before[8].index('printf("/* not a comment */')
    assert after[9] == "" and after[10] == ""  # a // comment continued by a line splice
    assert after[11] == before[11] and after[12] == before[12]
    assert not castle.ANSWER_MARKER.search(stripped)


@pytest.mark.parametrize(("code", "expected"), [
    ("a /* x\r\n y */ b\r\n", "a\r\n      b\r\n"),
    ("a /\\\n* split */ b\n", "a\n           b\n"),
    ("s = \"\\\"//\"; // c\n", "s = \"\\\"//\";\n"),
    ("c = '\\''; /* q */ d;\n", "c = '\\'';         d;\n"),
    ("x; // a\\\nb\\\nc\nend", "x;\n\n\nend"),
    ("no comments\n", "no comments\n"),
])
def test_strip_comments_cases(code: str, expected: str) -> None:
    assert castle.strip_comments(code) == expected


def test_strip_comments_rejects_unterminated_block() -> None:
    with pytest.raises(castle.CastleError, match="unterminated"):
        castle.strip_comments("int a; /* open\n")


# --- naming, build mapping, marker scan ---------------------------------------------------------

def test_blind_name_is_deterministic_salted_and_neutral() -> None:
    name = castle.blind_name(SALT, "CASTLE-22-1.c")
    assert name == castle.blind_name(SALT, "CASTLE-22-1.c")
    assert name != castle.blind_name(SALT + "x", "CASTLE-22-1.c")
    assert name != castle.blind_name(SALT, "CASTLE-22-2.c")
    assert re.fullmatch(r"t[0-9a-f]{10}\.c", name)
    assert name == "t" + castle.hashlib.sha256((SALT + "CASTLE-22-1.c").encode()).hexdigest()[:10] + ".c"


def test_parse_compile_and_cmake_library_mapping() -> None:
    plain = castle.parse_compile("gcc CASTLE-1-1.c -o CASTLE-1-1", "CASTLE-1-1.c")
    assert plain == castle.BuildSpec((), (), ())
    ssl = castle.parse_compile("gcc CASTLE-1-2.c -o CASTLE-1-2 -lsqlite3 -lssl -lcrypto", "CASTLE-1-2.c")
    mysql = castle.parse_compile("gcc CASTLE-1-3.c -o CASTLE-1-3 -lmysqlclient -lm -pthread", "CASTLE-1-3.c")
    stack = castle.parse_compile(
        "gcc CASTLE-1-4.c -o CASTLE-1-4 -fno-stack-protector -fno-pie -no-pie -z execstack -Wno-type-limits",
        "CASTLE-1-4.c")
    curl = castle.parse_compile("gcc CASTLE-1-5.c -o CASTLE-1-5 -lcurl", "CASTLE-1-5.c")
    assert castle.link_items(ssl) == ("SQLite::SQLite3", "OpenSSL::SSL", "OpenSSL::Crypto")
    assert castle.link_items(mysql) == ("PkgConfig::MYSQLCLIENT", "m", "Threads::Threads")
    assert stack.compile_options == ("-fno-stack-protector", "-fno-pie", "-Wno-type-limits")
    assert stack.link_options == ("-no-pie", "LINKER:-z,execstack")
    cmake = castle.render_cmake([("tb.c", ssl), ("ta.c", plain), ("tc.c", mysql), ("td.c", stack), ("te.c", curl)])
    lines = cmake.splitlines()
    finds = [line for line in lines if line.startswith(("find_package", "pkg_check_modules"))]
    assert finds == ["find_package(OpenSSL REQUIRED)", "find_package(SQLite3 REQUIRED)",
                     "find_package(CURL REQUIRED)", "find_package(PkgConfig REQUIRED)",
                     "pkg_check_modules(MYSQLCLIENT REQUIRED IMPORTED_TARGET mysqlclient)",
                     "find_package(Threads REQUIRED)"]
    assert lines.index("add_executable(ta src/ta.c)") < lines.index("add_executable(tb src/tb.c)")
    assert "target_link_libraries(tb PRIVATE SQLite::SQLite3 OpenSSL::SSL OpenSSL::Crypto)" in lines
    assert "target_compile_options(td PRIVATE -fno-stack-protector -fno-pie -Wno-type-limits)" in lines
    assert "target_link_options(td PRIVATE -no-pie LINKER:-z,execstack)" in lines
    assert "target_link_libraries(te PRIVATE CURL::libcurl)" in lines
    assert not any(line.startswith("target_") and "(ta " in line for line in lines)
    assert "find_package" not in castle.render_cmake([("ta.c", plain)])


@pytest.mark.parametrize("line", ["gcc CASTLE-1-1.c -o CASTLE-1-1 -lfoo", "cc CASTLE-1-1.c -o CASTLE-1-1",
                                  "gcc CASTLE-1-1.c -o other"])
def test_parse_compile_refuses_unmapped_lines(line: str) -> None:
    with pytest.raises(castle.CastleError):
        castle.parse_compile(line, "CASTLE-1-1.c")


def test_marker_scan_reports_code_hits_and_paths() -> None:
    hits = castle.marker_hits({"src/ta.c": "int a;\nconst char *s = \"exploit\";\n", "src/cwe-1.c": "int b;\n"},
                              {"src/ta.c": "CASTLE-9-9.c"})
    assert hits == ["src/cwe-1.c: path matches 'cwe-1'",
                    "src/ta.c:2 (CASTLE-9-9.c): 'exploit' in 'const char *s = \"exploit\";'"]


# --- prepare ------------------------------------------------------------------------------------

def test_prepare_end_to_end_is_reproducible_and_writes_only_neutral_files(tmp_path: Path) -> None:
    upstream, lock_path = _upstream(tmp_path)
    key = tmp_path / "key.toml"
    sha = _prepare(tmp_path, upstream, lock_path, "blind-1", record=True, key=key)
    assert castle.load_lock(lock_path)["blind"]["commit"] == sha
    assert _prepare(tmp_path, upstream, lock_path, "blind-2") == sha
    blind = tmp_path / "blind-1"
    tracked = castle._git(blind, "ls-files").splitlines()
    names = sorted("src/" + castle.blind_name(SALT, name) for name in ("CASTLE-22-1.c", "CASTLE-22-2.c", "CASTLE-476-1.c"))
    assert tracked == ["CMakeLists.txt", "README.md", *names]
    assert castle._git(blind, "rev-parse", "castle-c250-v1") == sha
    assert castle._git(blind, "log", "-1", "--format=%an <%ae> %aI|%cn|%s") == \
        "Sample Builder <builder@samples.invalid> 2025-03-13T19:33:49+00:00|Sample Builder|Import sources"
    assert (blind / "README.md").read_text() == "Build: `cmake -S . -B build && cmake --build build`\n"
    for path in tracked:
        assert not castle.ANSWER_MARKER.search(path)
        assert not castle.ANSWER_MARKER.search((blind / path).read_text(encoding="utf-8"))
    source = (FIXTURE / "datasets" / "MINI" / "CASTLE-22-2.c").read_text(encoding="utf-8")
    blanked = (blind / "src" / castle.blind_name(SALT, "CASTLE-22-2.c")).read_text(encoding="utf-8")
    assert blanked == castle.strip_comments(source) and not blanked.endswith("\n")
    lock = castle.load_lock(lock_path)
    castle.write_lock({**lock, "blind": {**lock["blind"], "commit": "0" * 40}}, lock_path)
    with pytest.raises(castle.CastleError, match="differs from the lock"):
        _prepare(tmp_path, upstream, lock_path, "blind-3")


def test_prepare_writes_the_key(tmp_path: Path) -> None:
    upstream, lock_path = _upstream(tmp_path)
    key = tmp_path / "key" / "expectations.toml"
    sha = _prepare(tmp_path, upstream, lock_path, "blind", record=True, key=key)
    document = tomllib.loads(key.read_text(encoding="utf-8"))
    assert document["corpus"] == {
        "name": "castle-c250", "tag": "castle-c250-v1", "commit": sha,
        "build": "cmake -S . -B build && cmake --build build",
        "upstream": "https://github.com/CASTLE-Benchmark/CASTLE-Benchmark",
        "upstream_commit": castle.load_lock(lock_path)["upstream"]["commit"],
        "reference_lock": "data/reference/castle/castle-c250.lock.json", "scored_paths": ["src"]}
    defects, controls = document["defect"], document["control"]
    assert [entry["id"] for entry in defects] == ["castle-22-1", "castle-476-1"]
    assert [entry["id"] for entry in controls] == ["castle-22-2"]
    assert defects[1] == {"id": "castle-476-1", "path": "src/" + castle.blind_name(SALT, "CASTLE-476-1.c"),
                          "cwe": "CWE-476", "line": 4, "lines": [4, 5], "scope": FILE_SCOPE,
                          "upstream": "CASTLE-476-1.c", "summary": "Toy pointer sample."}
    assert controls[0] == {"id": "castle-22-2", "path": "src/" + castle.blind_name(SALT, "CASTLE-22-2.c"),
                           "cwe": "CWE-22", "line": 1, "end_line": 9, "scope": FILE_SCOPE,
                           "upstream": "CASTLE-22-2.c", "summary": "Toy path sample two."}
    for kind, entries in ((EntryKind.DEFECT, defects), (EntryKind.CONTROL, controls)):
        for entry in entries:
            lines = tuple(entry.get("lines") or range(entry["line"], entry.get("end_line", entry["line"]) + 1))
            KeyEntry(entry["id"], kind, entry["path"], entry["cwe"], lines, None, upstream=entry["upstream"])


def test_prepare_refuses_output_inside_this_repository(tmp_path: Path) -> None:
    upstream, lock_path = _upstream(tmp_path)
    with pytest.raises(castle.CastleError, match="inside this repository"):
        castle.prepare(upstream, tmp_path / "blind", lock_path=lock_path)  # tmp_path is under test/tmp
    assert not (tmp_path / "blind").exists()


def test_prepare_refuses_a_non_empty_output_and_a_key_inside_it(tmp_path: Path) -> None:
    upstream, lock_path = _upstream(tmp_path)
    (tmp_path / "busy").mkdir()
    (tmp_path / "busy" / "keep").write_text("x")
    with pytest.raises(castle.CastleError, match="not an empty directory"):
        _prepare(tmp_path, upstream, lock_path, "busy")
    with pytest.raises(castle.CastleError, match="key must not"):
        _prepare(tmp_path, upstream, lock_path, "blind", key=tmp_path / "blind" / "key.toml")


def test_prepare_refuses_the_wrong_upstream_commit_or_dataset_hash(tmp_path: Path) -> None:
    upstream, lock_path = _upstream(tmp_path)
    lock = castle.load_lock(lock_path)
    castle.write_lock({**lock, "upstream": {**lock["upstream"], "commit": "1" * 40}}, lock_path)
    with pytest.raises(castle.CastleError, match="not the pinned commit"):
        _prepare(tmp_path, upstream, lock_path, "blind")
    castle.write_lock({**lock, "dataset": {**lock["dataset"], "sha256": "2" * 64}}, lock_path)
    with pytest.raises(castle.CastleError, match="sha256"):
        _prepare(tmp_path, upstream, lock_path, "blind")
    assert not (tmp_path / "blind").exists()


def test_prepare_refuses_a_source_file_that_differs_from_the_dataset(tmp_path: Path) -> None:
    def edit(upstream: Path) -> None:
        path = upstream / "datasets" / "MINI" / "CASTLE-22-2.c"
        path.write_bytes(path.read_bytes() + b"\n")

    upstream, lock_path = _upstream(tmp_path, edit)
    with pytest.raises(castle.CastleError, match="differs from the dataset code"):
        _prepare(tmp_path, upstream, lock_path, "blind")


def test_prepare_fails_on_a_marker_in_code_without_rewriting_it(tmp_path: Path) -> None:
    def plant(upstream: Path) -> None:
        dataset = upstream / "datasets" / "MINI.json"
        document = json.loads(dataset.read_text())
        row = document["tests"][2]
        row["code"] = row["code"].replace("int *pointer", "int *exploit_pointer")
        (upstream / "datasets" / "MINI" / row["name"]).write_text(row["code"])
        dataset.write_text(json.dumps(document, indent=2) + "\n")

    upstream, lock_path = _upstream(tmp_path, plant)
    path = "src/" + castle.blind_name(SALT, "CASTLE-476-1.c")
    with pytest.raises(castle.CastleError, match=re.escape(f"{path}:4 (CASTLE-476-1.c): 'exploit'")):
        _prepare(tmp_path, upstream, lock_path, "blind")
    assert not (tmp_path / "blind").exists()


def test_cli_reports_errors_and_exit_status(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    upstream, lock_path = _upstream(tmp_path)
    assert castle.main(["prepare", "--upstream", str(upstream), "--output", str(tmp_path / "blind"),
                        "--lock", str(lock_path)]) == 1
    assert "castle: " in capsys.readouterr().err


# --- committed lock and key ---------------------------------------------------------------------

def test_committed_lock_pins_upstream_paper_reference_and_blind_commit() -> None:
    lock = castle.load_lock()
    assert lock["upstream"]["commit"] == "c7391c9ec5dd944653103fbf55e7ebbf85842d82"
    assert lock["dataset"]["test_count"] == 250 and lock["license"]["spdx"] == "MIT"
    assert lock["blind"]["tag"] == "castle-c250-v1" and re.fullmatch(r"[0-9a-f]{40}", lock["blind"]["commit"])
    assert (lock["max_score"], lock["max_score_paper_text"], lock["floor_score"]) == (1232, 1250, 200)
    rows = lock["paper_reference"]
    assert all(set(row) == castle.PAPER_REFERENCE_KEYS for row in rows)
    assert [(row["tool"], row["producer"], row["castle_score"]) for row in rows] == [
        ("ESBMC", None, 661), ("CodeQL", "codeql", 634), ("GCC Fanalyzer", None, 559),
        ("Semgrep Code", "tool-semgrep", 541), ("Cppcheck", "tool-cppcheck", 406),
        ("Clang Analyzer", "clang-static-analyzer", 381)]
    # Transcribed from Table 3 as published; CodeQL (157) and Semgrep (156) have TP + FN != 150 there.
    assert [(row["version"], row["tp"], row["tn"], row["fp"], row["fn"]) for row in rows] == [
        ("7.8.1", 53, 91, 32, 97), ("2.20.1", 45, 79, 49, 112), ("13.3.0", 41, 76, 93, 109),
        ("1.110.0", 36, 73, 70, 120), ("2.13.0", 19, 100, 9, 131), ("18.1.3", 13, 99, 2, 137)]


def test_committed_key_covers_the_corpus() -> None:
    document = tomllib.loads(castle.KEY_PATH.read_text(encoding="utf-8"))
    lock = castle.load_lock()
    assert document["corpus"]["commit"] == lock["blind"]["commit"]
    assert document["corpus"]["scored_paths"] == ["src"]
    defects, controls = document["defect"], document["control"]
    assert len(defects) == 150 and len(controls) == 100
    entries = defects + controls
    assert len({entry["cwe"] for entry in entries}) == 25 == len({entry["cwe"] for entry in defects})
    paths = [entry["path"] for entry in entries]
    assert len(set(paths)) == 250 and all(re.fullmatch(r"src/t[0-9a-f]{10}\.c", path) for path in paths)
    assert len({entry["id"] for entry in entries}) == 250
    assert all(entry["scope"] == FILE_SCOPE for entry in entries)
    assert all(entry["lines"] == sorted(set(entry["lines"])) and entry["line"] == entry["lines"][0] for entry in defects)
    assert all(entry["line"] == 1 and entry["end_line"] >= 1 for entry in controls)
    for entry in entries:
        assert not castle.ANSWER_MARKER.search(entry["path"])
