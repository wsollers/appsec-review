from __future__ import annotations

from dataclasses import replace
import hashlib

import pytest

from appsec_review.jobs.job_dependency_intelligence.discovery import discover_native_dependencies
from appsec_review.jobs.job_dependency_intelligence.native import parse_native_candidates
from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import (
    DISCOVERY_COUNTERS, GAP_KINDS, NativeBounds, NativeInputIntegrityError,
    candidate_identity, evidence_identity,
)
from appsec_review.jobs.job_dependency_intelligence.resolution import normalize_dependencies
from appsec_review.storage import canonical_json


BOUNDS = NativeBounds(candidate_limit=100, command_token_limit=100, file_limit=100,
                      bytes_per_file=10000, source_bytes_limit=100000, root_limit=100,
                      evidence_limit=1000, evidence_per_candidate=100, field_bytes=4096,
                      path_chars=512)
REF = {"path": "data/partition.json", "sha256": "a" * 64, "size_bytes": 100}


def catalog(contents, *, domain="target", root_id="target"):
    data = {path: value.encode() if isinstance(value, str) else value
            for path, value in contents.items()}
    records = [{"domain": domain, "root_id": root_id, "path": path,
                "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value),
                "upstream": dict(REF), "backing": None}
               for path, value in data.items()]
    calls = []

    def read(record, limit):
        calls.append((record["path"], limit))
        value = data[record["path"]]
        if domain == "workspace":
            record["backing"] = {"path": "data/backings/" + record["sha256"],
                                 "sha256": record["sha256"], "size_bytes": len(value)}
        return value[:limit]
    return records, read, calls


def command(argv, **kwargs):
    return {"root_id": "target", "directory": ".", "argv": argv,
            "argv_sha256": hashlib.sha256(canonical_json(argv)).hexdigest(),
            "command_id": "cmd-1",
            "path_mappings": {"/target": "."},
            "evidence_source": {"artifact": dict(REF), "json_pointer": "/rows/0"}, **kwargs}


def artifact(path="out/libfoo.so.1.2.3", **kwargs):
    return {"root_id": "target", "path": path, "sha256": "b" * 64,
            "evidence_source": {"artifact": dict(REF), "json_pointer": "/artifacts/0"},
            **kwargs}


def discover(contents=None, *, invocations=(), artifacts=(), bounds=BOUNDS):
    files, read, calls = catalog(contents or {})
    result = discover_native_dependencies(source_fingerprint="snapshot-1", files=files,
                                         invocations=invocations, artifacts=artifacts,
                                         read_file=read, bounds=bounds)
    assert set(result["metrics"]) == set(DISCOVERY_COUNTERS)
    assert all(type(count) is int and count >= 0 for count in result["metrics"].values())
    assert all(gap["kind"] in GAP_KINDS for gap in result["gaps"])
    assert all(evidence_identity(item) == item["evidence_id"] for item in result["evidence"])
    known = {item["evidence_id"] for item in result["evidence"]}
    assert all(set(item["evidence_ids"]) <= known for item in result["candidates"])
    return result, calls


def named(result, name):
    return next(candidate for candidate in result["candidates"] if candidate["native_name"] == name)


def kinds(result):
    return {gap["kind"] for gap in result["gaps"]}


def test_buildless_known_header_has_exact_utf8_crlf_evidence_and_scoped_license():
    contents = {
        "LICENSE": "repository license only\n",
        "misc/zlib/LICENSE": "dependency license\n",
        "misc/zlib/zlib.h": '// café\r\n#define ZLIB_VERSION "1.3.1"\r\n',
        "misc/zlib/README": "Package: zlib\r\nVersion: 1.3.1\r\n",
    }
    result, calls = discover(contents)
    candidate = named(result, "zlib")
    assert candidate["package_root"] == "misc/zlib"
    assert candidate["identity"]["status"] == candidate["release"]["status"] == "corroborated"
    assert candidate["release"]["value"] == "1.3.1"
    assert result["metrics"]["commands_available"] == 0
    assert result["metrics"]["read_files"] == len(contents) == len(calls)
    evidence = next(item for item in result["evidence"] if item["kind"] == "macro_version")
    selector = evidence["selector"]
    raw = contents[evidence["path"]].encode()
    assert selector == {"start_byte": len("// café\r\n".encode()), "end_byte": len(raw),
                        "start_line": 2, "end_line": 2}
    assert raw[selector["start_byte"]:selector["end_byte"]].decode() == evidence["value"]
    linked_paths = {item["path"] for item in result["evidence"]
                    if item["evidence_id"] in candidate["evidence_ids"]}
    assert "misc/zlib/LICENSE" in linked_paths
    assert "LICENSE" not in linked_paths


@pytest.mark.parametrize(("macro", "value", "name", "version"), [
    ("ZLIB_VERSION", '"1.3"', "zlib", "1.3"),
    ("SQLITE_VERSION", '"3.45.0"', "sqlite", "3.45.0"),
    ("OPENSSL_VERSION_STR", '"3.3.1"', "openssl", "3.3.1"),
    ("OPENSSL_VERSION_TEXT", '"OpenSSL 3.3.1 4 Jun 2024"', "openssl", "3.3.1"),
    ("PNG_LIBPNG_VER_STRING", '"1.6.43"', "libpng", "1.6.43"),
    ("BOOST_VERSION", "108600", "boost", "1.86.0"),
    ("BOOST_LIB_VERSION", '"1_86"', "boost", "1.86.0"),
    ("BOOST_LIB_VERSION", '"1_85_1"', "boost", "1.85.1"),
])
def test_literal_known_and_packed_macros(macro, value, name, version):
    result, _ = discover({"unusual/pkg/version.hpp": f"#define {macro} {value}\n"})
    assert named(result, name)["release"] == {
        "value": version, "status": "corroborated",
        "evidence_ids": named(result, name)["release"]["evidence_ids"], "alternatives": []}


def test_generic_macros_require_independent_associated_declaration():
    header = '#define FOO_VERSION "2.4.6"\n'
    result, _ = discover({"strange/foo/version.h": header})
    assert named(result, "foo")["identity"]["status"] == "inferred"
    assert named(result, "foo")["release"]["status"] == "inferred"
    result, _ = discover({
        "strange/foo/include/version.h": header,
        "strange/foo/README": "Package: foo\nVersion: 2.4.6\n",
    })
    assert len(result["candidates"]) == 1
    assert named(result, "foo")["package_root"] == "strange/foo"
    assert named(result, "foo")["release"]["status"] == "corroborated"


def test_header_aliases_or_duplicate_bytes_do_not_corroborate_generic_release():
    header = '#define FOO_VERSION "2.4.6"\n'
    result, _ = discover({"vendor/foo/a.h": header, "vendor/foo/b.h": header})
    assert named(result, "foo")["release"]["status"] == "inferred"
    assert len(result["candidates"]) == 1


def test_version_tuple_and_include_guard_are_literal_not_execution():
    result, _ = discover({"vendor/foo/foo.h": (
        "#ifndef FOO_H\n#define FOO_H\n"
        "#define FOO_VERSION_MAJOR 2\n#define FOO_VERSION_MINOR 4\n"
        "#define FOO_VERSION_PATCH 6\n#endif\n")})
    candidate = named(result, "foo")
    assert candidate["release"]["value"] == "2.4.6"
    assert candidate["release"]["status"] == "inferred"
    evidence = next(item for item in result["evidence"] if item["kind"] == "macro_version_tuple")
    assert evidence["selector"]["start_line"] == 3
    assert evidence["selector"]["end_line"] == 5


def test_competing_tuple_components_never_select_the_last_value():
    result, _ = discover({"vendor/foo/foo.h": (
        "#define FOO_VERSION_MAJOR 1\n#define FOO_VERSION_MAJOR 2\n"
        "#define FOO_VERSION_MINOR 4\n#define FOO_VERSION_PATCH 6\n")})
    assert named(result, "foo")["release"]["status"] == "conflicted"
    assert named(result, "foo")["release"]["value"] is None
    assert {"version_conflict", "unsupported_metadata"} <= kinds(result)
    assert any(item["value"] == "#define FOO_VERSION_MAJOR 1\n" for item in result["evidence"])


def test_conditional_redefinition_cannot_promote_an_unconditional_release():
    result, _ = discover({"vendor/zlib/zlib.h": (
        '#define ZLIB_VERSION "1.2.3"\n#ifdef OTHER\n#define ZLIB_VERSION "2.3.4"\n#endif\n')})
    assert named(result, "zlib")["identity"]["status"] == "corroborated"
    assert named(result, "zlib")["release"]["status"] == "inferred"
    assert "unsupported_metadata" in kinds(result)


def test_unsupported_numeric_encoding_does_not_replace_authoritative_string():
    result, _ = discover({"vendor/sqlite/sqlite.h": (
        '#define SQLITE_VERSION "3.45.0"\n#define SQLITE_VERSION_NUMBER 3045000\n')})
    assert named(result, "sqlite")["release"]["value"] == "3.45.0"
    assert named(result, "sqlite")["release"]["status"] == "corroborated"
    assert "unsupported_metadata" in kinds(result)


def test_packed_boost_and_literal_alias_agree_without_a_false_conflict():
    result, _ = discover({"vendor/boost/version.h": (
        '#define BOOST_VERSION 108600\n#define BOOST_LIB_VERSION "1_86"\n')})
    assert named(result, "boost")["release"]["value"] == "1.86.0"
    assert "version_conflict" not in kinds(result)


def test_oversized_numeric_encoding_is_unsupported_without_integer_evaluation_failure():
    result, _ = discover({"vendor/boost/version.h": "#define BOOST_VERSION " + "9" * 5000 + "\n"})
    assert "unsupported_metadata" in kinds(result)
    assert all(candidate["release"]["status"] == "unknown" for candidate in result["candidates"])


@pytest.mark.parametrize("text", [
    "#define FOO_VERSION (1 + 2)\n",
    "#define OPENSSL_VERSION_NUMBER 0x30000010L\n",
    '#if PLATFORM\n#define ZLIB_VERSION "1.2.3"\n#endif\n',
    '#define FOO_VERSION "1." "2.3"\n',
    "#define FOO_VERSION_MAJOR 1\n",
    '#define FOO_VERSION \\\n"1.2.3"\n',
])
def test_unsupported_version_constructs_are_explicit(text):
    result, _ = discover({"arbitrary/foo/version.h": text})
    assert "unsupported_metadata" in kinds(result)
    assert result["metrics"]["unsupported_files"] == 1
    assert all(candidate["release"]["status"] == "unknown" for candidate in result["candidates"])


def test_scoped_pkgconfig_and_cmake_metadata_and_upstream_claims():
    result, _ = discover({
        "vendor/foo/lib/pkgconfig/foo.pc": (
            "Name: foo\nVersion: 1.2.3\nURL: https://github.com/acme/foo\n"),
        "vendor/foo/README": (
            "Package: foo\nVersion: 1.2.3\nRepository: https://github.com/acme/foo.git\n"),
        "elsewhere/bar/barConfig.cmake": 'set(bar_VERSION "4.5.6")\n',
    })
    foo, bar = named(result, "foo"), named(result, "bar")
    assert foo["release"]["status"] == bar["release"]["status"] == "corroborated"
    assert foo["upstream"]["value"] == "https://github.com/acme/foo"
    assert foo["upstream"]["status"] == "corroborated"
    assert foo["repository"] is None
    assert bar["package_root"] == "elsewhere/bar"


def test_homepage_and_license_copyright_never_assert_upstream_or_version():
    result, _ = discover({
        "vendor/foo/foo.pc": "Name: foo\nVersion: 1.2.3\nURL: https://example.com/foo\n",
        "vendor/foo/LICENSE": "Copyright 2024 Famous Foo, https://github.com/wrong/foo\n",
        "vendor/foo/README": "Some prose calls foo 9.8.7 a dependency.\n",
    })
    assert named(result, "foo")["upstream"]["status"] == "unknown"
    assert named(result, "foo")["release"]["value"] == "1.2.3"


@pytest.mark.parametrize(("path", "text"), [
    ("vendor/foo/foo.pc", "Name: foo\nVersion: ${foo_version}\n"),
    ("vendor/foo/fooConfig.cmake", 'set(foo_VERSION "${OTHER}")\n'),
    ("vendor/foo/fooConfig.cmake", 'if(PLATFORM)\nset(foo_VERSION "1.2.3")\nendif()\n'),
])
def test_metadata_expansions_or_conditions_are_not_evaluated(path, text):
    result, _ = discover({path: text})
    assert "unsupported_metadata" in kinds(result)
    assert all(candidate["release"]["status"] == "unknown" for candidate in result["candidates"])


@pytest.mark.parametrize("flag", [
    "-I", "-isystem", "-iquote", "-idirafter", "-L", "/I", "/external:I", "/LIBPATH:",
])
@pytest.mark.parametrize("joined", [False, True])
def test_gcc_clang_msvc_path_arguments_are_mapped_and_scoped(flag, joined):
    path = "/target/custom/foo"
    argv = ["cc", flag + path] if joined else ["cc", flag, path]
    result, calls = discover({"custom/foo/sub/foo.h": '#define FOO_VERSION "1.2.3"\n'},
                             invocations=[command(argv)])
    candidate = named(result, "foo")
    assert candidate["package_root"] == "custom/foo"
    assert candidate["release"]["status"] == "inferred"
    assert calls == [("custom/foo/sub/foo.h", len('#define FOO_VERSION "1.2.3"\n') + 1)]
    evidence = next(item for item in result["evidence"] if item["kind"] == "path_hint")
    assert evidence["selector"]["json_pointer"] == ("/rows/0/argv/1" if joined else "/rows/0/argv/2")


def test_relative_paths_use_working_directory_and_cross_domain_mappings():
    row = command(["cc", "-I", "../custom/foo"], directory="build")
    result, _ = discover({"custom/foo/v.h": '#define FOO_VERSION "1.2.3"\n'}, invocations=[row])
    assert named(result, "foo")["package_root"] == "custom/foo"
    row = command(["cc", "-I/target/custom/foo"], root_id="build-unit",
                  path_mappings={"/target": {"domain": "target", "root_id": "target", "path": "."}})
    result, _ = discover({"custom/foo/v.h": '#define FOO_VERSION "1.2.3"\n'}, invocations=[row])
    assert len(result["candidates"]) == 1
    assert named(result, "foo")["root_id"] == "target"


def test_response_unmapped_absolute_and_outputs_are_not_read_or_dependencies():
    row = command(["cl", "/I", r"C:\sdk\include", "-L/usr/lib", "@/target/args.rsp",
                   "/Foout.lib", "/Fe", "another.dll", "-o", "ignored.a",
                   "/OUT:last.lib", "-lfoo"])
    result, calls = discover(invocations=[row])
    assert calls == []
    assert {"unmapped_path", "unsupported_response_file"} <= kinds(result)
    assert [candidate["native_name"] for candidate in result["candidates"]] == ["foo"]
    assert named(result, "foo")["release"]["status"] == "unknown"
    assert named(result, "foo")["package_root"].startswith("@command/")


def test_accepted_expanded_argv_uses_exact_expanded_selectors_without_response_file_gap():
    expanded = ["cc", "-lfoo"]
    row = command(["cc", "@args.rsp"], expanded_argv=expanded,
                  expanded_argv_sha256=hashlib.sha256(canonical_json(expanded)).hexdigest())
    result, _ = discover(invocations=[row])
    assert named(result, "foo")["release"]["status"] == "unknown"
    assert "unsupported_response_file" not in kinds(result)
    assert result["evidence"][0]["selector"]["json_pointer"] == "/rows/0/expanded_argv/1"
    row["expanded_argv_sha256"] = "b" * 64
    with pytest.raises(NativeInputIntegrityError, match="expanded"):
        discover(invocations=[row])


def test_joined_outputs_lowercase_msvc_and_root_escape_are_not_libraries():
    result, _ = discover(invocations=[command([
        "cl", "-oignored.a", "/foignored.lib", "/out:ignored.dll",
        "/libpath:/target/libs", "-I../../outside", "-lfoo"])])
    assert {candidate["native_name"] for candidate in result["candidates"]} == {"foo", "libs"}
    assert "unmapped_path" in kinds(result)


def test_posix_absolute_library_paths_are_not_lowercase_msvc_options():
    result, _ = discover(invocations=[command([
        "clang", "/inputs/libfoo.a", "/forward/libbar.a"])])
    assert {candidate["native_name"] for candidate in result["candidates"]} == {"foo", "bar"}
    assert "unmapped_path" in kinds(result)


def test_linker_framework_artifact_loader_and_filename_versions_are_only_hints():
    row = command(["clang", "-l", "z", "-lssl", "-Wl,-lcrypto", "-framework", "Cocoa",
                   "-l:libexact.so.7", "/target/vendor/foo/libfoo-1.2.3.a"])
    result, _ = discover(invocations=[row], artifacts=[
        artifact(loader_dependencies=["libssl.so.3", "libz.so.1.2.13"],
                 loader_soname="libfoo.so.1.2.3")])
    assert {"z", "ssl", "crypto", "cocoa", "exact", "foo-1.2.3", "foo"} <= {
        item["native_name"] for item in result["candidates"]}
    assert all(item["release"]["status"] == "unknown" for item in result["candidates"])
    assert all(item["identity"]["status"] == "inferred" for item in result["candidates"])
    assert "identity_conflict" not in kinds(result)
    assert all("json_pointer" in evidence["selector"] for evidence in result["evidence"])
    assert all(evidence["domain"] == "run" for evidence in result["evidence"])
    assert any(evidence["selector"]["json_pointer"] == "/artifacts/0/loader_dependencies/1"
               for evidence in result["evidence"])


def test_unassociated_metadata_is_not_borrowed_by_each_loader_package():
    result, _ = discover({"out/VERSION": "1.2.3\n"}, artifacts=[
        artifact(loader_dependencies=["libbar.so.1"])])
    assert {candidate["native_name"] for candidate in result["candidates"]} == {"foo", "bar"}
    assert all(candidate["release"]["status"] == "unknown" for candidate in result["candidates"])
    assert "ambiguous_root" in kinds(result)


def test_two_copies_and_nested_vendor_roots_never_borrow_versions():
    result, _ = discover({
        "vendor/one/zlib.h": '#define ZLIB_VERSION "1.2.3"\n',
        "vendor/two/zlib.h": '#define ZLIB_VERSION "1.3.1"\n',
        "vendor/one/deps/nested/zlib.h": '#define ZLIB_VERSION "1.0.0"\n',
    })
    assert {(item["package_root"], item["release"]["value"]) for item in result["candidates"]} == {
        ("vendor/one", "1.2.3"), ("vendor/two", "1.3.1"), ("vendor/one/deps/nested", "1.0.0")}
    assert len({item["candidate_id"] for item in result["candidates"]}) == 3
    assert "version_conflict" not in kinds(result)
    for candidate in result["candidates"]:
        assert candidate["candidate_id"] == candidate_identity(
            "snapshot-1", candidate["root_id"], candidate["package_root"], candidate["native_name"])


def test_broad_include_hint_cannot_coalesce_independent_copies_or_nested_packages():
    result, _ = discover({
        "custom/includes/one/foo.h": '#define FOO_VERSION "1.2.3"\n',
        "custom/includes/two/foo.h": '#define FOO_VERSION "2.3.4"\n',
    }, invocations=[command(["cc", "-I/target/custom/includes"])])
    copies = [candidate for candidate in result["candidates"] if candidate["native_name"] == "foo"]
    assert {candidate["package_root"] for candidate in copies} == {
        "custom/includes/one", "custom/includes/two"}
    assert "ambiguous_root" in kinds(result)
    assert all(candidate["release"]["status"] == "inferred" for candidate in copies)
    result, _ = discover({
        "custom/outer/README": "Package: outer\nVersion: 1.2.3\n",
        "custom/outer/nested/bar.h": '#define BAR_VERSION "2.3.4"\n',
    })
    assert named(result, "bar")["package_root"] == "custom/outer/nested"
    assert named(result, "bar")["release"]["value"] == "2.3.4"


def test_conflicting_versions_repositories_and_names_are_not_last_write_wins():
    result, _ = discover({
        "vendor/foo/a.h": '#define FOO_VERSION "1.2.3"\n',
        "vendor/foo/b.h": '#define FOO_VERSION "2.3.4"\n',
        "vendor/foo/README": (
            "Package: foo\nRepository: https://github.com/one/foo\n"
            "Repository: https://github.com/two/foo\n"),
    })
    foo = named(result, "foo")
    assert foo["release"]["status"] == foo["upstream"]["status"] == "conflicted"
    assert foo["release"]["value"] is foo["upstream"]["value"] is None
    assert foo["release"]["alternatives"] == ["1.2.3", "2.3.4"]
    assert {"version_conflict", "repository_conflict"} <= kinds(result)
    result, _ = discover({"vendor/foo/a.h": '#define FOO_VERSION "1.2.3"\n',
                          "vendor/foo/README": "Package: bar\nVersion: 1.2.3\n"})
    assert "identity_conflict" in kinds(result)
    assert all(candidate["identity"]["status"] == "conflicted"
               for candidate in result["candidates"])


def test_decode_and_read_failures_are_distinct_and_independent_evidence_survives():
    files, reader, _ = catalog({"a/one.h": b"\xff", "b/two.h": "ignored",
                                "c/zlib.h": '#define ZLIB_VERSION "1.3.1"\n'})
    def read(file, limit):
        if file["path"] == "b/two.h":
            raise PermissionError("test")
        return reader(file, limit)
    result = discover_native_dependencies(source_fingerprint="snapshot-1", files=files,
        invocations=[], artifacts=[], read_file=read, bounds=BOUNDS)
    assert {"decode_failed", "read_failed"} <= kinds(result)
    assert named(result, "zlib")["release"]["value"] == "1.3.1"
    assert result["metrics"]["read_files"] == 2
    assert result["metrics"]["selected_files"] == 3


@pytest.mark.parametrize("mutate", ["bytes", "size", "backing", "record", "argv", "duplicate"])
def test_accepted_identity_mismatch_raises_not_a_gap(mutate):
    files, reader, _ = catalog({"vendor/foo/foo.h": '#define FOO_VERSION "1.2.3"\n'})
    rows = []
    if mutate == "size":
        files[0]["size_bytes"] += 1
    elif mutate == "backing":
        files[0]["backing"] = {**REF, "sha256": "f" * 64}
    elif mutate == "argv":
        rows = [command(["cc", "-lfoo"], argv_sha256="b" * 64)]
    elif mutate == "duplicate":
        files.append({**files[0], "sha256": "b" * 64})
    def read(file, limit):
        data = reader(file, limit)
        if mutate == "record":
            file["sha256"] = "b" * 64
        return b"x" * len(data) if mutate == "bytes" else data
    with pytest.raises(NativeInputIntegrityError):
        discover_native_dependencies(source_fingerprint="snapshot-1", files=files,
            invocations=rows, artifacts=[], read_file=read, bounds=BOUNDS)


def test_workspace_backing_populated_by_reader_is_retained_and_verified():
    files, read, _ = catalog({"vendor/foo/v.h": '#define FOO_VERSION "1.2.3"\n'},
                             domain="workspace", root_id="build-unit")
    result = discover_native_dependencies(source_fingerprint="snapshot-1", files=files,
        invocations=[], artifacts=[], read_file=read, bounds=BOUNDS)
    assert result["evidence"][0]["backing"] == files[0]["backing"]
    assert result["candidates"][0]["root_id"] == "build-unit"
    files[0]["backing"] = None
    with pytest.raises(ValueError, match="backing"):
        discover_native_dependencies(source_fingerprint="snapshot-1", files=files,
            invocations=[], artifacts=[],
            read_file=lambda file, limit: b'#define FOO_VERSION "1.2.3"\n', bounds=BOUNDS)


@pytest.mark.parametrize("path", ["../foo.h", "/foo.h", r"C:\foo.h", "C:/foo.h",
                                  "a//foo.h", "a/./foo.h", r"a\foo.h", "a/\x00foo.h"])
def test_noncanonical_file_paths_are_rejected_before_read(path):
    files, _, _ = catalog({"foo.h": ""})
    files[0]["path"] = path
    with pytest.raises(ValueError, match="path"):
        discover_native_dependencies(source_fingerprint="snapshot-1", files=files,
            invocations=[], artifacts=[], read_file=lambda *_: pytest.fail("must not read"), bounds=BOUNDS)


@pytest.mark.parametrize("row", [
    {"root_id": "target", "argv": ["cc"]},
    command(["cc"], evidence_source={"artifact": REF, "json_pointer": "/bad~2pointer"}),
    command(["cc"], directory="../outside"),
    command(["cc"], path_mappings={"relative": "."}),
    {**command(["cc"]), "argv": ["cc", 1]},
])
def test_invalid_caller_records_fail_admission(row):
    with pytest.raises(ValueError):
        discover({}, invocations=[row])


@pytest.mark.parametrize(("bound", "value", "expected"), [
    ("file_limit", 1, 2),
    ("bytes_per_file", 1, 3),
    ("source_bytes_limit", 31, 2),
    ("root_limit", 1, 2),
    ("candidate_limit", 1, 2),
    ("evidence_limit", 1, 2),
    ("evidence_per_candidate", 1, 1),
    ("field_bytes", 2, None),
    ("path_chars", 3, 3),
    ("command_token_limit", 1, 2),
])
def test_every_bound_has_exact_stable_omissions_and_a_named_gap(bound, value, expected):
    contents = {"a/foo.h": '#define FOO_VERSION "1.2.3"\n',
                "b/bar.h": '#define BAR_VERSION "2.3.4"\n',
                "c/baz.h": '#define BAZ_VERSION "3.4.5"\n'}
    rows = []
    if bound == "evidence_per_candidate":
        contents = {"a/foo.h": '#define FOO_VERSION "1.2.3"\n',
                    "a/README": "Package: foo\n"}
    if bound == "command_token_limit":
        rows = [command(["cc", "-lone", "-ltwo"])]
    result, _ = discover(contents, invocations=rows, bounds=replace(BOUNDS, **{bound: value}))
    count = result["coverage"]["omission_counts"][bound]
    assert count == expected if expected is not None else count > 0
    assert "bounds" in kinds(result)
    assert all(len(item["evidence_ids"]) <= value for item in result["candidates"]) \
        if bound == "evidence_per_candidate" else True
    if bound in {"file_limit", "bytes_per_file", "source_bytes_limit", "path_chars"}:
        assert result["metrics"]["omitted_files"] == expected


def test_global_candidate_bound_includes_command_artifact_and_metadata_sources():
    result, _ = discover({"vendor/pc/foo.pc": "Name: foo\nVersion: 1.2.3\n"},
        invocations=[command(["cc", "-lcommand"])],
        artifacts=[artifact(loader_dependencies=["libloader.so.1"])],
        bounds=replace(BOUNDS, candidate_limit=1))
    assert len(result["candidates"]) == 1
    assert result["coverage"]["omission_counts"]["candidate_limit"] == 3


def test_root_and_byte_bounds_prevent_reads_rather_than_truncating_afterward():
    contents = {"a/foo.h": '#define FOO_VERSION "1.2.3"\n',
                "b/bar.h": '#define BAR_VERSION "2.3.4"\n'}
    result, calls = discover(contents, bounds=replace(BOUNDS, root_limit=1))
    assert len(calls) == result["metrics"]["read_files"] == result["metrics"]["roots_inspected"] == 1
    assert result["metrics"]["omitted_files"] == 1
    result, calls = discover(contents, bounds=replace(BOUNDS, bytes_per_file=1))
    assert not calls and result["metrics"]["bytes_read"] == 0
    result, calls = discover(contents, bounds=replace(BOUNDS, source_bytes_limit=30))
    assert len(calls) == 1
    assert result["metrics"]["bytes_read"] == len(contents["a/foo.h"].encode())


@pytest.mark.parametrize("bound", ["evidence_per_candidate", "evidence_limit"])
def test_evidence_omission_never_upgrades_a_conflict_into_an_asserted_release(bound):
    result, _ = discover({
        "vendor/zlib/a.h": '#define ZLIB_VERSION "1.2.3"\n',
        "vendor/zlib/b.h": '#define ZLIB_VERSION "2.3.4"\n',
    }, bounds=replace(BOUNDS, **{bound: 1}))
    candidate = named(result, "zlib")
    assert candidate["release"]["status"] in {"inferred", "conflicted", "unknown"}
    assert "version" not in candidate["metadata"]
    assert "bounds" in kinds(result)


def test_file_budget_is_global_across_target_and_detached_workspace_records():
    target, target_reader, _ = catalog({"a/zlib.h": '#define ZLIB_VERSION "1.2.3"\n'})
    workspace, workspace_reader, _ = catalog({"a/foo.h": '#define FOO_VERSION "2.3.4"\n'},
                                            domain="workspace", root_id="build")
    calls = []
    def read(record, limit):
        calls.append(record["domain"])
        return (target_reader if record["domain"] == "target" else workspace_reader)(record, limit)
    result = discover_native_dependencies(source_fingerprint="snapshot-1", files=workspace + target,
        invocations=[], artifacts=[], read_file=read, bounds=replace(BOUNDS, file_limit=1))
    assert calls == ["target"]
    assert result["metrics"]["omitted_files"] == 1
    assert result["coverage"]["omission_counts"]["file_limit"] == 1


def test_deterministic_replay_permuted_inputs_and_true_zero():
    contents = {"vendor/foo/v.h": '#define FOO_VERSION "1.2.3"\n',
                "vendor/foo/README": "Package: foo\nVersion: 1.2.3\n",
                "vendor/bar/zlib.h": '#define ZLIB_VERSION "1.3.1"\n'}
    files, read, _ = catalog(contents)
    rows = [command(["cc", "-lfoo"]), command(["cc", "-lbar"], command_id="cmd-2")]
    artifacts = [artifact(loader_dependencies=["libz.so.1"]), artifact("out/libbar.a")]
    def run(files, rows, artifacts):
        return discover_native_dependencies(source_fingerprint="snapshot-1", files=files,
            invocations=rows, artifacts=artifacts, read_file=read, bounds=BOUNDS)
    assert canonical_json(run(files, rows, artifacts)) == canonical_json(
        run(list(reversed(files)), list(reversed(rows)), list(reversed(artifacts))))
    empty, calls = discover()
    assert empty["candidates"] == empty["evidence"] == empty["gaps"] == calls == []
    assert all(value == 0 for value in empty["metrics"].values())


def test_normalization_preserves_legacy_pc_version_and_root_scoped_native_copies():
    legacy, _ = parse_native_candidates([], metadata_files=[{
        "path": "lib/foo.pc", "fields": {"Name": "foo", "Version": "1.2.3"}}])
    dependencies, _ = normalize_dependencies([], [], legacy,
                                             supported_hosts=("github.com",), max_dependencies=100)
    assert dependencies[0]["version"] == "1.2.3"
    result, _ = discover({
        "vendor/a/foo.h": '#define FOO_VERSION "1.2.3"\n',
        "vendor/b/foo.h": '#define FOO_VERSION "2.3.4"\n',
    })
    for candidate in result["candidates"]:
        candidate["metadata"]["version"] = "not-corroborated"
        candidate["version"] = "also-not-corroborated"
    dependencies, _ = normalize_dependencies([], [], result["candidates"],
                                             supported_hosts=("github.com",), max_dependencies=100)
    assert len(dependencies) == 2
    assert all(item["version"] is None and len(item["native_candidates"]) == 1
               for item in dependencies)
    assert len({item["dependency_id"] for item in dependencies}) == 2


def test_normalization_only_promotes_corroborated_release_and_preserves_purl_case():
    result, _ = discover({"vendor/foo/foo.pc": "Name: foo\nVersion: 1.2.3\n"})
    dependencies, _ = normalize_dependencies([], [], result["candidates"],
                                             supported_hosts=("github.com",), max_dependencies=100)
    assert dependencies[0]["version"] == "1.2.3"
    packages = [{"name": "a", "purl": "pkg:generic/Acme@1?arch=X64"},
                {"name": "a", "purl": "pkg:generic/acme@1?arch=x64"}]
    dependencies, _ = normalize_dependencies([], packages, [],
                                             supported_hosts=("github.com",), max_dependencies=100)
    assert len(dependencies) == 2
    assert {item["purl"] for item in dependencies} == {item["purl"] for item in packages}


def test_normalization_preserves_legacy_coalescing_without_overwriting_native_candidates():
    observations = [{"candidate_id": "native-a", "native_name": "foo", "observations": []},
                    {"candidate_id": "native-b", "native_name": "foo", "observations": []}]
    first, _ = normalize_dependencies([], [], observations,
                                      supported_hosts=("github.com",), max_dependencies=100)
    second, _ = normalize_dependencies([], [], list(reversed(observations)),
                                       supported_hosts=("github.com",), max_dependencies=100)
    assert canonical_json(first) == canonical_json(second)
    assert len(first) == 1 and len(first[0]["native_candidates"]) == 2
