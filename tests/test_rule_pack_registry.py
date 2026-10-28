"""The rule-pack registry is the authoritative inventory of analysis packs.

These tests are offline: they assert the registry's shape and that it stays in step with the packs
on disk. Compiling the packs is the builder's job (`containers/build.py query-packs`), which needs
Docker and the pinned images.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tomllib

import pytest


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "rules" / "registry.toml"
ENGINES = {"codeql", "semgrep", "pmd", "gitleaks"}
VERIFY_MODES = {"check-only", "validate"}


def _registry() -> dict:
    with REGISTRY.open("rb") as stream:
        return tomllib.load(stream)


def _builder():
    spec = importlib.util.spec_from_file_location("appsec_builder", ROOT / "containers" / "build.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_registry_declares_a_known_schema() -> None:
    assert _registry()["schema"] == "appsec-review/rule-pack-registry/1"


def test_every_pack_is_completely_declared() -> None:
    seen: set[str] = set()
    for pack in _registry()["packs"]:
        for field in ("id", "engine", "language", "library", "verify", "state", "description"):
            assert isinstance(pack.get(field), str) and pack[field], f"{pack.get('id')}: {field}"
        assert pack["id"] not in seen, f"duplicate pack id {pack['id']}"
        seen.add(pack["id"])
        assert pack["engine"] in ENGINES
        assert pack["verify"] in VERIFY_MODES
        assert pack["state"] in {"enabled", "deferred"}
        # A pack is either in the repository or in its image, never neither and never both.
        assert ("path" in pack) ^ ("image_path" in pack), f"{pack['id']}: path/image_path"
        assert "@" in pack["library"], f"{pack['id']}: library must pin a version"


def test_repository_pack_paths_exist_and_carry_their_manifest() -> None:
    for pack in _registry()["packs"]:
        path = pack.get("path")
        if path is None:
            continue
        root = ROOT / path
        assert root.is_dir(), f"{pack['id']}: {path} is not a directory"
        if pack["engine"] == "codeql":
            assert (root / "qlpack.yml").is_file(), f"{pack['id']}: qlpack.yml is missing"
        suite = pack.get("suite")
        if suite is not None:
            assert (root / suite).is_file(), f"{pack['id']}: suite {suite} is missing"


def test_codeql_packs_pin_the_library_their_manifest_declares() -> None:
    """An unpinned dependency lets a pack bind to whichever library the image ships."""
    for pack in _registry()["packs"]:
        if pack["engine"] != "codeql" or "path" not in pack:
            continue
        manifest = (ROOT / pack["path"] / "qlpack.yml").read_text(encoding="utf-8")
        assert 'codeql/cpp-all: "*"' not in manifest, f"{pack['id']}: cpp-all is unpinned"
        name, _, version = pack["library"].partition("@")
        assert f"{name}: {version}" in manifest, f"{pack['id']}: manifest does not pin {pack['library']}"


def test_every_codeql_pack_under_rules_is_registered() -> None:
    """A pack on disk that nobody registered is a pack nobody verifies."""
    registered = {pack.get("path") for pack in _registry()["packs"]}
    for manifest in (ROOT / "rules").rglob("qlpack.yml"):
        if "test/tmp" in manifest.as_posix():
            continue
        assert manifest.parent.relative_to(ROOT).as_posix() in registered, \
            f"unregistered CodeQL pack: {manifest.parent.relative_to(ROOT)}"


def test_builder_rejects_an_unknown_pack_id() -> None:
    builder = _builder()
    args = builder.parser().parse_args(["query-packs", "no-such-pack"])
    with pytest.raises(SystemExit, match="unknown rule pack id"):
        builder.query_packs(args, builder.load_catalog())


def test_builder_loads_the_registry() -> None:
    builder = _builder()
    ids = [pack["id"] for pack in builder.load_registry()["packs"]]
    assert "graph-export-cpp" in ids


def test_the_export_pack_is_registered_for_a_warm_compile() -> None:
    packs = {pack["id"]: pack for pack in _registry()["packs"]}
    assert packs["graph-export-cpp"].get("warm") is True
    assert not any(pack.get("warm") for pack in packs.values() if pack["engine"] != "codeql")


def test_platform_warm_compile_fills_the_cache_review_runs_mount(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from appsec_review.codeql.runtime import CodeQLImage, compile_cache_volume

    builder = _builder()
    image_id = "sha256:" + "7" * 64
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        return SimpleNamespace(returncode=0, stdout=image_id + "\n", stderr="")

    seen: list[list[str]] = []
    monkeypatch.setattr(builder.subprocess, "run", fake_run)
    monkeypatch.setattr(builder, "_run_pack_container",
                        lambda argv, log, timeout, container: seen.append(argv) or SimpleNamespace(returncode=0))
    pack = {pack["id"]: pack for pack in _registry()["packs"]}["graph-export-cpp"]
    ok, detail = builder._codeql_warm(pack, tmp_path / "warm.log")
    assert ok

    import tomllib
    release = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))[
        "review_policy"]["releases"]["codeql"]
    derived = CodeQLImage("appsec-review/codeql-derived-image/2", "a" * 64, image_id, "b", "t", "c", "t",
                          "10001:10001", release, "runner-x", False, "m")
    volume = builder.compile_cache_volume()
    assert compile_cache_volume(derived, tmp_path / "run") == volume and volume in detail
    [argv] = seen
    assert f"type=volume,src={volume},dst=/codeql-cache" in argv
    assert any(value.endswith(",dst=/scratch/export/pack,readonly") for value in argv)
    assert argv[argv.index("--network") + 1] == "none"
    assert "query compile" in argv[-1] and "--check-only" not in argv[-1]
    # The cache must be written as the uid the job reads it as (application_runtime_user), and
    # chowned recursively to it; another uid's entries are unreadable and force a cold recompile.
    from appsec_review.container_runtime.identity import application_runtime_user
    owner = application_runtime_user("10001:10001")
    assert builder.cache_owner() == owner and argv[argv.index("--user") + 1] == owner
    [chown] = [call for call in calls if "chown" in call]
    assert chown[-3:] == ["-R", owner, "/codeql-cache"]


def test_warm_flag_is_parsed_and_skips_packs_that_are_not_registered() -> None:
    args = _builder().parser().parse_args(["query-packs", "--warm", "cert-cpp-coding-standards"])
    assert args.warm is True
