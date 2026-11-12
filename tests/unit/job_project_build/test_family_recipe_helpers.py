"""Per-family recipe and probe-environment helpers of job_project_build.job, moved from the
language-build pre-walk files by T-113."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from appsec_review.jobs.job_project_build.job import _deterministic_jvm_recipe, _probe_environment


def test_direct_mixed_jvm_sources_receive_a_deterministic_build_only_recipe(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = target / "mixed" / "src"
    source.mkdir(parents=True)
    (source / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    (source / "Helper.kt").write_text("class Helper\n", encoding="utf-8")
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target))
    action = {"family": "java", "build_system": "javac", "root": "mixed",
              "build_unit_id": "build-unit-" + "d" * 20}

    recipe = _deterministic_jvm_recipe(unit, action)

    assert recipe is not None
    assert [command[0] for command in recipe["build_commands"]] == ["kotlinc", "javac", "jar"]
    assert recipe["network_required"] is False
    assert not any(word in {"run", "test", "exec"} for command in recipe["build_commands"]
                   for word in command)
    assert recipe["expected_outputs"] == ["mixed/build/classes", "mixed/build/appsec-review.jar"]


def test_go_probe_environment_gives_an_undeclared_dependency_build_a_writable_module_cache() -> None:
    recipe = {"build_system": "go", "source_dir": "go", "environment": {"CGO_ENABLED": "1"}}
    # Only a dependency-bearing project image carries a module cache; otherwise the cache would
    # be the read-only image root and any declared module would fail to resolve.
    assert _probe_environment({**recipe, "network_required": False}) == {
        "CGO_ENABLED": "1", "GOMODCACHE": "/tmp/appsec-go-mod"}
    assert _probe_environment({**recipe, "network_required": True}) == {"CGO_ENABLED": "1"}
    # A recipe cannot point the cache at the unwritable image path either.
    assert _probe_environment({**recipe, "network_required": False,
                               "environment": {"GOMODCACHE": "/go/pkg/mod"}})["GOMODCACHE"] == "/tmp/appsec-go-mod"
    assert _probe_environment({**recipe, "network_required": True,
                               "environment": {"GOMODCACHE": "/go/pkg/mod"}})["GOMODCACHE"] == "/opt/project-deps/go"


def test_go_mod_mod_build_downloads_into_scratch_and_reads_the_image_cache_first() -> None:
    recipe = {"build_system": "go", "source_dir": "go", "network_required": True,
              "environment": {"GOFLAGS": "-mod=mod -buildvcs=false", "GOMODCACHE": "/go/pkg/mod"}}
    environment = _probe_environment(recipe)
    # The image-restored cache is on the read-only root; -mod=mod may need to download.
    assert environment["GOMODCACHE"] == "/tmp/appsec-go-mod"
    assert environment["GOPROXY"] == (
        "file:///opt/project-deps/go/cache/download,https://proxy.golang.org,direct")
    # Builds stay online: an explicit upstream is kept after the image cache, never replaced by off.
    upstream = _probe_environment({**recipe, "environment": {
        **recipe["environment"], "GOPROXY": "https://goproxy.example,direct"}})
    assert upstream["GOPROXY"] == "file:///opt/project-deps/go/cache/download,https://goproxy.example,direct"
    assert _probe_environment({**recipe, "environment": dict(environment)})["GOPROXY"] == environment["GOPROXY"]
    # Without -mod=mod the image cache is complete for the module graph and stays in place.
    readonly = _probe_environment({**recipe, "environment": {"GOFLAGS": "-mod=readonly",
                                                              "GOMODCACHE": "/go/pkg/mod"}})
    assert readonly["GOMODCACHE"] == "/opt/project-deps/go"
    assert "GOPROXY" not in readonly
