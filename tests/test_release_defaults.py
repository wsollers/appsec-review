"""Release ids: declared, derived from the host pins, set by an overlay, or absent (T-080)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tomllib

import pytest

from appsec_review.config import load_config
from appsec_review.config.loader import OVERLAY_LAYER, OVERLAY_RELEASE_KEY, RELEASE_SOURCES_KEY, overlay_capacity_keys
from tests.host_pins_support import fixture_bindings, fixture_preinstalled, write_host_pins
from tests.test_job_runtime import write_config


ROOT = Path(__file__).parents[1]
NATIVE_TAG = "audit-buildenv-cpp:local"
NATIVE_SETTING = "jobs.job_project_build.settings.profiles.native.image_id"
SHIPPED = {"platform": 'platform = "appsec-review-2026-11-11"\n',
           "validation": 'validation = "validation-2026-11-11"\n'}
TRACKED = ("build_toolchain", "platform", "validation")
UNDECLARED = {"build_toolchain": "no native build profile image is configured",
              "platform": "no derived default", "validation": "no derived default"}


def _load(tmp_path: Path, *, drop: tuple[str, ...] = (), declare: dict[str, str] | None = None,
          overlay: str | None = None, host_pins: Path | None = None):
    """The shipped configuration, with release lines removed or added, under inert host pins."""
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    for name in drop:
        assert SHIPPED[name] in source, name
        source = source.replace(SHIPPED[name], "", 1)
    header = "[review_policy.releases]\n"
    assert source.count(header) == 1
    declared = "".join(f'{name} = "{value}"\n' for name, value in sorted((declare or {}).items()))
    source = source.replace(header, header + declared, 1)
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "appsec-review.toml"
    path.write_text(source, encoding="utf-8")
    overlay_path = ""
    if overlay is not None:
        overlay_path = tmp_path / "local-overlay.toml"
        overlay_path.write_text(overlay, encoding="utf-8")
    return load_config(path, profile="dev", overlay=overlay_path, host_pins=host_pins)


def _releases(config) -> tuple[dict[str, str], dict[str, dict]]:
    resolved = json.loads(config.resolved_json)
    assert resolved["review_policy"]["releases"] == config.review_policy.releases.view()
    return config.review_policy.releases.view(), resolved[RELEASE_SOURCES_KEY]


def _overlay(**releases: str) -> str:
    return "[review_policy.releases]\n" + "".join(f'{name} = "{value}"\n' for name, value in releases.items())


def test_the_shipped_file_declares_platform_and_validation_and_leaves_build_toolchain_to_the_host() -> None:
    declared = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))["review_policy"]["releases"]
    assert "build_toolchain" not in declared
    assert {"platform", "validation"} <= declared.keys()


@pytest.mark.parametrize("name", TRACKED)
def test_a_release_declared_in_the_base_file_is_used_and_recorded_as_declared(tmp_path: Path, name: str) -> None:
    drop = () if name == "build_toolchain" else (name,)
    releases, sources = _releases(_load(tmp_path, drop=drop, declare={name: "declared-in-base/1"}))
    assert releases[name] == "declared-in-base/1"
    assert sources[name] == {"source": "declared", "layer": "base"}


def test_an_undeclared_build_toolchain_is_derived_from_the_host_pinned_native_build_image(tmp_path: Path) -> None:
    config = _load(tmp_path)
    releases, sources = _releases(config)
    resolved = json.loads(config.resolved_json)
    native = resolved["jobs"]["job_project_build"]["settings"]["profiles"]["native"]
    assert native["tag"] == NATIVE_TAG
    assert releases["build_toolchain"] == native["image_id"] == fixture_bindings()[NATIVE_TAG]
    assert sources["build_toolchain"] == {
        "source": "derived", "layer": "host-pins", "host_pins_sha256": config.host_pins.sha256,
        "setting": NATIVE_SETTING, "image_tag": NATIVE_TAG}
    # Every id in the table is accounted for, not only the three with special handling.
    assert sources.keys() == releases.keys()
    assert sources["codeql"] == {"source": "declared", "layer": "base"}


def test_the_derived_build_toolchain_follows_a_re_pinned_build_image(tmp_path: Path) -> None:
    rebuilt = "sha256:" + "7" * 64
    pins = write_host_pins(tmp_path / "rebuilt-pins.toml", images={**fixture_bindings(), NATIVE_TAG: rebuilt},
                           runtimes=[item for item in fixture_preinstalled()
                                     if item["build_image_id"] != fixture_bindings()[NATIVE_TAG]])
    before = _load(tmp_path / "before")
    after = _load(tmp_path / "after", host_pins=pins)
    assert _releases(after)[0]["build_toolchain"] == rebuilt != _releases(before)[0]["build_toolchain"]
    assert _releases(after)[1]["build_toolchain"]["host_pins_sha256"] == after.host_pins.sha256
    # A declared value does not move with the image.
    fixed = _load(tmp_path / "fixed", declare={"build_toolchain": "fixed/1"}, host_pins=pins)
    assert _releases(fixed)[0]["build_toolchain"] == "fixed/1"


@pytest.mark.parametrize("name", TRACKED)
@pytest.mark.parametrize("base", ["absent-in-base", "declared-in-base"])
def test_an_overlay_release_wins_over_the_base_value_and_the_derived_default(tmp_path: Path, name: str,
                                                                               base: str) -> None:
    if base == "declared-in-base":
        drop = () if name == "build_toolchain" else (name,)
        arguments = {"drop": drop, "declare": {name: "declared-in-base/1"}}
    else:
        arguments = {"drop": () if name == "build_toolchain" else (name,)}
    config = _load(tmp_path, overlay=_overlay(**{name: "host-overlay/7"}), **arguments)
    releases, sources = _releases(config)
    assert releases[name] == "host-overlay/7"
    assert sources[name] == {"source": "declared", "layer": OVERLAY_LAYER}
    assert json.loads(config.resolved_json)["configuration_overlay"]["keys"] == [f"review_policy.releases.{name}"]
    # The ids the overlay did not name keep their own origin.
    for other in set(TRACKED) - {name}:
        assert sources[other]["source"] == ("derived" if other == "build_toolchain" else "declared")


@pytest.mark.parametrize("name", TRACKED)
def test_a_release_with_no_declaration_and_no_available_source_stays_missing(tmp_path: Path, name: str) -> None:
    if name == "build_toolchain":
        # No native build profile is configured, so there is no bound image to derive from.
        config = load_config(write_config(tmp_path), profile="dev", overlay="")
    else:
        # platform and validation have no derived default, even where host pins are present.
        config = _load(tmp_path, drop=(name,))
    releases, sources = _releases(config)
    assert name not in releases
    assert sources[name]["source"] == "undeclared"
    assert UNDECLARED[name] in sources[name]["reason"]
    assert config.review_policy.releases.require(name) == (False, "missing_release_identity")


def test_the_overlay_layer_hash_covers_its_release_ids(tmp_path: Path) -> None:
    plain = _load(tmp_path / "plain")
    first = _load(tmp_path / "first", overlay=_overlay(build_toolchain="host-overlay/7"))
    second = _load(tmp_path / "second", overlay=_overlay(build_toolchain="host-overlay/8"))
    for config, value in ((first, "host-overlay/7"), (second, "host-overlay/8")):
        content = _overlay(build_toolchain=value).encode()
        layer = next(item for item in config.layers if item.get("layer") == OVERLAY_LAYER)
        assert layer["sha256"] == config.overlay_sha256 == hashlib.sha256(content).hexdigest()
        record = json.loads(config.resolved_json)["configuration_overlay"]
        assert record["sha256"] == layer["sha256"]
        assert record["document"] == {"review_policy": {"releases": {"build_toolchain": value}}}
    assert first.overlay_sha256 != second.overlay_sha256
    assert len({plain.resolved_sha256, first.resolved_sha256, second.resolved_sha256}) == 3
    assert all(item.get("layer") != OVERLAY_LAYER for item in plain.layers)


def test_an_overlay_may_set_releases_beside_capacity_and_nothing_else_under_review_policy() -> None:
    assert OVERLAY_RELEASE_KEY == "review_policy.releases.*"
    assert overlay_capacity_keys({"review_policy": {
        "releases": {"validation": "v/2", "build_toolchain": "t/1"}, "resources": {"io_slots": 4}}}) == (
        "review_policy.releases.build_toolchain", "review_policy.releases.validation",
        "review_policy.resources.io_slots")


@pytest.mark.parametrize(("overlay", "message"), [
    ('[review_policy]\nmode = "strict"\n[review_policy.releases]\nplatform = "p/1"\n', "rejected: review_policy.mode"),
    ('[review_policy.image_builder]\nendpoint = "x"\n', "rejected: review_policy.image_builder"),
    ('[review_policy.release]\nplatform = "p/1"\n', "rejected: review_policy.release"),
    ("[review_policy.releases]\n", "review_policy.releases must be a non-empty table"),
    ('[review_policy.releases]\n"bad name" = "p/1"\n', "review_policy.releases.bad name must be a bounded opaque"),
    ('[review_policy.releases]\nplatform = ""\n', "review_policy.releases.platform must be a bounded opaque"),
    ("[review_policy.releases]\nplatform = 7\n", "review_policy.releases.platform must be a bounded opaque"),
    ('[review_policy.releases.platform]\nid = "p/1"\n', "review_policy.releases.platform must be a bounded opaque"),
    ('[jobs.job_project_build.settings.profiles.native]\ntag = "other:local"\n', "rejected: jobs.job_project_build"),
], ids=["policy-mode", "image-builder", "misspelt-table", "empty-table", "bad-name", "empty-id", "integer-id",
        "table-id", "build-profile"])
def test_the_overlay_still_refuses_unknown_keys_and_malformed_release_ids(tmp_path: Path, overlay: str,
                                                                          message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _load(tmp_path, overlay=overlay)


def test_a_derived_build_toolchain_dispatches_a_build_iteration(tmp_path: Path) -> None:
    """The three ids the controller requires resolve on a host with pins and no declared toolchain."""
    from appsec_review.jobs.build_iterations import BuildIterations, IterationOutcome, digest
    from appsec_review.jobs.build_workspace import ProductSpec
    from appsec_review.jobs.job_target_analysis_plan import load_accepted_plan
    from tests.accepted_topology_fixture import accept_isolated_dispatch
    from tests.test_build_iterations import fixture
    from tests.test_build_recipe_replay import NATIVE_AXES, NATIVE_OBJECT

    releases, sources = _releases(_load(tmp_path / "configuration"))
    assert sources["build_toolchain"]["source"] == "derived"
    source, _documents, _run, graph, dispatches = fixture(tmp_path / "fixture")
    dispatch = {key: value for key, value in next(item for item in dispatches if item["root"] == "a").items()
                if key != "descriptor_package"}
    dispatch["source_fingerprint"] = graph["source_fingerprint"]
    # A variant that names a toolchain must name the resolved release, here the derived one.
    dispatch["build_variant"] = {**dispatch["build_variant"], "toolchain": releases["build_toolchain"]}
    run_root, bound = accept_isolated_dispatch(tmp_path / "accepted", source, dispatch, ["a/CMakeLists.txt"],
                                               releases=releases)
    accepted = load_accepted_plan(run_root)["build_topology"]["executable_graph"]
    (node,) = accepted["nodes"]
    calls = []

    def worker(request, dagster_id):
        calls.append(request["node_id"])
        product = node["products"][0]
        path = controller.workspace.paths.target / "a/build/libA.a"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(NATIVE_OBJECT)
        return IterationOutcome(
            {"build_unit_id": request["node_id"], "family": node["family"], "terminal_status": "SUCCEEDED",
             "gaps": [], "artifacts": []},
            (ProductSpec("target/a/build/libA.a", product["kind"], product["product_id"], product["interface"],
                         product["variant"], role="static_archive", axes=NATIVE_AXES),), True)

    controller = BuildIterations(run_root, source, accepted, [bound], configuration={"fixture": 1},
                                 releases=releases, execution_identity="fixture-executor/1",
                                 output_policy_identity=digest("outputs"))
    # The refusal this replaces ("missing release evidence: build_toolchain, ...") is raised by the
    # same binding step; test_build_iterations covers it with no releases at all.
    assert controller._binding(node["build_unit_id"], ()).toolchain_identity == releases["build_toolchain"]
    result = controller.run(worker, invoke=lambda request, label, execute: execute(request, "dagster-0"))
    assert calls == [node["build_unit_id"]]
    assert not [gap for gap in result["gaps"] if node["build_unit_id"] in gap or "release" in gap]
    assert result["states"] == {node["build_unit_id"]: "SUCCEEDED"}
    (receipt,) = result["receipts"]
    assert receipt["terminal_status"] == "SUCCEEDED"
