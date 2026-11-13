"""Pin-update transaction branches with synthetic recipes and a typed-loader boundary fake."""

import hashlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from appsec_review.config import loader
from appsec_review.config.host_pins import HostPins, parse_host_pins, serialize_host_pins
from appsec_review.jobs.job_image_pin_verification.pins import PinUpdateError, update_pins
from appsec_review import storage
from tests.unit.job_image_pin_verification.support import PIN_A, PIN_B


def inputs(tmp_path, *, existing=False, runtime_records=()):
    config = tmp_path / "appsec-review.toml"
    config.write_text(
        '[jobs.job_one.settings]\ntag = "fixture/config"\n'
        '[reporting.telemetry_report]\nimage_tag = "fixture/report"\n', encoding="utf-8")
    catalog = tmp_path / "catalog.toml"
    catalog.write_text(
        '[[images]]\nid = "a"\nstate = "enabled"\ntag = "fixture/catalog"\n'
        '[[images]]\nid = "duplicate"\nstate = "enabled"\ntag = "fixture/config"\n'
        '[[images]]\nid = "manual"\nstate = "enabled"\nmanual = true\ntag = "fixture/manual"\n'
        '[[images]]\nid = "off"\nstate = "retired"\ntag = "fixture/retired"\n', encoding="utf-8")
    host = tmp_path / "fixture-host.toml"
    if existing:
        host.write_bytes(serialize_host_pins({
            "fixture/catalog": PIN_A, "fixture/config": PIN_A,
            "fixture/manual": PIN_A, "fixture/report": PIN_A,
        }, list(runtime_records)))
    return config, catalog, host


def loader_boundary(monkeypatch, runtimes=()):
    configured = SimpleNamespace(typed_settings=SimpleNamespace(preinstalled_runtimes=list(runtimes)))
    job = Mock(return_value=configured)
    load = Mock(return_value=SimpleNamespace(job=job))
    monkeypatch.setattr(loader, "load_config", load)
    return load, job


def all_present(argv, timeout):
    assert tuple(argv[:3]) == ("docker", "image", "inspect")
    assert tuple(argv[4:]) == ("--format", "{{.Id}}") and timeout == 60
    return 0, PIN_A.encode(), b"", False


@pytest.mark.parametrize("write", [False, True], ids=["dry-run", "write"])
def test_update_sorts_deduplicates_all_recipes_and_validates_candidate_before_publication(tmp_path, monkeypatch, write):
    config, catalog, host = inputs(tmp_path)
    before = config.read_bytes(), catalog.read_bytes()
    load, job = loader_boundary(monkeypatch)
    calls = []

    def runner(argv, timeout):
        calls.append(argv[3])
        return all_present(argv, timeout)

    report = update_pins(config_path=config, catalog_path=catalog, host_path=host, profile="fixture-profile",
                         write=write, runner=runner)
    expected_tags = ["fixture/catalog", "fixture/config", "fixture/manual", "fixture/report"]
    content = serialize_host_pins(dict.fromkeys(expected_tags, PIN_A), [])
    assert calls == expected_tags
    assert report == {
        "written": write, "checked": 4, "host_file": str(host),
        "edits": [{"tag": tag, "old": None, "new": PIN_A} for tag in expected_tags],
        "failures": [], "sha256": hashlib.sha256(content).hexdigest(),
    }
    load.assert_called_once_with(config, profile="fixture-profile", host_pins=HostPins(host, content))
    job.assert_called_once_with("job_codeql_analysis")
    assert (config.read_bytes(), catalog.read_bytes()) == before
    assert host.exists() is write
    if write:
        assert host.read_bytes() == content


def test_identical_bindings_report_written_without_rewriting_host_file(tmp_path, monkeypatch):
    config, catalog, host = inputs(tmp_path, existing=True)
    before = host.read_bytes()
    loader_boundary(monkeypatch)
    publish = Mock(side_effect=AssertionError("identical content must not be rewritten"))
    monkeypatch.setattr(storage, "atomic_bytes", publish)
    report = update_pins(config_path=config, catalog_path=catalog, host_path=host, write=True, runner=all_present)
    assert report == {
        "written": True, "checked": 4, "host_file": str(host), "edits": [], "failures": [],
        "sha256": hashlib.sha256(before).hexdigest(),
    }
    assert host.read_bytes() == before
    publish.assert_not_called()


def test_update_refuses_all_writes_when_any_tag_is_missing_or_uninspectable(tmp_path, monkeypatch):
    config, catalog, host = inputs(tmp_path, existing=True)
    before = tuple(path.read_bytes() for path in (config, catalog, host))
    load, _ = loader_boundary(monkeypatch)

    def runner(argv, timeout):
        if argv[3] == "fixture/catalog":
            return 1, b"", b"No such image: fixture/catalog", False
        if argv[3] == "fixture/config":
            return 1, b"", b"daemon down", False
        return 0, PIN_B.encode(), b"", False

    report = update_pins(config_path=config, catalog_path=catalog, host_path=host, write=True, runner=runner)
    assert report == {
        "written": False, "checked": 4, "host_file": str(host),
        "edits": [
            {"tag": "fixture/catalog", "old": PIN_A, "new": None},
            {"tag": "fixture/config", "old": PIN_A, "new": None},
            {"tag": "fixture/manual", "old": PIN_A, "new": PIN_B},
            {"tag": "fixture/report", "old": PIN_A, "new": PIN_B},
        ],
        "failures": [
            f'host-pins.images["fixture/catalog"]: tag fixture/catalog pinned {PIN_A} resolved missing',
            f'host-pins.images["fixture/config"]: tag fixture/config pinned {PIN_A} '
            'resolved not inspectable (docker image inspect exited 1: daemon down)',
        ],
    }
    assert tuple(path.read_bytes() for path in (config, catalog, host)) == before
    load.assert_not_called()


@pytest.mark.parametrize("error", ["missing-config", "bad-config", "bad-utf8", "missing-catalog", "bad-host"], ids=str)
def test_update_wraps_input_failures_and_does_not_inspect_or_publish(tmp_path, error):
    config, catalog, host = inputs(tmp_path)
    if error == "missing-config":
        config.unlink()
    elif error == "bad-config":
        config.write_bytes(b"[[")
    elif error == "bad-utf8":
        config.write_bytes(b"\xff")
    elif error == "missing-catalog":
        catalog.unlink()
    else:
        host.write_bytes(b"[[")
    before = host.read_bytes() if host.exists() else None
    runner = Mock(side_effect=AssertionError("invalid input must not be inspected"))
    with pytest.raises(PinUpdateError, match="cannot read the pins:") as failure:
        update_pins(config_path=config, catalog_path=catalog, host_path=host, write=True, runner=runner)
    assert isinstance(failure.value.__cause__, (OSError, ValueError))
    assert (host.read_bytes() if host.exists() else None) == before
    runner.assert_not_called()


@pytest.mark.parametrize("error", [OSError("cannot read"), ValueError("invalid config"), KeyError("missing job")],
                         ids=["os-error", "value-error", "key-error"])
def test_update_wraps_typed_configuration_refusals_without_publishing(tmp_path, monkeypatch, error):
    config, catalog, host = inputs(tmp_path)
    monkeypatch.setattr(loader, "load_config", Mock(side_effect=error))
    with pytest.raises(PinUpdateError, match="host pins do not load through the typed configuration:") as failure:
        update_pins(config_path=config, catalog_path=catalog, host_path=host, write=True, runner=all_present)
    assert failure.value.__cause__ is error
    assert "no files changed" in str(failure.value) and not host.exists()


@pytest.mark.parametrize("change", ["catalog", "config", "host-create", "host-modify", "host-delete"], ids=str)
def test_update_rechecks_all_original_inputs_before_atomic_publication(tmp_path, monkeypatch, change):
    config, catalog, host = inputs(tmp_path, existing=change in {"host-modify", "host-delete"})
    load, _ = loader_boundary(monkeypatch)

    def changed(*args, **kwargs):
        if change == "config":
            config.write_bytes(config.read_bytes() + b"\n# concurrent edit\n")
        elif change == "catalog":
            catalog.write_bytes(catalog.read_bytes() + b"\n# concurrent edit\n")
        elif change == "host-delete":
            host.unlink()
        else:
            host.write_bytes(serialize_host_pins({"concurrent/tag": PIN_B}, []))
        return load.return_value

    load.side_effect = changed
    publish = Mock(side_effect=AssertionError("concurrent change must not be overwritten"))
    monkeypatch.setattr(storage, "atomic_bytes", publish)
    with pytest.raises(PinUpdateError, match="image binding inputs changed during inspection; no files changed"):
        update_pins(config_path=config, catalog_path=catalog, host_path=host, write=True, runner=all_present)
    publish.assert_not_called()
    if change in {"host-create", "host-modify"}:
        assert parse_host_pins(host.read_bytes())["images"] == {"concurrent/tag": PIN_B}
    else:
        assert not host.exists()


@pytest.mark.parametrize("failure_id", [None, PIN_A, PIN_B], ids=["available", "build-missing", "runtime-moved"])
def test_update_checks_each_declared_preinstalled_id_without_relabelling_the_declaration(
        tmp_path, monkeypatch, failure_id):
    declaration = {
        "source_image_id": PIN_A, "build_image_id": PIN_A, "runtime_image_id": PIN_B,
        "runtime_user": "1000:1000", "codeql_release_id": "codeql-fixture",
        "runner_release_id": "runner-fixture", "runner_source": "application",
    }
    config, catalog, host = inputs(tmp_path, existing=True, runtime_records=[declaration])
    before = host.read_bytes()
    loader_boundary(monkeypatch, [SimpleNamespace(build_image_id=PIN_A, runtime_image_id=PIN_B)])
    calls = []

    def runner(argv, timeout):
        tag = argv[3]
        calls.append(tag)
        if tag == failure_id:
            if tag == PIN_A:
                return 1, b"", b"No such image: build", False
            return 0, PIN_A.encode(), b"", False
        return 0, (tag if tag.startswith("sha256:") else PIN_A).encode(), b"", False

    if failure_id is not None:
        with pytest.raises(PinUpdateError, match=f"declared preinstalled image is not available: {failure_id}"):
            update_pins(config_path=config, catalog_path=catalog, host_path=host, write=True, runner=runner)
    else:
        result = update_pins(config_path=config, catalog_path=catalog, host_path=host, write=True, runner=runner)
        assert result["written"] is True and result["edits"] == [] and result["failures"] == []
    expected_ids = [PIN_A] if failure_id == PIN_A else [PIN_A, PIN_B]
    assert calls == ["fixture/catalog", "fixture/config", "fixture/manual", "fixture/report", *expected_ids]
    assert host.read_bytes() == before
    assert parse_host_pins(before)["preinstalled_runtimes"] == [declaration]


def test_update_propagates_atomic_publication_failure_without_a_success_report(tmp_path, monkeypatch):
    config, catalog, host = inputs(tmp_path)
    loader_boundary(monkeypatch)
    error = OSError("disk full")
    monkeypatch.setattr(storage, "atomic_bytes", Mock(side_effect=error))
    with pytest.raises(OSError, match="disk full") as failure:
        update_pins(config_path=config, catalog_path=catalog, host_path=host, write=True, runner=all_present)
    assert failure.value is error and not host.exists()
