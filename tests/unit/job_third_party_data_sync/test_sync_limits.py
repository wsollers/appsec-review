"""Private byte-budget regressions; no cve-bin-tool library or image is executed."""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_third_party_data_sync.steps.cve_bin_tool_db_build import database as cve
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync import feed as nvd
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.models import NvdSettings
from tests.unit.job_third_party_data_sync.test_cve_bin_tool_database import _settings, write_databases
from tests.unit.job_third_party_data_sync.test_sync_closure import _publisher, private_offline_only
from tests.unit.job_third_party_data_sync.test_nvd_sync_job import FakeClient


@pytest.mark.parametrize("field", ["max_uncompressed_bytes", "max_layer_bytes", "max_total_layer_bytes"],
                         ids=["nvd-expanded", "cve-layer", "cve-total"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "64"], ids=["zero", "negative", "bool", "float", "text"])
def test_byte_limits_require_positive_integers(tmp_path, field, value):
    with pytest.raises(ValueError, match="positive integer"):
        if field == "max_uncompressed_bytes":
            NvdSettings.from_mapping(tmp_path, {"feed_root": "nvd", field: value})
        else:
            _settings(tmp_path, **{field: value})


def test_cve_layer_limit_cannot_exceed_total(tmp_path):
    with pytest.raises(ValueError, match="per-layer.*total"):
        _settings(tmp_path, max_layer_bytes=128, max_total_layer_bytes=64)


@pytest.mark.parametrize("domain", ["compressed", "expanded"])
def test_cve_default_budget_admits_full_replay_without_relaxing_layer_bounds(tmp_path, domain):
    """Exercise 3018 MiB of accounting without allocating feed-sized fixtures."""
    settings = _settings(tmp_path)
    mib = 1024 * 1024
    remaining = settings.max_total_layer_bytes
    for size in [398 * mib] * 7 + [232 * mib]:
        cve._check_layer_bytes(size, settings.max_layer_bytes, remaining, domain)
        remaining -= size
    assert remaining == (4096 - 3018) * mib
    with pytest.raises(ValueError, match="CVE_BIN_TOOL_LAYER_BYTE_LIMIT"):
        cve._check_layer_bytes(512 * mib + 1, settings.max_layer_bytes, remaining, domain)
    with pytest.raises(ValueError, match="CVE_BIN_TOOL_TOTAL_LAYER_BYTE_LIMIT"):
        cve._check_layer_bytes(1, settings.max_layer_bytes, 0, domain)
    frozen = _settings(tmp_path, max_total_layer_bytes=512 * mib)
    with pytest.raises(ValueError, match="CVE_BIN_TOOL_TOTAL_LAYER_BYTE_LIMIT"):
        cve._check_layer_bytes(398 * mib, frozen.max_layer_bytes,
                              frozen.max_total_layer_bytes - 398 * mib, domain)


def _document(size=512):
    return json.dumps({"format": "NVD_CVE", "version": "2.0", "padding": "x" * size,
                       "vulnerabilities": []}).encode()


def test_nvd_declared_expansion_fails_before_downloading(tmp_path):
    class Client(FakeClient):
        def download(self, *args, **kwargs):
            pytest.fail("oversized metadata must fail before transport")

    publisher = _publisher(tmp_path, Client(_document()), max_uncompressed_bytes=64)
    with pytest.raises(ValueError, match="NVD_UNCOMPRESSED_BYTE_LIMIT"):
        publisher.sync("too-large")
    assert not (publisher.root / "current.json").exists()


def test_nvd_dishonest_size_stops_at_remaining_plus_one_and_preserves_pointer(tmp_path, monkeypatch):
    publisher = _publisher(tmp_path)
    first = publisher.sync("first")
    before = (publisher.root / "current.json").read_bytes()
    old_manifest = publisher.root / "snapshots" / first["snapshot_id"] / "manifest.json"
    old_bytes = old_manifest.read_bytes()
    raw = _document(4096)
    path = tmp_path / "dishonest.gz"
    path.write_bytes(gzip.compress(raw))
    reads = []
    original = gzip.GzipFile.read

    def measured(stream, size=-1):
        value = original(stream, size)
        reads.append((size, len(value)))
        return value

    monkeypatch.setattr(gzip.GzipFile, "read", measured)
    metadata = {"gzSize": path.stat().st_size, "size": 32, "sha256": hashlib.sha256(raw).hexdigest()}
    with pytest.raises(ValueError):
        publisher._verify_year(path, 2026, metadata)
    assert sum(size for _, size in reads) <= 33
    assert reads[0][0] == 33
    assert (publisher.root / "current.json").read_bytes() == before
    assert old_manifest.read_bytes() == old_bytes


def test_nvd_exact_expansion_bound_accepts_valid_snapshot(tmp_path):
    raw = _document()
    publisher = _publisher(tmp_path, FakeClient(raw), max_uncompressed_bytes=len(raw))
    pointer = publisher.sync("exact")
    assert publisher.verify()["snapshot_id"] == pointer["snapshot_id"]


def _layers(tmp_path, documents):
    root = tmp_path / "source"
    root.mkdir()
    layers = []
    for index, raw in enumerate(documents):
        path = root / f"{index}.json.gz"
        path.write_bytes(gzip.compress(raw, mtime=0))
        layers.append({"path": str(path), "size_bytes": path.stat().st_size,
                       "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return {"snapshot_id": "sha256-fixture", "manifest_sha256": "a" * 64,
            "layers": layers, "layer_count": len(layers)}


def _prior_database(settings, tmp_path):
    directory = tmp_path / "prior"
    write_databases(directory)
    cve.publish(settings, {
        "directory": str(directory), "nvd_snapshot_id": "prior", "nvd_manifest_sha256": "a" * 64,
        "tool": {"tool_version": "3.4"}, "cve_count": 1, "range_count": 0, "layer_records": 1,
    })
    return (settings.feed_root / "current.json").read_bytes()


@pytest.mark.parametrize("kind", ["compressed-layer", "compressed-total", "expanded-layer", "expanded-total"],
                         ids=["compressed-layer", "compressed-total", "expanded-layer", "expanded-total"])
def test_cve_admission_bounds_both_byte_domains_before_runner(tmp_path, kind):
    raw = _document(128)
    documents = [raw, raw] if kind.endswith("total") else [raw]
    resolved = _layers(tmp_path, documents)
    compressed_size = resolved["layers"][0]["size_bytes"]
    per_layer = compressed_size - 1 if kind == "compressed-layer" else (
        compressed_size + 1 if kind == "compressed-total" else len(raw) - 1 if kind == "expanded-layer" else len(raw))
    total = per_layer if kind.endswith("total") else per_layer * 2
    settings = _settings(tmp_path, max_layer_bytes=per_layer, max_total_layer_bytes=total)
    before = _prior_database(settings, tmp_path)

    def forbidden(*args):
        pytest.fail("oversized input must fail before any external builder")

    with pytest.raises(ValueError, match="CVE_BIN_TOOL_.*BYTE_LIMIT"):
        cve.build(settings, resolved, tmp_path / "work", forbidden)
    assert (settings.feed_root / "current.json").read_bytes() == before


def test_cve_staging_rejects_dishonest_compressed_size_before_runner(tmp_path):
    resolved = _layers(tmp_path, [_document()])
    resolved["layers"][0]["size_bytes"] = 1
    settings = _settings(tmp_path, max_layer_bytes=64, max_total_layer_bytes=64)
    with pytest.raises(ValueError, match="CVE_BIN_TOOL_.*BYTE_LIMIT|NVD layer changed"):
        cve.build(settings, resolved, tmp_path / "work",
                  lambda *args: pytest.fail("dishonest input reached the builder"))


def _builder():
    path = Path(__file__).resolve().parents[3] / "tools/cve-bin-tool/build_db.py"
    spec = importlib.util.spec_from_file_location("bounded_cve_builder", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("kind", ["compressed-layer", "compressed-total", "expanded-layer", "expanded-total"],
                         ids=["compressed-layer", "compressed-total", "expanded-layer", "expanded-total"])
def test_builder_materialization_enforces_independent_cumulative_budgets(tmp_path, kind):
    raw = _document(128)
    resolved = _layers(tmp_path, [raw, raw] if kind.endswith("total") else [raw])
    compressed_size = resolved["layers"][0]["size_bytes"]
    per_layer = compressed_size - 1 if kind == "compressed-layer" else (
        compressed_size + 1 if kind == "compressed-total" else len(raw) - 1 if kind == "expanded-layer" else len(raw))
    limits = {"max_layer_bytes": per_layer, "max_total_layer_bytes": per_layer * (1 if kind.endswith("total") else 2)}
    with pytest.raises(ValueError, match="CVE_BIN_TOOL_.*BYTE_LIMIT"):
        list(_builder().layer_entries([Path(layer["path"]) for layer in resolved["layers"]], limits))


def test_builder_reads_only_remaining_plus_one_expanded_bytes(tmp_path, monkeypatch):
    resolved = _layers(tmp_path, [_document(4096)])
    reads = []
    original = gzip.GzipFile.read

    def measured(stream, size=-1):
        value = original(stream, size)
        reads.append((size, len(value)))
        return value

    monkeypatch.setattr(gzip.GzipFile, "read", measured)
    limits = {"max_layer_bytes": 128, "max_total_layer_bytes": 128}
    with pytest.raises(ValueError, match="BYTE_LIMIT"):
        list(_builder().layer_entries([Path(resolved["layers"][0]["path"])], limits))
    assert reads and reads[0][0] == 129
    assert sum(size for _, size in reads) <= 129


def test_builder_valid_layers_and_limits_use_real_json_and_gzip(tmp_path):
    documents = [_document(16), _document(32)]
    resolved = _layers(tmp_path, documents)
    limits = {"max_layer_bytes": 512, "max_total_layer_bytes": 512}
    (tmp_path / "limits.json").write_text(json.dumps(limits))
    builder = _builder()
    assert builder.load_limits(tmp_path) == limits
    assert list(builder.layer_entries([Path(item["path"]) for item in resolved["layers"]], limits)) == [[], []]


def test_builder_compressed_reads_remain_bounded_after_preflight_file_growth(tmp_path, monkeypatch):
    resolved = _layers(tmp_path, [_document(16)])
    path = Path(resolved["layers"][0]["path"])
    limit = path.stat().st_size
    original = Path.open

    def grow_before_read(candidate, mode="r", *args, **kwargs):
        if candidate == path and mode == "rb":
            with original(candidate, "ab") as stream:
                stream.write(b"\0" * 512)
        return original(candidate, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", grow_before_read)
    with pytest.raises(ValueError, match="BYTE_LIMIT.*compressed"):
        list(_builder().layer_entries([path], {"max_layer_bytes": limit, "max_total_layer_bytes": limit}))


def test_cve_stages_exact_limits_for_the_isolated_builder(tmp_path):
    resolved = _layers(tmp_path, [_document()])
    settings = _settings(tmp_path, max_layer_bytes=1024, max_total_layer_bytes=2048)

    def external_builder(settings, source, output):
        assert json.loads((source / "limits.json").read_text()) == {
            "max_layer_bytes": 1024, "max_total_layer_bytes": 2048,
        }
        write_databases(output)
        return {"tool_version": "3.4", "image": "fixture", "image_id": "sha256:" + "b" * 64}

    assert cve.build(settings, resolved, tmp_path / "work", external_builder)["cve_count"] == 1
