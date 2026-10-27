from pathlib import Path

import pytest

from appsec_review.observability import EventLog, PipelineLog, aggregate_run_metrics
from appsec_review.observability.spans import count_work, operation_span
from appsec_review.storage.atomic import file_sha256
from appsec_review.storage.shared import verify_reference
from appsec_review.storage.validation import validation_scope


def test_validation_context_hashes_each_payload_once(tmp_path: Path, monkeypatch):
    import appsec_review.storage.validation as validation
    path = tmp_path / "payload"
    path.write_bytes(b"target")
    ref = {"path": "payload", "sha256": file_sha256(path), "size_bytes": 6}
    calls = []
    def counted(candidate):
        calls.append(candidate)
        return file_sha256(candidate)
    monkeypatch.setattr(validation, "file_sha256", counted)
    with validation_scope(tmp_path):
        verify_reference(tmp_path, ref)
        verify_reference(tmp_path, ref)
    assert calls == [path]
    with validation_scope(tmp_path):
        verify_reference(tmp_path, ref)
    assert calls == [path, path]
    path.write_bytes(b"mutate")
    with pytest.raises(ValueError, match="integrity"):
        verify_reference(tmp_path, ref)


def test_operation_spans_have_terminal_and_unavailable_resources(tmp_path: Path):
    pipeline = PipelineLog(tmp_path)
    events = EventLog(tmp_path / "events.jsonl", pipeline, {"run_id": tmp_path.name})
    with operation_span(events, "fixture.validation"):
        count_work("target_hash_bytes", 6)
    records, _ = pipeline.read()
    assert records[0]["details"]["span_id"] == records[1]["details"]["span_id"]
    terminal = records[1]["details"]
    assert terminal["work"] == {"target_hash_bytes": 6}
    assert terminal["resources"]["peak_rss_bytes"] is None
    assert terminal["resources"]["peak_rss_unavailable_reason"]
    pipeline.write("OPERATION_COMPLETED", run_id=tmp_path.name, details=terminal)
    metrics = aggregate_run_metrics(tmp_path)
    assert metrics["duplicate_lifecycle_records"] == 1
    assert metrics["work_counters"]["target_hash_bytes"] == 6


def test_operation_failure_is_terminal(tmp_path: Path):
    pipeline = PipelineLog(tmp_path)
    events = EventLog(tmp_path / "events.jsonl", pipeline, {"run_id": tmp_path.name})
    with pytest.raises(RuntimeError):
        with operation_span(events, "fixture.failure"):
            raise RuntimeError("fixture")
    records, _ = pipeline.read()
    assert records[-1]["details"]["terminal_status"] == "FAILED"


def test_nested_validation_cannot_change_snapshot_or_policy(tmp_path):
    with validation_scope(tmp_path, target_snapshot="one", policy_identity="strict"):
        with validation_scope(tmp_path):
            pass
        with pytest.raises(ValueError, match="identity changed"):
            with validation_scope(tmp_path, target_snapshot="two"):
                pass
        with pytest.raises(ValueError, match="identity changed"):
            with validation_scope(tmp_path, policy_identity="managed"):
                pass


def test_parallel_span_counters_are_exact(tmp_path):
    from appsec_review.storage.shared import PublicationThreadPoolExecutor
    pipeline = PipelineLog(tmp_path)
    events = EventLog(tmp_path / "events.jsonl", pipeline, {"run_id": tmp_path.name})
    def count(_):
        for _ in range(1000):
            count_work("target_hash_objects")
    with operation_span(events, "fixture.concurrent"):
        with PublicationThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(count, range(8)))
    assert pipeline.read()[0][-1]["details"]["work"]["target_hash_objects"] == 8000


def test_parallel_preparation_spans_keep_scope_profile_lease_and_tool_links(tmp_path):
    from threading import Barrier
    from appsec_review.storage.shared import PublicationThreadPoolExecutor

    pipeline = PipelineLog(tmp_path)
    events = EventLog(tmp_path / "events.jsonl", pipeline, {"run_id": tmp_path.name})
    barrier = Barrier(2)

    def prepare(index):
        scope, lease, invocation = f"scope-{index}", f"lease-{index}", f"tool-{index}"
        with operation_span(events, "codeql.query", unit_id="execution.scopes",
                            scope_id=scope, query_profile="security", resource_lease_id=lease):
            barrier.wait(timeout=5)
            with operation_span(events, "codeql.prepare.query", tool_invocation_id=invocation):
                count_work("copy_bytes", index + 1)

    with PublicationThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(prepare, range(2)))
    with operation_span(events, "fixture.unrelated"):
        pass
    metrics = aggregate_run_metrics(tmp_path)
    spans = metrics["resource_spans"]
    for index in range(2):
        scope_spans = [span for span in spans if span["scope_id"] == f"scope-{index}"]
        parent = next(span for span in scope_spans if span["stage"] == "codeql.query")
        child = next(span for span in scope_spans if span["stage"] == "codeql.prepare.query")
        assert child["parent_span_id"] == parent["span_id"]
        for span in scope_spans:
            assert span["unit_id"] == "execution.scopes"
            assert span["query_profile"] == "security"
            assert span["resource_lease_id"] == f"lease-{index}"
        assert child["tool_invocation_id"] == f"tool-{index}"
        assert parent["tool_invocation_id"] is None
        assert child["work"] == {"copy_bytes": index + 1}
    assert metrics["work_counters"]["copy_bytes"] == 3
    unrelated = next(span for span in spans if span["stage"] == "fixture.unrelated")
    assert all(unrelated[name] is None for name in (
        "unit_id", "scope_id", "query_profile", "resource_lease_id", "tool_invocation_id"))


def test_content_addressed_references_share_the_operation_verification(tmp_path, monkeypatch):
    import appsec_review.storage.validation as validation
    from appsec_review.storage.shared import put_bytes, reference
    ref = put_bytes(tmp_path, b"evidence")
    calls = []
    def counted(path):
        calls.append(path)
        return file_sha256(path)
    monkeypatch.setattr(validation, "file_sha256", counted)
    with validation_scope(tmp_path):
        assert reference(tmp_path, tmp_path / ref["path"]) == ref
        verify_reference(tmp_path, ref)
        assert reference(tmp_path, tmp_path / ref["path"]) == ref
    assert calls == [tmp_path / ref["path"]]


def test_canonical_validation_root_avoids_repeated_resolution(tmp_path, monkeypatch):
    from appsec_review.storage.validation import current_validation

    root = tmp_path.resolve()
    alias = root / ".." / root.name
    resolve = Path.resolve
    calls = []

    def counted(path, *args, **kwargs):
        calls.append(path)
        return resolve(path, *args, **kwargs)

    with validation_scope(root) as context:
        monkeypatch.setattr(Path, "resolve", counted)
        for _ in range(10):
            assert current_validation(root) is context
        assert calls == []
        assert current_validation(alias) is context
        assert calls == [alias]


def test_validation_root_fast_path_does_not_allow_rebound_payload(tmp_path):
    from appsec_review.storage.validation import verified_digest

    root, outside = tmp_path / "bound", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    for directory in (root, outside):
        (directory / "payload").write_bytes(b"same bytes in a different run")
    expected = file_sha256(root / "payload")
    with validation_scope(root):
        root.rename(tmp_path / "original-bound")
        root.symlink_to(outside, target_is_directory=True)
        with pytest.raises(ValueError, match="escapes"):
            verified_digest(root, root / "payload", expected)


def test_copy_accounting_counts_payloads_without_hashing_or_per_file_events(tmp_path):
    import shutil
    from appsec_review.storage.atomic import copy_file
    from appsec_review.storage.shared import put_private_file

    source = tmp_path / "source"
    source.mkdir()
    (source / "a").write_bytes(b"abc")
    (source / "b").write_bytes(b"12345")
    (source / "a").chmod(0o444)
    pipeline = PipelineLog(tmp_path)
    events = EventLog(tmp_path / "events.jsonl", pipeline, {"run_id": tmp_path.name})
    with operation_span(events, "fixture.copy") as span:
        copy_file(source / "a", tmp_path / "single")
        shutil.copytree(source, tmp_path / "tree", copy_function=copy_file)
    assert span.counters == {"copy_bytes": 11, "copy_objects": 3}
    assert (tmp_path / "single").read_bytes() == b"abc"
    assert (tmp_path / "single").stat().st_mode == (source / "a").stat().st_mode
    assert (tmp_path / "tree/b").read_bytes() == b"12345"
    assert len(pipeline.read()[0]) == 2
    with operation_span(events, "fixture.publication_copy") as span:
        reference = put_private_file(tmp_path, source / "b")
    assert span.counters["copy_bytes"] == 5 and span.counters["copy_objects"] == 1
    assert (tmp_path / reference["path"]).read_bytes() == b"12345"


def test_failed_copy_has_no_success_count_and_a_failed_terminal(tmp_path):
    from appsec_review.storage.atomic import copy_file

    pipeline = PipelineLog(tmp_path)
    events = EventLog(tmp_path / "events.jsonl", pipeline, {"run_id": tmp_path.name})
    with pytest.raises(FileNotFoundError):
        with operation_span(events, "fixture.copy_failure") as span:
            copy_file(tmp_path / "absent", tmp_path / "destination")
    assert span.counters == {}
    assert pipeline.read()[0][-1]["details"]["terminal_status"] == "FAILED"
def test_platform_metrics_distinguish_unmeasured_from_explicit_zero(tmp_path):
    from appsec_review.observability import EventLog, PipelineLog, aggregate_run_metrics
    from appsec_review.observability.spans import operation_span

    events = EventLog(tmp_path / "events.jsonl", PipelineLog(tmp_path),
                      {"run_id": tmp_path.name, "job_id": "job_fixture", "attempt_id": "attempt_0001"})
    missing = aggregate_run_metrics(tmp_path)["platform_work"]
    assert missing["hash_bytes"] is None and missing["scan_invocations"] is None
    assert missing["unavailable_reason"] == "platform_counters_not_emitted"
    with operation_span(events, "fixture.explicit_platform_measurement") as span:
        span.count("platform_hash_bytes", 0)
        span.count("platform_scan_invocations", 0)
    measured = aggregate_run_metrics(tmp_path)["platform_work"]
    assert measured["hash_bytes"] == measured["scan_invocations"] == 0
    assert measured["unavailable_reason"] is None
    assert measured["measurement_scope"] == "explicit_instrumented_counters_only"
