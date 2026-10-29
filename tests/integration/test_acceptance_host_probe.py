"""Bounded filesystem diagnosis, not a platform-reliability qualification."""
from __future__ import annotations

from contextlib import contextmanager
import json
import time

from appsec_review.jobs.job_third_party_data_sync.publication import publish_snapshot, verify_current
from appsec_review.storage import atomic_json


def test_owned_atomic_status_and_feed_publication_without_retries(acceptance_workspace) -> None:
    workspace = acceptance_workspace
    root = workspace.require_owned_path(workspace.root / "host-probe")
    root.mkdir()
    status = root / "attempt" / "steps" / "probe" / "tasks" / "transaction" / "status.json"
    feed = root / "feed"
    records = []

    @contextmanager
    def observe(operation, transaction, pointer):
        started = time.monotonic()
        previous = pointer.read_bytes() if pointer.exists() else None
        record = {"operation": operation, "transaction": transaction,
                  "pointer": str(pointer.relative_to(workspace.root)), "outcome": "running"}
        try:
            with workspace.span("acceptance.host-probe." + operation):
                yield
            record["outcome"] = "passed"
        except OSError as error:
            record.update(outcome="failed", exception_type=type(error).__name__,
                          errno=error.errno, winerror=getattr(error, "winerror", None),
                          previous_pointer_preserved=(
                              (pointer.read_bytes() if pointer.exists() else None) == previous))
            raise
        finally:
            record["duration_seconds"] = time.monotonic() - started
            records.append(record)

    try:
        for transaction in range(5):
            with observe("atomic-status", transaction, status):
                atomic_json(status, {"status": "SUCCEEDED", "probe_transaction": transaction})
                assert json.loads(status.read_text(encoding="utf-8"))["probe_transaction"] == transaction
            source = root / f"catalog-{transaction}.json"
            atomic_json(source, {"probe_transaction": transaction})
            with observe("feed-publication", transaction, feed / "current.json"):
                pointer = publish_snapshot(
                    feed, feed_id="mitre", schema="appsec-review/acceptance-host-probe/1",
                    files={"catalog.json": source}, manifest_fields={"probe_transaction": transaction})
                verified = verify_current(feed, "mitre")
                assert verified["snapshot_id"] == pointer["snapshot_id"]
                assert verified["verified_files"] == 1
                assert (feed / "snapshots" / pointer["snapshot_id"] / "catalog.json").read_bytes() == source.read_bytes()
        assert len(records) == 10 and all(record["outcome"] == "passed" for record in records)
    finally:
        atomic_json(root / "transactions.json", {
            "schema": "appsec-review/acceptance-host-probe/1",
            "transactions": records,
            "retry_count": 0,
            "scope": "owned_atomic_status_and_feed_directory_publication",
            "limitation": "No platform reliability or cause of previous WinError 5 established.",
        })
