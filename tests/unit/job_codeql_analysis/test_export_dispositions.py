"""Every export outcome the CodeQL job records maps to a closed ``ProducerStatus`` disposition."""
import pytest

from appsec_review.interchange import ProducerStatus
from appsec_review.jobs.job_codeql_analysis import job as codeql_job

# The export_status values _export_one / _export_guarded produce, in source order.
EXPORT_STATUSES = ("SUCCEEDED", "NOT_APPLICABLE", "SKIPPED", "FAILED")


@pytest.mark.parametrize("export_status", EXPORT_STATUSES)
def test_export_disposition_terminal_status_is_a_producer_status(export_status):
    [disposition] = codeql_job._export_dispositions([
        {"scope_id": "scope-1", "language": "cpp", "export_status": export_status}])
    assert disposition["action"] == "export" and disposition["scope_id"] == "scope-1"
    assert ProducerStatus(disposition["terminal_status"])


def test_skipped_export_is_a_not_applicable_disposition_and_keeps_its_payload_status():
    # Run 2026-11-17-0001 on WSOLLERS1: seeded export found no finding location in the database, the
    # record said "SKIPPED", and execution.scopes failed its output contract at finalize.
    record = {"scope_id": "scope-1", "language": "cpp", "export_status": "SKIPPED", "reason": "no seeds"}
    [disposition] = codeql_job._export_dispositions([record])
    assert disposition["terminal_status"] == ProducerStatus.SKIPPED_NA.value
    assert record["export_status"] == "SKIPPED"


def test_every_source_export_status_is_covered():
    source = (codeql_job.__file__ and open(codeql_job.__file__, encoding="utf-8").read())
    import re
    found = set(re.findall(r'"export_status": "([A-Z_]+)"', source))
    assert found == set(EXPORT_STATUSES)
