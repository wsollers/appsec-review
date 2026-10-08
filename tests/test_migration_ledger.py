from pathlib import Path

from appsec_review.migration import validate_ledger


def test_migration_ledger_completely_accounts_for_archive() -> None:
    summary = validate_ledger(Path(__file__).parents[1] / "docs/migration-ledger.json")
    assert summary["graph_jobs"]["count"] == 91
    assert summary["templates"]["count"] == 116
    assert summary["graph_jobs"]["wave1_verified"] == 23
    assert summary["templates"]["wave1_verified"] == 23
