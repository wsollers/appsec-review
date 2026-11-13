"""Read-only, manually selected acceptance against an operator-supplied completed review.

APPSEC_T146_OWASP_ACCEPTANCE_RUN must identify a post-change run containing an assessed Python
subject beyond line 120 and explicit outside-subject omissions. No review or model is launched.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from appsec_review.owasp_workbench.evidence import EvidenceResolver
from appsec_review.owasp_workbench.indexes import WorkbenchIndex
from appsec_review.owasp_workbench.obligations import procedure_for, subjects
from appsec_review.retrieval import RetrievalCore
from appsec_review.review.scope import accept_manifest
from appsec_review.storage import file_sha256
from appsec_review.storage.shared import safe_path


pytestmark = pytest.mark.time_budget(60, reason="Re-resolve bounded OWASP package evidence in a supplied completed run")


def test_completed_run_retains_complete_late_subjects_and_scoped_unknowns():
    selected = os.environ.get("APPSEC_T146_OWASP_ACCEPTANCE_RUN")
    assert selected, "manual prerequisite: APPSEC_T146_OWASP_ACCEPTANCE_RUN is not set"
    root = Path(selected).resolve(strict=True)
    index = WorkbenchIndex(root.parent, root.name)
    assert index.manifest.get("assessment_mode") == "assessment", "qualification is not assessment"
    pin = index.manifest["accepted_upstream_manifest"]
    manifest = safe_path(root, pin["path"])
    assert file_sha256(manifest) == pin["sha256"], "upstream manifest pin no longer resolves"
    core = RetrievalCore(root.parent, root.name, manifest_path=manifest,
                         manifest_sha256=pin["sha256"])
    scope = accept_manifest(root, manifest_path=manifest, manifest_sha256=pin["sha256"])
    resolver = EvidenceResolver(core, scope, max_source_lines=500)
    late, outside, checked = 0, 0, 0
    cursor = None
    for _ in range(20):
        page = index.query(family="finding-package", limit=100, cursor=cursor)
        assert not any("shard resolution failed" in gap for gap in page["coverage_gaps"])
        for wrapped in page["results"]:
            package = wrapped["record"]
            rule = procedure_for(package["control"])
            if rule is None or rule.evidence_mode != "static_source":
                continue
            component = package["component"]["component_id"]
            resolved = {}
            for item in package["evidence_references"]:
                if item.get("category") != "source" or not item.get("source_subject"):
                    continue
                original = resolver.resolve(item["reference"], component_id=component)
                assert original["source_subject"] == item["source_subject"]
                assert not original["truncated"], "a clipped source was delivered as a complete subject"
                assert original["excerpt"] == item["excerpt"]
                resolved[item["evidence_id"]] = original
                late += int(original["reference"]["locator"]["lines"][0] > 120)
                outside += int(original["source_subject"]["outside_lines"] > 0)
                if original["source_subject"]["outside_lines"]:
                    assert any(not item.get("supported") and "outside subject" in item.get("reason", "")
                               for item in package["proof_obligations"])
                checked += 1
            for obligation in package["proof_obligations"]:
                if obligation.get("supported"):
                    assert obligation["evidence_ids"], "supported obligation has no original evidence"
                    assert any(obligation["subject_id"] in subjects(rule, resolved[identity])
                               for identity in obligation["evidence_ids"] if identity in resolved)
                else:
                    assert obligation["required_outcome"] == "cannot_verify"
        cursor = page["pagination"]["next_cursor"]
        if not cursor:
            break
    assert not cursor, "manual fixture exceeds the explicit 2000-package acceptance budget"
    assert checked and late and outside, "fixture lacks complete late subjects with scoped omissions"
    scope.verify()
