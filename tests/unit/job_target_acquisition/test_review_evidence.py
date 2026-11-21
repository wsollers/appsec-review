"""Offline acquisition regressions; only Git and provider I/O are replaced."""

from copy import deepcopy
import hashlib
import json
import subprocess

import pytest

from appsec_review.jobs.job_change_context_analysis.sources import review_records_from_export
from appsec_review.interchange import validate_unit_output
from appsec_review.runtime.execution_safety import ReviewStopped
from appsec_review.target_acquisition import acquire, git_source, review_exports
from appsec_review.target_acquisition.safety import AcquisitionError

from .support import ACQUISITION, PUBLICATION, SELECTION, artifact_document, handler, unit_context


OLD, CURRENT, BASE = "a" * 40, "b" * 40, "c" * 40
TREE = "d" * 40
DATE = "2024-01-02T03:04:05Z"


def responses_for(provider):
    if provider == "gerrit":
        return {"change": {
            "_number": 31, "current_revision": CURRENT, "status": "MERGED",
            "created": "2024-01-02 03:00:00", "submitted": "2024-01-02 04:00:00",
            "owner": {"_account_id": 100}, "submitter": {"_account_id": 200},
            "labels": {"Code-Review": {"values": {"+2": "approved"}, "all": [
                {"_account_id": 200, "value": 2, "date": "2024-01-02 03:30:00"}]}},
            "revisions": {revision: {"_number": index, "commit": {
                "parents": [{"commit": BASE}], "committer": {"date": "2024-01-02 03:04:05"}}}
                for index, revision in enumerate((OLD, CURRENT), 1)},
        }}
    commits = {"items": [], "truncated": False}
    if provider == "gitlab":
        commits["items"] = [{"id": rev, "committed_date": DATE} for rev in (OLD, CURRENT)]
        return {"merge_request": {
            "iid": 31, "sha": CURRENT, "state": "merged", "created_at": DATE,
            "merged_at": DATE, "author": {"id": 100}, "merge_user": {"id": 200},
            "diff_refs": {"base_sha": BASE}},
            "approvals": {"approved_by": []}, "commits": commits}
    commits["items"] = [{"commitId": rev, "committer": {"date": DATE}} for rev in (OLD, CURRENT)]
    return {"pull_request": {
        "pullRequestId": 31, "status": "completed", "creationDate": DATE, "closedDate": DATE,
        "createdBy": {"id": "author"}, "closedBy": {"id": "reviewer"}, "reviewers": []},
        "iteration": {"id": 2, "sourceRefCommit": {"commitId": CURRENT},
                      "commonRefCommit": {"commitId": BASE}}, "commits": commits}


def normalize(provider, responses, *, revision=CURRENT, limit=2):
    return review_exports.normalize(
        provider, responses, change=31, revision=revision,
        patchset=1 if revision == OLD else 2, iteration=2, max_commits=limit)


@pytest.mark.parametrize("provider", ["gerrit", "gitlab", "azure_devops"], ids=["gerrit", "gitlab", "ado"])
def test_normalized_cap_preserves_pin_without_mutating_evidence(provider):
    responses = responses_for(provider)
    original = deepcopy(responses)
    metadata = normalize(provider, responses, limit=1)
    assert list(metadata.records) == [CURRENT]
    assert metadata.head == CURRENT and metadata.base == BASE
    assert [g["reason"] for g in metadata.gaps].count("review_commits_truncated") == 1
    assert responses == original
    if provider == "gerrit":
        responses["change"]["revisions"] = dict(reversed(list(responses["change"]["revisions"].items())))
    else:
        responses["commits"]["items"].reverse()
    assert normalize(provider, responses, limit=1) == metadata


@pytest.mark.parametrize("current", [CURRENT, None, "invalid"], ids=["superseded", "missing", "malformed"])
def test_gerrit_historical_facts_are_unknown_not_current_approval(current):
    responses = responses_for("gerrit")
    if current is None:
        responses["change"].pop("current_revision")
    else:
        responses["change"]["current_revision"] = current
    metadata = normalize("gerrit", responses, revision=OLD)
    assert metadata.state == "unknown"
    assert metadata.fetch_ref == "refs/changes/31/31/1"
    raw = metadata.records[OLD]
    assert raw["head_sha"] == OLD and raw["head_committed_at"] == DATE
    assert raw["approvals"] is None and raw["merged_at"] is None and raw["self_merged"] is None
    assert metadata.records[CURRENT]["head_sha"] == CURRENT
    records, problems = review_records_from_export(review_exports.review_records_document(metadata))
    assert not problems and records[OLD]["approved_by_other"] is None
    assert not records[OLD]["complete"]
    reasons = {g["reason"] for g in metadata.gaps}
    expected = "review_revision_state_unavailable" if current == CURRENT else "review_current_revision_unavailable"
    assert expected in reasons
    assert "review_not_merged" not in reasons
    if current == CURRENT:
        assert records[CURRENT]["approved_by_other"] is True
        assert records[CURRENT]["merged_at"] is not None
    else:
        assert records[CURRENT]["approved_by_other"] is None


def test_gerrit_current_pin_does_not_fan_facts_over_old_patchset():
    metadata = normalize("gerrit", responses_for("gerrit"))
    assert metadata.state == "merged"
    assert metadata.records[CURRENT]["approvals"]
    assert metadata.records[CURRENT]["merged_at"] is not None
    assert metadata.records[OLD]["approvals"] is None
    assert metadata.records[OLD]["merged_at"] is None
    assert metadata.records[OLD]["head_sha"] == OLD
    assert "review_revision_state_unavailable" in {g["reason"] for g in metadata.gaps}
    assert "review_commits_truncated" not in {g["reason"] for g in metadata.gaps}


def test_historical_pin_is_retained_when_current_patchset_exceeds_cap():
    metadata = normalize("gerrit", responses_for("gerrit"), revision=OLD, limit=1)
    assert list(metadata.records) == [OLD]
    assert metadata.head == OLD and metadata.state == "unknown"
    assert metadata.records[OLD]["approvals"] is None
    assert {g["reason"] for g in metadata.gaps} >= {
        "review_commits_truncated", "review_revision_state_unavailable", "review_approvals_unavailable"}


@pytest.mark.parametrize("provider", ["gitlab", "azure_devops"], ids=["gitlab", "ado"])
def test_upstream_truncation_is_preserved_even_when_records_fit(provider):
    responses = responses_for(provider)
    responses["commits"]["truncated"] = True
    metadata = normalize(provider, responses, limit=2)
    assert len(metadata.records) == 2
    assert [g["reason"] for g in metadata.gaps].count("review_commits_truncated") == 1


@pytest.mark.parametrize("provider", ["gitlab", "azure_devops"], ids=["gitlab", "ado"])
def test_missing_head_is_not_fabricated_by_cap(provider):
    responses = responses_for(provider)
    responses["commits"]["items"] = responses["commits"]["items"][:1]
    metadata = normalize(provider, responses, limit=1)
    assert list(metadata.records) == [OLD]
    assert "review_head_not_in_commit_list" in {g["reason"] for g in metadata.gaps}


class FixtureGit:
    """External Git boundary: fixed inert bytes and explicit command outcomes."""

    mode = "ok"

    def __init__(self, *args, **kwargs):
        self.calls = []

    def fetch_pinned(self, repo, url, commit, refs=(), extra_commits=()):
        assert url == "https://example.invalid/repo.git"
        assert commit in (OLD, CURRENT) and extra_commits == (BASE,)
        assert len(refs) == 1 and refs[0].startswith("refs/")
        repo.mkdir()
        (repo / "source.txt").write_bytes(b"fixed inert source\n")

    def checkout(self, repo, commit):
        assert commit in (OLD, CURRENT) and (repo / "source.txt").is_file()
        return TREE

    def version(self):
        return "git unit-fixture"

    def index_entries(self, repo):
        return [("100644", "e" * 40, "source.txt")]

    def has_commit(self, repo, commit):
        assert commit == BASE
        return self.mode != "missing-base"

    def __call__(self, *args, **kwargs):
        assert args[0] == "diff" and args[-3] == BASE and args[-2] in (OLD, CURRENT) and args[-1] == "--"
        self.calls.append((args, kwargs))
        names = "--name-status" in args
        if names and isinstance(self.mode, BaseException):
            raise self.mode
        if self.mode == "empty":
            return subprocess.CompletedProcess(args, 0, b"", b"")
        failed = (names and self.mode == "names-failed") or (not names and self.mode == "patch-failed")
        result = subprocess.CompletedProcess(args, 1 if failed else 0,
            b"M\0source.txt\0" if names else b"fixture patch\n", b"fixture optional diff I/O failure")
        if failed and kwargs.get("check", True):
            raise AcquisitionError("fixture diff exited 1")
        return result


@pytest.mark.parametrize("mode", ["names-failed", "patch-failed", "missing-base", "ok", "empty"],
                         ids=["names-failed", "patch-failed", "missing-base", "complete", "empty-success"])
def test_diff_failure_is_not_an_empty_success(mode, tmp_path):
    git = FixtureGit()
    git.mode = mode
    patch, changed, gaps = git_source.change_diff(git, tmp_path, BASE, CURRENT, 1024)
    if mode in ("names-failed", "missing-base"):
        assert patch is None and changed is None
        assert gaps[0]["reason"] == ("change_base_unavailable" if mode == "missing-base" else "change_diff_failed")
        assert len(git.calls) == (0 if mode == "missing-base" else 1)
    elif mode == "empty":
        assert patch == b"" and changed == [] and gaps == []
    else:
        assert changed == [{"status": "M", "score": None, "paths": ["source.txt"]}]
        assert patch == (None if mode == "patch-failed" else b"fixture patch\n")
        assert [g["reason"] for g in gaps] == (["change_diff_failed"] if mode == "patch-failed" else [])


@pytest.mark.parametrize("error", [
    ReviewStopped("global admission stopped"),
    KeyboardInterrupt(),
    AcquisitionError("integrity refusal", status="REFUSED"),
    AcquisitionError("unclassified failure"),
], ids=["review-stop", "interrupt", "refusal", "unclassified"])
def test_diff_does_not_demote_stop_or_integrity_errors(error, tmp_path):
    git = FixtureGit()
    git.mode = error
    with pytest.raises(type(error)) as raised:
        git_source.change_diff(git, tmp_path, BASE, CURRENT, 1024)
    assert raised.value is error


def _frozen(tmp_path, provider, responses, source):
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(acquire._canonical(review_exports.bundle_document(provider, 31, responses)))
    common = (
        '[target_acquisition]\ntargets_dir = "checkouts"\nrecords_dir = "acquisition-records"\n'
        'max_review_commits = 1\nmax_parallel_components = 1\n'
        '[[target_acquisition.systems]]\nid = "sys"\n'
        '[[target_acquisition.systems.components]]\nid = "review"\nkind = "review_export"\n'
        f'provider = "{provider}"\nsource = "{source}"\nchange = 31\nrevision = "{CURRENT}"\n'
        'clone_url = "https://example.invalid/repo.git"\nproject = "project"\n')
    if provider == "gerrit":
        common += 'patchset = 2\n'
    elif provider == "azure_devops":
        common += 'iteration = 2\nrepository = "repo"\n'
    if source == "bundle":
        return common + f'bundle_path = "bundle.json"\nbundle_sha256 = "{hashlib.sha256(bundle.read_bytes()).hexdigest()}"\n'
    return common + 'api_url = "https://example.invalid"\n'


def _fetcher(responses):
    def factory(**kwargs):
        def fetch(url):
            if "change" in responses:
                return responses["change"]
            if "merge_request" in responses:
                if "/commits?" in url:
                    return responses["commits"]["items"]
                return responses["approvals"] if url.endswith("/approvals") else responses["merge_request"]
            if "/commits?" in url:
                return {"value": responses["commits"]["items"]}
            return responses["iteration"] if "/iterations/" in url else responses["pull_request"]
        return fetch
    return factory


@pytest.mark.parametrize("provider,source", [
    ("gerrit", "api"), ("gerrit", "bundle"), ("gitlab", "bundle"), ("azure_devops", "bundle"),
], ids=["gerrit-api", "gerrit-bundle", "gitlab-bundle", "ado-bundle"])
def test_job_acquires_bounded_records_with_real_manifest_and_receipts(provider, source, tmp_path, monkeypatch):
    responses = responses_for(provider)
    frozen = _frozen(tmp_path, provider, responses, source)
    monkeypatch.setattr(git_source, "Git", FixtureGit)
    kwargs = {"environ": {"APPSEC_REVIEW_SYSTEM": "sys"}, "fetcher_factory": _fetcher(responses)}
    selection, _ = unit_context(tmp_path, SELECTION, frozen=frozen)
    plan = handler(SELECTION, **kwargs)(selection)
    acquisition, _ = unit_context(tmp_path, ACQUISITION, frozen=frozen, outputs={SELECTION: plan})
    result = handler(ACQUISITION, **kwargs)(acquisition)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["status"] == "PARTIAL"
    manifest = artifact_document(acquisition, result["manifest"])
    component = manifest["components"]["review"]
    record_dir = tmp_path / "acquisition-records" / "sys" / "components" / "review"
    component_bytes = (record_dir / "manifest.json").read_bytes()
    assert component["manifest_sha256"] == hashlib.sha256(component_bytes).hexdigest()
    component_manifest = json.loads(component_bytes)
    assert component_manifest["identity"]["revision"] == CURRENT
    assert component_manifest["identity"]["provider"] == provider
    assert component_manifest["identity"]["git"]["commit"] == CURRENT
    assert component_manifest["identity"]["git"]["tree"] == TREE
    records = json.loads((record_dir / "review-records.json").read_bytes())
    assert list(records["records"]) == [CURRENT]
    assert "review_commits_truncated" in {g["reason"] for g in component_manifest["gaps"]}
    for artifact in component_manifest["artifacts"]:
        data = (record_dir / artifact["name"]).read_bytes()
        assert artifact["sha256"] == hashlib.sha256(data).hexdigest()
        assert artifact["size_bytes"] == len(data)
    if source == "bundle":
        assert (record_dir / "review-export-bundle.json").read_bytes() == (tmp_path / "bundle.json").read_bytes()
    validate_unit_output(result, unit_id=ACQUISITION, strict_gaps=True)
    publication, _ = unit_context(tmp_path, PUBLICATION, frozen=frozen, outputs={ACQUISITION: result})
    handoff = handler(PUBLICATION, **kwargs)(publication)
    assert artifact_document(publication, handoff["artifact"])["gaps"] == result["gaps"]
    validate_unit_output(handoff, unit_id=PUBLICATION, strict_gaps=True)
    before = {p: p.read_bytes() for p in record_dir.iterdir()}
    verified = handler(ACQUISITION, **kwargs)(acquisition)
    assert verified["components"]["review"]["action"] == "verified"
    assert verified["manifest"]["sha256"] == result["manifest"]["sha256"]
    assert all(p.read_bytes() == data for p, data in before.items())
    receipt = json.loads((tmp_path / "acquisition-records" / "sys" / "verification.json").read_bytes())
    assert receipt["manifest_sha256"] == result["manifest"]["sha256"]
    assert receipt["components"]["review"]["action"] == "verified"


@pytest.mark.parametrize("mode", ["names-failed", "patch-failed", "missing-base"],
                         ids=["names-failed", "patch-failed", "missing-base"])
def test_qualified_diff_gap_retains_source_but_not_missing_artifacts(mode, tmp_path, monkeypatch):
    frozen = _frozen(tmp_path, "gerrit", responses_for("gerrit"), "bundle")
    monkeypatch.setattr(git_source, "Git", FixtureGit)
    monkeypatch.setattr(FixtureGit, "mode", mode)
    selection, _ = unit_context(tmp_path, SELECTION, frozen=frozen)
    kwargs = {"environ": {"APPSEC_REVIEW_SYSTEM": "sys"}}
    plan = handler(SELECTION, **kwargs)(selection)
    context, _ = unit_context(tmp_path, ACQUISITION, frozen=frozen, outputs={SELECTION: plan})
    result = handler(ACQUISITION, **kwargs)(context)
    assert result["status"] == "PARTIAL"
    assert (tmp_path / "checkouts" / "sys" / "review" / "source.txt").read_bytes() == b"fixed inert source\n"
    records = tmp_path / "acquisition-records" / "sys" / "components" / "review"
    assert not (records / "change.diff").exists()
    assert (records / "changed-paths.json").exists() == (mode == "patch-failed")
    component = json.loads((records / "manifest.json").read_bytes())
    expected = "change_base_unavailable" if mode == "missing-base" else "change_diff_failed"
    assert expected in {g["reason"] for g in component["gaps"]}
    assert component["identity"]["base"] == BASE and component["identity"]["revision"] == CURRENT
    assert artifact_document(context, result["manifest"])["status"] == "PARTIAL"
    validate_unit_output(result, unit_id=ACQUISITION, strict_gaps=True)


def test_historical_acquisition_keeps_exact_pin_and_unknown_review_state(tmp_path, monkeypatch):
    frozen = _frozen(tmp_path, "gerrit", responses_for("gerrit"), "bundle")
    frozen = frozen.replace(f'revision = "{CURRENT}"', f'revision = "{OLD}"').replace("patchset = 2", "patchset = 1")
    monkeypatch.setattr(git_source, "Git", FixtureGit)
    kwargs = {"environ": {"APPSEC_REVIEW_SYSTEM": "sys"}}
    selection, _ = unit_context(tmp_path, SELECTION, frozen=frozen)
    plan = handler(SELECTION, **kwargs)(selection)
    context, _ = unit_context(tmp_path, ACQUISITION, frozen=frozen, outputs={SELECTION: plan})
    result = handler(ACQUISITION, **kwargs)(context)
    assert result["status"] == "PARTIAL"
    records = tmp_path / "acquisition-records" / "sys" / "components" / "review"
    manifest = json.loads((records / "manifest.json").read_bytes())
    identity = manifest["identity"]
    assert identity["revision"] == OLD and identity["git"]["commit"] == OLD
    assert identity["patchset"] == 1 and identity["fetch_ref"] == "refs/changes/31/31/1"
    assert identity["state"] == "unknown"
    assert identity["bundle_sha256"] == hashlib.sha256((records / "review-export-bundle.json").read_bytes()).hexdigest()
    exported, problems = review_records_from_export(json.loads((records / "review-records.json").read_bytes()))
    assert list(exported) == [OLD] and not problems
    assert exported[OLD]["approved_by_other"] is None and exported[OLD]["merged_at"] is None
    assert not exported[OLD]["complete"]
    validate_unit_output(result, unit_id=ACQUISITION, strict_gaps=True)


@pytest.mark.parametrize("failure", ["hash", "pin", "refusal", "review-stop"],
                         ids=["bundle-hash", "revision-pin", "integrity-refusal", "review-stop"])
def test_job_does_not_qualify_untrusted_input_or_global_stop(failure, tmp_path, monkeypatch):
    from appsec_review.jobs.job_target_acquisition.job import TargetAcquisitionFailed

    frozen = _frozen(tmp_path, "gerrit", responses_for("gerrit"), "bundle")
    if failure == "hash":
        (tmp_path / "bundle.json").write_bytes(b"modified after pinning")
    elif failure == "pin":
        frozen = frozen.replace("patchset = 2", "patchset = 3")
    elif failure == "refusal":
        monkeypatch.setattr(FixtureGit, "mode", AcquisitionError("integrity refusal", status="REFUSED"))
    else:
        monkeypatch.setattr(FixtureGit, "mode", ReviewStopped("global admission stopped"))
    monkeypatch.setattr(git_source, "Git", FixtureGit)
    kwargs = {"environ": {"APPSEC_REVIEW_SYSTEM": "sys"}}
    selection, _ = unit_context(tmp_path, SELECTION, frozen=frozen)
    plan = handler(SELECTION, **kwargs)(selection)
    context, _ = unit_context(tmp_path, ACQUISITION, frozen=frozen, outputs={SELECTION: plan})
    with pytest.raises(ReviewStopped if failure == "review-stop" else TargetAcquisitionFailed):
        handler(ACQUISITION, **kwargs)(context)
    assert not (tmp_path / "checkouts" / "sys" / "review").exists()
    assert not (tmp_path / "acquisition-records" / "sys" / "components" / "review" / "manifest.json").exists()
