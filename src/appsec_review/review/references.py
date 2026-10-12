"""Run-pinned reference feeds for the inference review: the MITRE CWE catalog.

``job_review_data_indexing`` pins each global feed snapshot for the run (``feed_pins``) and records
the pins in its hash-bound ``load.accepted_inputs`` artifact. The review reads that artifact through
the accepted index-set pointer, re-hashes the pinned ``index/mitre.sqlite`` against the pin and
opens it read-only and immutable (the ``_feed_database`` pattern). A pin that is missing,
mismatched or stale is a named gap: claim CWE validation then falls back to the narrower set of
CWE ids named by accepted lead rules and the security-tagging crosswalk, and the gap is recorded
in the run's ledger. The fallback is never silent.

Reference records classify claims and give workers context; they are never finding evidence.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import json
from pathlib import Path
import sqlite3
from typing import Any

from appsec_review.review.claims import normalize_cwe
from appsec_review.storage import file_sha256

INDEXING_JOB = "job_review_data_indexing"
INPUTS_UNIT = "load.accepted_inputs"
MITRE_INDEX = "index/mitre.sqlite"
REFERENCE_RULE = "appsec-review/cwe-reference/1"


@dataclass(frozen=True, slots=True)
class CweEntry:
    cwe_id: str
    name: str | None
    abstraction: str | None


@dataclass(frozen=True, slots=True)
class CweReference:
    """The CWE identities claim validation accepts, with their source and any gap."""

    source: str                               # "mitre_catalog" | "fallback"
    entries: Mapping[str, CweEntry] = field(default_factory=dict)
    snapshot_id: str | None = None
    manifest_sha256: str | None = None
    version: str | None = None
    gap: str | None = None
    fallback_ids: frozenset[str] = frozenset()

    @property
    def accepted_ids(self) -> frozenset[str]:
        return frozenset(self.entries) if self.source == "mitre_catalog" else self.fallback_ids

    def lookup(self, cwe_id: str) -> CweEntry | None:
        return self.entries.get(cwe_id)

    def record(self) -> dict[str, Any]:
        return {"rule": REFERENCE_RULE, "source": self.source, "snapshot_id": self.snapshot_id,
                "manifest_sha256": self.manifest_sha256, "version": self.version, "gap": self.gap,
                "accepted_count": len(self.accepted_ids)}

    def with_fallback(self, fallback_ids: frozenset[str]) -> "CweReference":
        return CweReference(self.source, self.entries, self.snapshot_id, self.manifest_sha256, self.version,
                            self.gap, frozenset(item for item in (normalize_cwe(value) for value in fallback_ids)
                                                if item))


def _unavailable(reason: str, catalog: Mapping[str, CweEntry] | None = None, **identity: Any) -> CweReference:
    return CweReference("fallback", dict(catalog or {}), gap=reason[:400], **identity)


def accepted_feed_pins(run_root: Path) -> tuple[Mapping[str, Any] | None, str | None]:
    """The run's feed pins from the accepted indexing handoff, or ``(None, reason)``."""
    from appsec_review.retrieval.core import resolve_accepted_manifest
    run_root = Path(run_root).resolve()
    try:
        resolve_accepted_manifest(run_root)       # verifies the pointer and the handoff hash
        pointer = json.loads((run_root / "data" / "indices" / "accepted.json").read_text(encoding="utf-8"))
        handoff_path = (run_root / str(pointer["handoff_path"])).resolve()
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    except Exception as exc:  # an unreadable pointer is reported, never treated as clean
        return None, f"accepted index pointer is unavailable ({type(exc).__name__})"
    if handoff.get("job_id") != INDEXING_JOB:
        return None, f"the accepted index set was not published by {INDEXING_JOB}; no feed pins are bound"
    reference = ((handoff.get("outputs") or {}).get(INPUTS_UNIT) or {}).get("artifact")
    if not isinstance(reference, Mapping) or not isinstance(reference.get("path"), str):
        return None, f"the accepted {INDEXING_JOB} handoff records no {INPUTS_UNIT} artifact with feed pins"
    path = (run_root / reference["path"]).resolve()
    if run_root not in path.parents or not path.is_file() or file_sha256(path) != reference.get("sha256"):
        return None, f"{INDEXING_JOB} {INPUTS_UNIT} artifact identity mismatch"
    document = json.loads(path.read_text(encoding="utf-8"))
    feeds = document.get("feeds")
    if not isinstance(feeds, Mapping):
        return None, f"{INDEXING_JOB} {INPUTS_UNIT} artifact pins no reference feeds"
    return feeds, None


def load_cwe_reference(run_root: Path) -> CweReference:
    """Load the run-pinned MITRE CWE catalog; any defect yields a ``fallback`` reference with a gap."""
    feeds, reason = accepted_feed_pins(run_root)
    if feeds is None:
        return _unavailable(f"mitre_feed_unavailable: {reason}")
    pin = feeds.get("mitre") or {}
    if pin.get("status") != "pinned":
        return _unavailable(f"mitre_feed_unavailable: {pin.get('reason') or 'no pinned MITRE snapshot'}")
    identity = {"snapshot_id": pin.get("snapshot_id"), "manifest_sha256": pin.get("manifest_sha256")}
    path = Path(str(pin.get("directory", ""))) / MITRE_INDEX
    expected = (pin.get("files") or {}).get(MITRE_INDEX)
    if not path.is_file() or expected is None or file_sha256(path) != expected:
        return _unavailable(f"mitre_identity_mismatch: pinned {MITRE_INDEX} does not match its pinned hash",
                            **identity)
    entries: dict[str, CweEntry] = {}
    version = None
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    try:
        for external_id, name, raw in connection.execute(
                "SELECT external_id, name, raw_json FROM entry WHERE object_type = 'weakness' ORDER BY external_id"):
            cwe = normalize_cwe(str(external_id))
            if cwe is None:
                continue
            try:
                attributes = json.loads(raw) if isinstance(raw, str) else {}
            except ValueError:
                attributes = {}
            abstraction = attributes.get("abstraction") if isinstance(attributes, Mapping) else None
            entries[cwe] = CweEntry(cwe, str(name)[:256] if name else None,
                                    str(abstraction)[:64] if isinstance(abstraction, str) else None)
    except sqlite3.Error as exc:
        return _unavailable(f"mitre_identity_mismatch: pinned catalog is unreadable ({type(exc).__name__})",
                            **identity)
    finally:
        connection.close()
    manifest_path = Path(str(pin["directory"])) / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        version = str(((manifest.get("sources") or {}).get("cwe") or {}).get("version") or "") or None
    except (OSError, ValueError):
        version = None
    if not entries:
        return _unavailable("mitre_identity_mismatch: the pinned MITRE snapshot holds no CWE weakness", **identity,
                            version=version)
    if pin.get("stale"):
        # A stale catalog still names real weaknesses, so it continues to supply names and
        # abstractions; claim validation nevertheless falls back with the gap recorded.
        return _unavailable("mitre_stale_feed: the pinned MITRE CWE catalog is older than the configured "
                            "freshness bound", entries, **identity, version=version)
    return CweReference("mitre_catalog", entries, version=version, **identity)
