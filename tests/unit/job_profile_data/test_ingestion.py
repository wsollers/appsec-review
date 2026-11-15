"""job_profile_data: format detection, bounds, hotness ranking, origin, and custody enforcement."""

from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.jobs.job_profile_data import (
    ProfileBounds,
    ProfileIntegrityError,
    detect_profile_format,
    ingest_profile_artifacts,
)
from appsec_review.storage import file_sha256


def _artifact(
    run_root: Path,
    relative: str,
    data: bytes,
    *,
    origin: str = "build-output",
    profile_format: str | None = None,
    kind: str = "execution-profile",
) -> dict[str, object]:
    path = run_root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    value: dict[str, object] = {
        "path": relative,
        "workspace_path": Path(relative).name,
        "sha256": file_sha256(path),
        "size_bytes": len(data),
        "kind": kind,
        "artifact_origin": origin,
    }
    if profile_format:
        value["profile_format"] = profile_format
    return value


def test_profile_bounds_validate_positive_limits_and_mapping_overrides() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        ProfileBounds(max_artifacts=0)
    mapped = ProfileBounds.from_mapping({"max_artifacts": "4", "ignored": 99})
    assert mapped.max_artifacts == 4
    assert mapped.max_frames_per_sample == 256


@pytest.mark.parametrize(("name", "data", "declared", "expected_fmt", "expected_gap"), [
    ("any.txt", b"x", "folded-stacks", "folded-stacks", None),
    ("any.bin", b"x", "pprof", None, "requires a pinned converter"),
    ("any.txt", b"x", "custom-fmt", None, "unsupported_profile_format: any.txt: custom-fmt"),
    ("gmon.out", b"opaque", None, None, "opaque gmon"),
    ("sample.gmon", b"opaque", None, None, "opaque gmon"),
    ("cpu.pprof", b"opaque", None, None, "opaque pprof"),
    ("trace.pb.gz", b"opaque", None, None, "opaque pprof"),
    ("default.profraw", b"opaque", None, None, "opaque LLVM raw"),
    ("merged.profdata", b"opaque", None, None, "opaque LLVM indexed"),
    ("raw.bin", b"\xff\xfe", None, None, "unrecognized opaque profile"),
    ("notes.txt", b"events: Ir\nfn=f\n1 2\n", None, "callgrind", None),
    ("notes.txt", b"main;hot 5\n", None, "folded-stacks", None),
    ("notes.txt", b"worker 10 1.2: cycles:\n  7f hot\n", None, "perf-script", None),
    ("notes.txt", b"ns::hot:12:1\n", None, "llvm-sample", None),
    ("sample.perf.txt", b"# comment\n", None, "perf-script", None),
    ("sample.prof", b"# comment\n", None, "llvm-sample", None),
    ("callgrind.folded", b"main;hot 5\n", None, None, "ambiguous_profile_format"),
    ("notes.txt", b"plain prose without profile syntax\n", None, None, "unrecognized text profile"),
])
def test_detect_profile_format_handles_declared_opaque_text_and_ambiguous_inputs(
    name: str,
    data: bytes,
    declared: str | None,
    expected_fmt: str | None,
    expected_gap: str | None,
) -> None:
    fmt, gap = detect_profile_format(name, data, declared)
    assert fmt == expected_fmt
    if expected_gap is None:
        assert gap is None
    else:
        assert gap is not None and expected_gap in gap


def test_ingestion_ranks_rows_and_preserves_report_identity_origin_and_semantics(tmp_path: Path) -> None:
    folded = _artifact(
        tmp_path,
        "data/build/u/profile/app.folded",
        b"root;hot 30\nroot;cold 2\n",
        origin="accepted-input",
    )
    callgrind = _artifact(tmp_path, "data/build/u/profile/callgrind.out", b"events: Ir\nfn=middle\n1 10\n")
    ignored = _artifact(tmp_path, "data/build/u/bin/app", b"\x7fELF", kind="executable")
    output = ingest_profile_artifacts(
        tmp_path,
        [
            {
                "build_unit_id": "u",
                "family": "native",
                "root": ".",
                "terminal_status": "SUCCEEDED",
                "artifacts": [folded, callgrind, ignored],
            }
        ],
    )
    unit = output["units"][0]
    assert unit["coverage_state"] == "complete"
    assert unit["gaps"] == []
    ranked = sorted(unit["rows"], key=lambda row: row["hotness_rank"])
    assert [(row["symbol"], row["count"]) for row in ranked] == [
        ("root", 32),
        ("hot", 30),
        ("middle", 10),
        ("cold", 2),
    ]
    assert ranked[0]["semantics"] == "context_only"
    assert ranked[0]["is_finding"] is False and ranked[0]["defect_probability"] is None
    hot = next(row for row in ranked if row["symbol"] == "hot")
    assert hot["report_sha256"] == folded["sha256"]
    assert hot["report_format"] == "folded-stacks" and hot["artifact_origin"] == "accepted-input"


def test_ingestion_records_absent_duplicate_byte_bound_unsupported_malformed_and_truncated_gaps(
    tmp_path: Path,
) -> None:
    many_frames = _artifact(
        tmp_path,
        "data/build/u/a-frames.folded",
        b"f1;f2;f3 5\n",
        profile_format="folded-stacks",
    )
    opaque = _artifact(tmp_path, "data/build/u/b-gmon.out", b"opaque")
    malformed = _artifact(tmp_path, "data/build/u/c-bad.folded", b"no-count\n")
    too_big = _artifact(tmp_path, "data/build/u/d-big.folded", b"a 1\n" * 30)
    extra_truncated = _artifact(tmp_path, "data/build/u/z-extra.folded", b"x 1\n")

    output = ingest_profile_artifacts(
        tmp_path,
        [
            {
                "build_unit_id": "u",
                "family": "native",
                "artifacts": [many_frames, dict(many_frames), opaque, malformed, too_big, extra_truncated],
            },
            {"build_unit_id": "empty", "family": "java", "artifacts": []},
        ],
        bounds=ProfileBounds(max_artifacts=5, max_artifact_bytes=40, max_rows_per_artifact=2),
    )
    by_unit = {item["build_unit_id"]: item for item in output["units"]}
    assert by_unit["u"]["coverage_state"] == "partial"
    assert len(by_unit["u"]["rows"]) == 2
    assert by_unit["empty"]["coverage_state"] == "unavailable"
    gaps = "\n".join(output["gaps"])
    for expected in (
        "artifact_count_truncation",
        "ambiguous_profile_identity",
        "profile_row_truncation",
        "unsupported_profile_format",
        "malformed_profile",
        "artifact_byte_bound",
        "missing_profile_data",
    ):
        assert expected in gaps


def test_ingestion_enforces_origin_and_safe_file_custody(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    valid = _artifact(run_root, "data/build/u/a.folded", b"a 1\n")

    with pytest.raises(ProfileIntegrityError, match="invalid artifact origin"):
        ingest_profile_artifacts(
            run_root,
            [{"build_unit_id": "u", "artifacts": [{**valid, "artifact_origin": "unknown"}]}],
        )

    with pytest.raises(ProfileIntegrityError, match="identity changed"):
        ingest_profile_artifacts(
            run_root,
            [{"build_unit_id": "u", "artifacts": [{**valid, "sha256": "0" * 64}]}],
        )

    outside = tmp_path / "outside.folded"
    outside.write_bytes(b"a 1\n")
    with pytest.raises(ProfileIntegrityError, match="outside the run"):
        ingest_profile_artifacts(
            run_root,
            [
                {
                    "build_unit_id": "u",
                    "artifacts": [
                        {
                            "path": "../outside.folded",
                            "sha256": file_sha256(outside),
                            "kind": "execution-profile",
                        }
                    ],
                }
            ],
        )

    link = run_root / "data/build/u/link.folded"
    link.symlink_to(outside)
    with pytest.raises(ProfileIntegrityError, match="symlink"):
        ingest_profile_artifacts(
            run_root,
            [
                {
                    "build_unit_id": "u",
                    "artifacts": [
                        {
                            "path": "data/build/u/link.folded",
                            "sha256": file_sha256(outside),
                            "kind": "execution-profile",
                        }
                    ],
                }
            ],
        )
