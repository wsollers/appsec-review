"""Direct selection, byte parsing, verification, deduplication and diagnostic bounds."""

from copy import deepcopy

import pytest

from appsec_review.jobs.job_image_pin_verification.pins import (
    PASSING, configured_pins, describe, inspect_image, verify_pins,
)
from tests.unit.job_image_pin_verification.support import PIN_A, PIN_B, pin


def test_configured_pins_filter_catalog_and_sort_enabled_jobs_without_mutating_inputs():
    catalog = [
        {"id": "pinned", "state": "enabled", "tag": "fixture/pinned", "image_id": PIN_A},
        {"id": "unpinned", "state": "enabled", "tag": "fixture/unpinned", "image_id": 123},
        {"id": "no-id", "state": "enabled", "tag": "fixture/no-id"},
        {"id": "retired", "state": "retired", "tag": "fixture/retired"},
        {"id": "bad-tag", "state": "enabled", "tag": 7},
        {"id": "manual", "state": "enabled", "tag": "fixture/manual", "manual": True},
    ]
    document = {"jobs": {
        "job_z": {"settings": {"profiles": {"native": {"tag": "fixture/build", "image_id": PIN_B}}}},
        "job_a": {"settings": {"source_image_tag": "fixture/source", "source_image_id": PIN_A}},
        "job_disabled": {"settings": {"enabled": False, "tag": "fixture/off", "image_id": PIN_A}},
        "job_missing_id": {"settings": {"tag": "fixture/missing"}},
        "job_wrong_id": {"settings": {"tag": "fixture/wrong", "image_id": 7}},
        "job_non_mapping": [],
    }}
    before = deepcopy((catalog, document))
    assert configured_pins(catalog, document) == [
        pin("containers/catalog.toml images.pinned.image_id", "fixture/pinned"),
        pin("containers/catalog.toml images.unpinned.image_id", "fixture/unpinned", None),
        pin("containers/catalog.toml images.no-id.image_id", "fixture/no-id", None),
        pin("jobs.job_a.settings.source_image_id", "fixture/source"),
        pin("jobs.job_z.settings.profiles.native.image_id", "fixture/build", PIN_B),
    ]
    assert (catalog, document) == before


def test_configured_pins_include_step_list_and_image_tag_pairs_but_not_preinstalled_runtime_ids():
    document = {"jobs": {"job_scan": {
        "settings": {"image_tag": "fixture/image-tag", "image_id": PIN_B,
                     "preinstalled_runtimes": [{"source_image_tag": "ignored", "source_image_id": PIN_A}]},
        "steps": {"scan": {"settings": {"tools": [{"tag": "fixture/list", "image_id": PIN_A}]}}},
    }}}
    assert configured_pins([], document) == [
        pin("jobs.job_scan.settings.image_id", "fixture/image-tag", PIN_B),
        pin("jobs.job_scan.steps.scan.settings.tools[0].image_id", "fixture/list"),
    ]


@pytest.mark.parametrize(
    ("enabled", "render_pdf", "selected"),
    [(False, False, False), (False, True, False), (True, False, False),
     (True, True, True), (1, True, False), (True, 1, False)],
    ids=["off", "disabled", "no-pdf", "pdf", "enabled-not-bool", "pdf-not-bool"],
)
def test_telemetry_image_requires_both_literal_switches(enabled, render_pdf, selected):
    document = {"reporting": {"telemetry_report": {
        "enabled": enabled, "render_pdf": render_pdf, "image_tag": "fixture/latex", "image_id": PIN_B,
    }}}
    expected = [pin("reporting.telemetry_report.image_id", "fixture/latex", PIN_B)] if selected else []
    assert configured_pins([], document) == expected


@pytest.mark.parametrize("document", [{}, {"jobs": None}, {"jobs": {}}], ids=["absent", "null", "empty"])
def test_empty_selection_remains_empty(document):
    assert configured_pins([], document) == []


@pytest.mark.parametrize(
    ("code", "stdout", "stderr", "timed_out", "state", "resolved", "detail"),
    [
        (0, (f" \n{PIN_A}\n ").encode(), b"", False, "present", PIN_A, ""),
        (0, PIN_A.encode(), b"No such image: warning", False, "present", PIN_A, ""),
        (0, PIN_A.encode(), b"", True, "inspect_failed", None, "docker image inspect timed out after 60s"),
        (1, b"", b"Error: No such image: absent\n", False, "missing", None, "Error: No such image: absent"),
        (1, b"", b"NO SUCH OBJECT: absent", False, "missing", None, "NO SUCH OBJECT: absent"),
        (1, PIN_A.encode(), b"daemon unavailable", False, "inspect_failed", None,
         "docker image inspect exited 1: daemon unavailable"),
        (0, b"", b"", False, "inspect_failed", None, "docker image inspect exited 0: "),
        (0, b"sha256:abc", b"", False, "inspect_failed", None, "docker image inspect exited 0: sha256:abc"),
        (0, ("sha256:" + "A" * 64).encode(), b"", False, "inspect_failed", None,
         "docker image inspect exited 0: sha256:" + "A" * 64),
        (0, (PIN_A + "0").encode(), b"", False, "inspect_failed", None,
         "docker image inspect exited 0: " + PIN_A + "0"),
        (0, (PIN_A + "\n" + PIN_B).encode(), b"", False, "inspect_failed", None,
         "docker image inspect exited 0: " + PIN_A + "\n" + PIN_B),
        (0, b"No such image: absent", b"", False, "inspect_failed", None,
         "docker image inspect exited 0: No such image: absent"),
        (0, b"", b"No such object: absent", False, "inspect_failed", None,
         "docker image inspect exited 0: No such object: absent"),
        (1, b"No such object: absent", b"", False, "inspect_failed", None,
         "docker image inspect exited 1: No such object: absent"),
        (2, b" \xff\n", b"", False, "inspect_failed", None, "docker image inspect exited 2: \ufffd"),
        (2, b"ignored", b" \xfe\n", False, "inspect_failed", None, "docker image inspect exited 2: \ufffd"),
    ],
    ids=["trim", "success-stderr", "timeout-wins", "missing-image", "missing-object", "nonzero",
         "empty", "short-id", "uppercase-id", "long-id", "multiple-ids", "zero-absent-out",
         "zero-absent-err", "nonzero-absent-out", "invalid-stdout", "invalid-stderr"],
)
def test_inspect_parses_only_one_exact_image_id_and_classifies_failures(
        code, stdout, stderr, timed_out, state, resolved, detail):
    calls = []

    def runner(argv, timeout):
        calls.append((argv, timeout))
        return code, stdout, stderr, timed_out

    assert inspect_image(runner, "fixture/name:1") == {
        "resolved_image_id": resolved, "state": state, "detail": detail,
    }
    assert calls == [(("docker", "image", "inspect", "fixture/name:1", "--format", "{{.Id}}"), 60)]


@pytest.mark.parametrize("kind", ["missing", "stderr", "stdout"], ids=str)
def test_inspect_bounds_diagnostic_tail_to_512_characters(kind):
    text = ("No such image: " if kind == "missing" else "") + "prefix-" + "x" * 512
    code = 1 if kind == "missing" else 2
    stdout = text.encode() if kind == "stdout" else b"ignored"
    stderr = b"" if kind == "stdout" else text.encode()
    result = inspect_image(lambda argv, timeout: (code, stdout, stderr, False), "fixture/tool")
    assert result == {
        "state": "missing" if kind == "missing" else "inspect_failed", "resolved_image_id": None,
        "detail": ("docker image inspect exited 2: " if kind != "missing" else "") + "x" * 512,
    }


@pytest.mark.parametrize("error", [FileNotFoundError("docker missing"), PermissionError("denied")],
                         ids=["missing-executable", "permission"])
def test_inspect_converts_os_errors_to_named_inspection_failures(error):
    def runner(argv, timeout):
        raise error

    assert inspect_image(runner, "fixture/tool") == {
        "state": "inspect_failed", "resolved_image_id": None, "detail": f"{type(error).__name__}: {error}",
    }


def test_verify_deduplicates_by_tag_preserves_source_order_and_each_expected_binding():
    pins = [
        pin("matched"), pin("unpinned", image_id=None), pin("moved", image_id=PIN_B),
        pin("missing", tag="fixture/absent"), pin("missing-again", tag="fixture/absent"),
        pin("failed", tag="fixture/failed"), {"source": "coerced", "tag": 9},
    ]
    before = deepcopy(pins)
    calls = []

    def runner(argv, timeout):
        tag = argv[3]
        calls.append((tag, timeout))
        if tag == "fixture/absent":
            return 1, b"", b"No such image: fixture/absent", False
        if tag == "fixture/failed":
            return 2, b"", b"daemon unavailable", False
        return 0, PIN_A.encode(), b"", False

    results = verify_pins(pins, runner)
    statuses = ("matched", "present", "mismatched", "missing", "missing", "inspect_failed", "present")
    expected = []
    for row, status in zip(pins, statuses, strict=True):
        expected.append({
            "source": row["source"], "tag": str(row["tag"]), "image_id": row.get("image_id"),
            "resolved_image_id": None if status in {"missing", "inspect_failed"} else PIN_A,
            "status": status,
            "detail": ("No such image: fixture/absent" if status == "missing" else
                       "docker image inspect exited 2: daemon unavailable" if status == "inspect_failed" else ""),
        })
    assert results == expected
    assert calls == [("fixture/tool:1", 60), ("fixture/absent", 60), ("fixture/failed", 60), ("9", 60)]
    assert pins == before and PASSING == {"matched", "present"}


def test_verify_empty_does_not_inspect_and_each_call_gets_a_fresh_cache():
    calls = []

    def runner(argv, timeout):
        calls.append(argv[3])
        return 0, (PIN_A if len(calls) == 1 else PIN_B).encode(), b"", False

    assert verify_pins([], runner) == [] and calls == []
    assert verify_pins([pin()], runner)[0]["status"] == "matched"
    assert verify_pins([pin()], runner)[0]["status"] == "mismatched"
    assert calls == ["fixture/tool:1", "fixture/tool:1"]


@pytest.mark.parametrize(
    ("status", "image_id", "resolved", "detail", "description"),
    [
        ("matched", PIN_A, PIN_A, "", PIN_A),
        ("mismatched", PIN_A, PIN_B, "", PIN_B),
        ("present", None, PIN_A, "", PIN_A),
        ("missing", PIN_A, None, "No such image", "missing"),
        ("inspect_failed", PIN_A, None, "daemon down", "not inspectable (daemon down)"),
    ],
    ids=["matched", "mismatched", "present", "missing", "inspect-failed"],
)
def test_describe_names_source_tag_expected_and_actual_resolution(status, image_id, resolved, detail, description):
    result = {**pin("jobs.job_build.settings.image_id", image_id=image_id),
              "status": status, "resolved_image_id": resolved, "detail": detail}
    assert describe(result) == (
        f"jobs.job_build.settings.image_id: tag fixture/tool:1 pinned {image_id or '<unpinned>'} "
        f"resolved {description}")
