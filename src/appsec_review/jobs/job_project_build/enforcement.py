"""Post-build native target evidence, derived only from verified execution captures."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from functools import lru_cache
import json
from pathlib import Path, PurePosixPath
import posixpath
import shlex
from typing import Any

from appsec_review.config.build_selection import AXES, parse_build_selection
from appsec_review.container_runtime import VerifiedCapture
from appsec_review.container_runtime.compiler_profiles import merge_profile_sets
from appsec_review.interchange import producer_gap
from appsec_review.jobs.build_topology import ENFORCEMENT_SCHEMA, RULES, _compiler_axes, _digest
from appsec_review.storage import canonical_json, file_sha256
from appsec_review.storage.shared import safe_path


def gap_text(value: Any) -> str:
    return str(value["reason"]) if isinstance(value, Mapping) else str(value)


def unique_gaps(values):
    return list({canonical_json(value): value for value in values}.values())


def scoped_gaps(values, unit_id: str, scope_id: str | None = None):
    return unique_gaps(value if isinstance(value, Mapping) else producer_gap(
        "producer_reported_gap", str(value),
        scope_id=scope_id or (str(value).split(":", 1)[0] if str(value).startswith("build-unit-") else unit_id))
        for value in values)


def _profile_for(executable, records):
    from appsec_review.jobs.job_language_build.capture import image_owned
    for profile in records.values():
        # A recorded symlink chain is image evidence; a basename or profile label is not.
        paths = {profile["executable"], *profile["invocation_paths"],
                 *(hop["path"] for hop in profile["wrapper_closure"])}
        if image_owned(executable) and executable in paths:
            return profile
    return None


def _targets(argv, defaults):
    flags, triples = [], []
    malformed = False
    for index, value in enumerate(argv):
        if value in {"--target", "-target", "-triple"}:
            if index + 1 == len(argv):
                malformed = True
            else:
                flags.append([value, argv[index + 1]])
                triples.append(argv[index + 1])
        elif value.startswith("--target="):
            flags.append([value])
            triples.append(value.partition("=")[2])
        elif value in {"-m32", "-m64"}:
            flags.append([value])
        elif value.startswith("@"):
            malformed = True
    axes = [{**defaults, **_compiler_axes(triple)} for triple in triples] or [dict(defaults)]
    bitness = {flag[0] for flag in flags if flag[0] in {"-m32", "-m64"}}
    if bitness:
        if any(value.get("isa") not in {"x86", "x86_64"} for value in axes):
            malformed = True
        axes = [{**value, "isa": "x86" if flag == "-m32" else "x86_64"}
                for value in axes for flag in sorted(bitness)]
    return flags, [{key: value.get(key) for key in AXES} for value in axes], malformed


def _capture_wrapper_invocation(executable, argv):
    """Identify instrumentation frames; their arguments are not execution evidence."""
    tool = PurePosixPath(executable).name
    if executable == f"/capture/wrappers/{tool}":
        return tool, argv[1:]
    if (executable == "/usr/bin/python3" and len(argv) >= 3
            and argv[1] == "/capture/tool-wrapper.py"):
        return argv[2], argv[3:]
    if executable != "/bin/sh" or len(argv) != 3 or argv[1] != "-c":
        return None
    if "$" in argv[2] or "`" in argv[2]:
        return None
    try:
        lexer = shlex.shlex(argv[2], posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        command = list(lexer)
    except ValueError:
        return None
    # Ninja surrounds a linker command with these no-op guards.
    if command[:2] == [":", "&&"]:
        command = command[2:]
    if command[-2:] == ["&&", ":"]:
        command = command[:-2]
    if not command or any(value in {";", "&&", "||", "|", "&", "<", ">", "(", ")"} for value in command):
        return None
    tool = PurePosixPath(command[0]).name
    return (tool, command[1:]) if command[0] == f"/capture/wrappers/{tool}" else None


def captured_enforcement(*, captures: Sequence[tuple[int, VerifiedCapture]],
                         dispatch: Mapping[str, Any], bound: Mapping[str, Any],
                         profiles: Mapping[str, Any], policy, run_root: Path,
                         artifacts: Sequence[Mapping[str, Any]]):
    """Return one unit-scoped proof, including all observed drivers and target switches."""
    from appsec_review.jobs.job_language_build.native import tool_kind
    from appsec_review.jobs.job_language_build.native_components import compile_entries
    profiles = merge_profile_sets([profiles])
    image = dispatch["image"]["image_id"]
    records = profiles["images"].get(image, {})
    required = bound["selection"]["required_axes"]
    entries, entry_gaps = compile_entries(
        captures, initial_directory=posixpath.normpath(f"/workspace/{dispatch['recipe']['source_dir']}"))
    reasons, observed, axes = [], [], {}
    incomplete = bool(entry_gaps)
    for ordinal, capture in captures:
        if capture.document.get("collector", {}).get("image_id") != image:
            raise ValueError("execution capture belongs to a different pinned image")
        incomplete |= bool(capture.gaps) or not capture.document.get("limits", {}).get("capture_envp")
        events = list(capture.events())
        image_calls = set()
        for event in events:
            if (event.get("kind") != "process_exec" or event.get("result") != 0
                    or event.get("argv_truncated") or not isinstance(event.get("argv"), list)
                    or not isinstance(event.get("executable"), str)):
                continue
            profile = _profile_for(event["executable"], records)
            if profile is not None:
                image_calls.update((name, canonical_json(event["argv"][1:]))
                                   for name in profile["invocation_names"])
        for event in events:
            if event.get("kind") != "process_exec" or event.get("result") != 0:
                continue
            executable, argv = event.get("executable"), event.get("argv")
            if (not isinstance(executable, str) or not isinstance(argv, list) or not argv
                    or any(not isinstance(value, str) for value in argv)):
                incomplete = True
                continue
            kind = tool_kind(executable, argv)
            wrapper = _capture_wrapper_invocation(executable, argv)
            if (wrapper is not None and not event.get("argv_truncated")
                    and (wrapper[0], canonical_json(wrapper[1])) in image_calls):
                continue  # Only the matching kernel-observed image compiler proves execution.
            compiler_wrapper = wrapper is not None and tool_kind(
                wrapper[0], [wrapper[0], *wrapper[1]]) in {"compiler", "linker-driver"}
            if kind not in {"compiler", "linker-driver"} and not compiler_wrapper:
                # An unrecognised executable with compile flags cannot borrow a known driver's name.
                source_argument = any(PurePosixPath(value).suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".c++"}
                                      for value in argv[1:])
                if not ({"-c", "-cc1"} & set(argv) or kind is None and source_argument and "-o" in argv):
                    continue
            profile = _profile_for(executable, records)
            flags, targets, malformed = _targets(argv, profile["target_axes"] if profile else {})
            if not flags and not any(
                    PurePosixPath(value).suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm", ".s", ".o", ".obj"}
                    for value in argv[1:]) and "-o" not in argv:
                targets = []  # Version/default-target queries do not compile a native target.
            trusted = profile is not None and not event.get("argv_truncated") and not malformed
            if not trusted:
                reasons.append("unknown_compiler_in_capture")
            for value in targets:
                axes[_digest(value)] = value
            observed.append({
                "executable": executable, "profile_identity": _digest(profile) if profile else None,
                "compiler_sha256": profile["compiler_sha256"] if profile else None,
                "capture_record_sha256": capture.identity["sha256"],
                "command_ordinal": ordinal, "event_ordinal": event["ordinal"],
                "target_flags": flags, "axes": targets, "trusted": trusted,
            })
    if not entries or not observed or not axes:
        reasons.append("capture_empty")
    elif incomplete:
        reasons.append("unknown_compiler_in_capture")
    if len(axes) > 1:
        reasons.append("mixed_targets_in_capture")
    proven = next(iter(axes.values())) if len(axes) == 1 else dict.fromkeys(AXES)
    selection = parse_build_selection(policy)
    if len(axes) == 1 and not reasons and (selection.forbids_isa(proven["isa"]) or any(
            value is not None and proven.get(key) != value for key, value in required.items())
            or proven["os"] is None or proven["isa"] is None):
        reasons.append("cross_target_not_permitted")
    output_checks = []
    if not reasons:
        from appsec_review.jobs.build_workspace import ProductSpec, WorkspaceError, verify_native_product
        roles = {"executable": ("executable", "executable"), "shared-library": ("library", "runtime_shared"),
                 "static-library": ("library", "static_archive"), "object": ("generated_source", "native_object")}
        for artifact in artifacts:
            if artifact["kind"] not in roles:
                continue
            path = safe_path(run_root, artifact["path"])
            if file_sha256(path) != artifact["sha256"]:
                raise ValueError("native artifact changed before target enforcement")
            kind, role = roles[artifact["kind"]]
            spec = ProductSpec("target/" + artifact["workspace_path"], kind, artifact["sha256"],
                               artifact["workspace_path"], dispatch["build_variant"], role, proven)
            check = {"path": artifact["path"], "sha256": artifact["sha256"], "role": role}
            try:
                verify_native_product(path, spec)
            except WorkspaceError as error:
                reasons.append("cross_target_not_permitted")
                check["rejection"] = str(error)
            output_checks.append(check)
    reasons = sorted(set(reasons))
    operations = [operation["operation_id"] for operation in bound["operations"]
                  if operation["kind"] in {"native_compile", "native_link", "native_aot"}]
    operation = _digest(operations)
    annotation = bound["enforcement"][0] if bound["enforcement"] else {}
    proof = {
        "schema": ENFORCEMENT_SCHEMA, "build_unit_id": dispatch["build_unit_id"],
        "operation_id": operation, "operation_binding": operation,
        "required_axes": required, "proof_kind": "captured_invocation",
        "status": "proven" if not reasons else "unknown", "proven_axes": proven,
        "unresolved_inputs": reasons, "scope_rule": RULES,
        "source_evidence_refs": [], "source_fingerprint": dispatch["source_fingerprint"],
        "catalog_bundle_identity": annotation.get("catalog_bundle_identity", _digest({})),
        "selection_id": bound["selection"]["selection_id"], "recipe_digest": _digest(dispatch["recipe"]),
        "profile_identity": _digest(profiles),
        "closure_manifest": {
            "schema": "appsec-review/captured-native-closure/1", "image_id": image,
            "profiles": profiles, "operations": operations, "compilers": observed,
            "translation_units": sorted({entry["file"] for entry in entries}),
            "native_artifacts": output_checks,
            "observed_axes": [axes[key] for key in sorted(axes)],
            "captures": [dict(capture.identity) for _, capture in captures],
        },
    }
    proof["enforcement_id"] = _digest(proof)
    validate_enforcement(proof, dispatch=dispatch)
    gaps = [producer_gap("producer_reported_gap", reason,
                         scope_id=dispatch["build_unit_id"]) for reason in reasons]
    return proof, gaps


@lru_cache(maxsize=1)
def _validator():
    from jsonschema import Draft202012Validator
    from appsec_review.application_paths import application_root
    directory = application_root("docs/schemas/native-target-enforcement.schema.json") / "docs/schemas"
    schema = json.loads((directory / "native-target-enforcement.schema.json").read_bytes())
    axes = json.loads((directory / "build-selection-policy.schema.json").read_bytes())["$defs"]["axes"]
    schema["properties"]["required_axes"] = axes
    schema["properties"]["proven_axes"] = axes
    return Draft202012Validator(schema)


def validate_enforcement(proof, *, dispatch=None):
    _validator().validate(proof)
    if (not isinstance(proof, Mapping) or proof.get("schema") != ENFORCEMENT_SCHEMA
            or proof.get("proof_kind") != "captured_invocation"
            or proof.get("enforcement_id") != _digest({
                key: value for key, value in proof.items() if key != "enforcement_id"})
            or proof.get("status") not in {"proven", "unknown"}
            or (proof["status"] == "proven") != (not proof.get("unresolved_inputs"))):
        raise ValueError("captured native enforcement identity is invalid")
    closure = proof["closure_manifest"]
    if dispatch is not None and (
            proof["build_unit_id"] != dispatch["build_unit_id"]
            or proof["recipe_digest"] != _digest(dispatch["recipe"])
            or proof["source_fingerprint"] != dispatch["source_fingerprint"]
            or closure["image_id"] != dispatch["image"]["image_id"]):
        raise ValueError("captured native enforcement belongs to a different build")
    if proof["status"] == "proven" and (
            len(closure["observed_axes"]) != 1 or not closure["translation_units"]
            or not closure["captures"] or not closure["compilers"]
            or any(not compiler["trusted"] for compiler in closure["compilers"])
            or proof["proven_axes"]["os"] is None or proof["proven_axes"]["isa"] is None
            or any(value is not None and proof["proven_axes"][key] != value
                   for key, value in proof["required_axes"].items())):
        raise ValueError("captured native enforcement does not prove one compatible target")
