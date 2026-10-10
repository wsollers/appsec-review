"""Safe, ordered classification of captured compile/link commands and build environments.

Exact ``argv``/``envp`` stay in protected run-owned capture artifacts. This module derives the
retrievable view: every token keeps its ordinal and a kind; only allowlisted values survive, host
paths become logical target identities or a redacted external class, and environment variables are
reported by security class with presence and an allowlisted value only. The normalization rule and
per-token redaction state travel with every fact.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.storage import file_sha256


NORMALIZATION_RULE = "appsec-review/safe-command-facts/1"
ENVIRONMENT_RULE = "appsec-review/safe-environment-classes/1"
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm", ".s", ".asm", ".rs", ".go", ".java",
                    ".kt", ".cs", ".swift", ".f", ".f90"}
_OBJECT_SUFFIXES = {".o", ".obj", ".a", ".lib", ".so", ".dylib", ".dll", ".exe", ".wasm", ".rlib", ".class", ".jar"}
_SECURITY_FLAGS = re.compile(
    r"^(-fstack-protector(-all|-strong|-explicit)?|-fno-stack-protector|-D_FORTIFY_SOURCE(=\d)?|-U_FORTIFY_SOURCE|"
    r"-fPIE|-fpie|-fPIC|-fpic|-pie|-no-pie|-static|-static-pie|-shared|-fsanitize=[\w,-]+|-fno-sanitize=[\w,-]+|"
    r"-fcf-protection(=\w+)?|-fstack-clash-protection|-ftrivial-auto-var-init=\w+|-D_GLIBCXX_ASSERTIONS|"
    r"-fvisibility=\w+|-Wformat-security|-Werror=format-security|-fno-strict-overflow|-fwrapv|"
    r"-fno-delete-null-pointer-checks|-mshstk|-mbranch-protection=[\w+-]+|-Wl,-z,(relro|now|noexecstack|"
    r"execstack|norelro|lazy)|-z|relro|now|noexecstack|execstack|-Wl,--as-needed|-Wl,-pie|-Wl,--no-undefined|"
    r"/GS-?|/guard:cf|/DYNAMICBASE(:NO)?|/NXCOMPAT(:NO)?|/HIGHENTROPYVA|/CETCOMPAT|/sdl)$")
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.+-]{0,64}$")
_SECRETISH = re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|credential|auth|private[_-]?key|session)")
_SAFE_DEFINE_VALUES = {
    "_FORTIFY_SOURCE": frozenset({"0", "1", "2", "3"}),
    "_GLIBCXX_ASSERTIONS": frozenset({"0", "1"}),
    "NDEBUG": frozenset({"0", "1"}),
}


def _logical_path(value: str, target_prefixes: Sequence[str]) -> tuple[str, bool]:
    """Return a logical target path, or a redacted external class for any other host path."""
    text = value.replace("\\", "/")
    for prefix in target_prefixes:
        normalized = prefix.rstrip("/") + "/"
        if text.startswith(normalized):
            relative = PurePosixPath(text[len(normalized):])
            if ".." not in relative.parts and relative.as_posix() not in {"", "."}:
                return "target:" + relative.as_posix(), False
    if not text.startswith("/") and not re.match(r"^[A-Za-z]:/", text):
        relative = PurePosixPath(text)
        if ".." not in relative.parts and relative.as_posix() not in {"", "."}:
            return "relative:" + relative.as_posix(), False
    return "<external-path>", True


def _token(ordinal: int, kind: str, value: str | None, redacted: bool) -> dict[str, Any]:
    token: dict[str, Any] = {"ordinal": ordinal, "kind": kind, "redacted": redacted}
    if value is not None:
        token["safe_value"] = value[:256]
    return token


def classify_command(argv: Sequence[str], *, target_prefixes: Sequence[str] = ("/target/source", "/target")) -> list[dict[str, Any]]:
    """Classify every argv token in order; the raw token is never returned verbatim unless allowlisted."""
    tokens: list[dict[str, Any]] = []
    pending: str | None = None
    for ordinal, raw in enumerate(str(item) for item in argv):
        if ordinal == 0:
            tokens.append(_token(ordinal, "tool", PurePosixPath(raw.replace("\\", "/")).name or "<unknown>",
                                 False))
            continue
        if pending is not None:
            kind, pending = pending, None
            if kind in {"output", "include_path", "library_path", "source_input", "dependency_file"}:
                logical, redacted = _logical_path(raw, target_prefixes)
                tokens.append(_token(ordinal, kind, logical, redacted))
            elif kind == "language" and _SAFE_VALUE.fullmatch(raw):
                tokens.append(_token(ordinal, kind, raw, False))
            else:
                tokens.append(_token(ordinal, kind + "_value", None, True))
            continue
        if raw in {"-o", "/Fo", "-MF", "-MT", "-MQ"}:
            tokens.append(_token(ordinal, "output_flag" if raw in {"-o", "/Fo"} else "dependency_flag", raw, False))
            pending = "output" if raw in {"-o", "/Fo"} else "dependency_file"
        elif raw in {"-I", "-isystem", "-iquote", "-idirafter", "-L", "-include", "-x", "-Xlinker", "-Xclang"}:
            tokens.append(_token(ordinal, "flag", raw, False))
            pending = {"-L": "library_path", "-x": "language", "-Xlinker": "linker_argument",
                       "-Xclang": "frontend_argument", "-include": "include_path"}.get(raw, "include_path")
        elif raw.startswith("@"):
            tokens.append(_token(ordinal, "response_file", None, True))
        elif _SECURITY_FLAGS.fullmatch(raw):
            tokens.append(_token(ordinal, "security_flag", raw, False))
        elif raw.startswith(("-D", "/D")) and len(raw) > 2:
            name, separator, value = raw[2:].partition("=")
            safe = bool(_SAFE_VALUE.fullmatch(name)) and not _SECRETISH.search(name)
            value_safe = safe and separator and value in _SAFE_DEFINE_VALUES.get(name, ())
            rendered = (raw[:2] + name + ("=" + value if value_safe else "=<redacted>" if separator else "")
                        if safe else None)
            tokens.append(_token(ordinal, "define", rendered, not safe or bool(separator and not value_safe)))
        elif raw.startswith("-U") and _SAFE_VALUE.fullmatch(raw[2:]):
            tokens.append(_token(ordinal, "undefine", raw, False))
        elif raw.startswith(("-I", "-L")) and len(raw) > 2:
            logical, redacted = _logical_path(raw[2:], target_prefixes)
            tokens.append(_token(ordinal, "include_path" if raw.startswith("-I") else "library_path", logical, redacted))
        elif raw.startswith("-l") and _SAFE_VALUE.fullmatch(raw[2:]):
            tokens.append(_token(ordinal, "library", raw, False))
        elif re.fullmatch(r"-O[0-3sgz]?|-Ofast|/O[12dx]", raw):
            tokens.append(_token(ordinal, "optimization", raw, False))
        elif re.fullmatch(r"-g[0-3]?|-ggdb\d?|-gdwarf(-\d)?|/Zi|/Z7", raw):
            tokens.append(_token(ordinal, "debug", raw, False))
        elif re.fullmatch(r"-std=[\w+]+|/std:[\w+]+", raw):
            tokens.append(_token(ordinal, "language_standard", raw, False))
        elif raw in {"-c", "/c", "-S", "-E"}:
            tokens.append(_token(ordinal, "mode", raw, False))
        elif re.fullmatch(r"-W[\w=,+-]*", raw) and not raw.startswith("-Wl,"):
            tokens.append(_token(ordinal, "warning", raw[:128], False))
        elif raw.startswith("-Wl,"):
            tokens.append(_token(ordinal, "linker_flag", raw.split(",", 2)[0] + ",<redacted>" if "," in raw[4:] else
                                 raw if _SAFE_VALUE.fullmatch(raw[4:]) else "-Wl,<redacted>", True))
        elif raw.startswith(("-", "/")) and not raw.startswith("//") and "/" not in raw[1:] and len(raw) < 64:
            name = raw.split("=", 1)[0]
            tokens.append(_token(ordinal, "flag", name + ("=<redacted>" if "=" in raw else ""), "=" in raw))
        else:
            suffix = PurePosixPath(raw.replace("\\", "/")).suffix.lower()
            kind = ("source_input" if suffix in _SOURCE_SUFFIXES else
                    "object_input" if suffix in _OBJECT_SUFFIXES else "positional")
            if kind == "positional":
                tokens.append(_token(ordinal, kind, None, True))
            else:
                logical, redacted = _logical_path(raw, target_prefixes)
                tokens.append(_token(ordinal, kind, logical, redacted))
    return tokens


_ENV_CLASSES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"^(CC|CXX|AR|LD|AS|RANLIB|NM|STRIP|OBJCOPY|RUSTC|GOROOT|JAVA_HOME)$"), "toolchain_selection", "basename"),
    (re.compile(r"^(CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS|RUSTFLAGS|GOFLAGS|CGO_CFLAGS|CGO_LDFLAGS)$"), "compiler_flags",
     "security_flags"),
    (re.compile(r"^(LD_PRELOAD|LD_AUDIT|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH)$"), "loader_injection", "presence"),
    (re.compile(r"^(PATH|LD_LIBRARY_PATH|LIBRARY_PATH|CPATH|C_INCLUDE_PATH|CPLUS_INCLUDE_PATH|PKG_CONFIG_PATH|"
                r"PYTHONPATH|NODE_PATH|CLASSPATH|GOPATH)$"), "search_path", "presence"),
    (re.compile(r"^(SOURCE_DATE_EPOCH)$"), "reproducibility", "digits"),
    (re.compile(r"^(CI|NDEBUG|DEBUG|GOOS|GOARCH|CGO_ENABLED|NODE_ENV|RUST_BACKTRACE|MAKEFLAGS|CMAKE_BUILD_TYPE)$"),
     "build_mode", "safe_value"),
    (re.compile(r"(?i)^(HTTPS?_PROXY|NO_PROXY|ALL_PROXY)$"), "network_proxy", "presence"),
    (re.compile(r"(?i)(INDEX_URL|REGISTRY|_MIRROR$|NPM_CONFIG_|NUGET_|GOPROXY|GOPRIVATE|CARGO_REGISTRIES)"),
     "package_registry", "presence"),
)


def classify_environment(environment: Mapping[str, str] | Iterable[str]) -> dict[str, Any]:
    """Return security-relevant classes; credentials and arbitrary values are never returned."""
    pairs: list[tuple[str, str]] = []
    if isinstance(environment, Mapping):
        pairs = [(str(key), str(value)) for key, value in environment.items()]
    else:
        for item in environment:
            name, _, value = str(item).partition("=")
            pairs.append((name, value))
    facts: list[dict[str, Any]] = []
    other = 0
    for name, value in sorted(pairs):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
            other += 1
            continue
        if _SECRETISH.search(name):
            # Index sanitization would blank a class name containing "credential"; keep it stable.
            facts.append({"name": name, "class": "sensitive_variable", "present": True, "redacted": True})
            continue
        for pattern, env_class, policy in _ENV_CLASSES:
            if not pattern.search(name):
                continue
            fact: dict[str, Any] = {"name": name, "class": env_class, "present": True, "redacted": True}
            if policy == "basename" and value:
                base = PurePosixPath(value.replace("\\", "/").split()[0]).name
                if _SAFE_VALUE.fullmatch(base):
                    fact.update(safe_value=base, redacted=False)
            elif policy == "security_flags":
                flags = [token for token in value.split() if _SECURITY_FLAGS.fullmatch(token)]
                fact.update(safe_value=" ".join(flags)[:256], redacted=len(flags) != len(value.split()))
            elif policy == "digits" and value.isdigit():
                fact.update(safe_value=value, redacted=False)
            elif policy == "safe_value" and _SAFE_VALUE.fullmatch(value) and len(value) <= 32:
                fact.update(safe_value=value, redacted=False)
            facts.append(fact)
            break
        else:
            other += 1
    return {"environment_facts": facts, "unclassified_variable_count": other, "normalization_rule": ENVIRONMENT_RULE}


COMMAND_RULE_VERSION = "appsec-review/build-command-facts/1"


def capture_events(run_root: Path, handoffs: Mapping[str, Any]) -> dict[str, Path]:
    """Map protected capture-event hashes to run-owned paths named by accepted build handoffs."""
    found: dict[str, Path] = {}
    for job_id in ("job_language_build", "job_project_build"):
        handoff = handoffs.get(job_id)
        for artifact in (handoff.handoff.get("artifacts", ()) if handoff is not None else ()):
            path = str(artifact.get("path", ""))
            if path.endswith("events.jsonl"):
                found[str(artifact.get("sha256"))] = Path(run_root) / path
    return found


def _exec_events(path: Path, expected_sha256: str, limit: int) -> tuple[list[dict[str, Any]], bool]:
    if not path.is_file() or file_sha256(path) != expected_sha256:
        raise ValueError(f"protected capture events changed after acceptance: {path.name}")
    events: list[dict[str, Any]] = []
    with path.open("rb") as stream:
        for line in stream:
            record = json.loads(line)
            if record.get("kind") != "process_exec" or int(record.get("result", 0)) != 0:
                continue
            if len(events) >= limit:
                return events, True
            events.append(record)
    return events, False


def build_command_facts(shards: Any, run_root: Path, handoffs: Mapping[str, Any], *, max_events: int,
                        max_commands: int) -> Any:
    """Safe ordered command and environment facts per accepted language-build action.

    Exact argv/envp are read only from hash-verified protected capture artifacts at job time; facts
    keep token order, kinds, allowlisted values, redaction state and the protected artifact hash.
    """
    from appsec_review.indexing.products_base import Fact, Product

    product = Product("build_provenance", COMMAND_RULE_VERSION)
    build = shards.select("build", job="job_language_build")
    product.use(build)
    if not build:
        return product.unavailable("no accepted language-build shard: build command facts are unavailable")
    events = capture_events(run_root, handoffs)
    produced: dict[str, list[str]] = {}
    for relation in shards.relations([*shards.select("artifacts"), *build], ("GENERATED_FROM",)):
        produced.setdefault(relation["target_id"], []).append(relation["source_id"])
    without_capture = 0
    for row in shards.entities(build, ("build_action",)):
        payload = row.payload
        capture = payload.get("execution_capture") if isinstance(payload.get("execution_capture"), Mapping) else {}
        events_sha = capture.get("events_sha256")
        commands: list[dict[str, Any]] = []
        meta: list[dict[str, Any]] = []
        environment: dict[str, dict[str, Any]] = {}
        unclassified = 0
        gaps: list[str] = []
        if events_sha and str(events_sha) in events:
            records, truncated = _exec_events(events[str(events_sha)], str(events_sha), max_events)
            if truncated:
                gaps.append(f"exec events truncated at {max_events}")
            for record in records[:max_commands]:
                tokens = classify_command(record.get("argv") or [])
                commands.append({"build_action_id": row.identity,
                                 "tool_id": tokens[0].get("safe_value", "<unknown>") if tokens else "<unknown>",
                                 "ordered_tokens": tokens, "exact_artifact_sha256": str(events_sha),
                                 "normalization_rule": NORMALIZATION_RULE})
                meta.append({"exec_ordinal": record.get("ordinal"), "argv_truncated": bool(record.get("argv_truncated")),
                             "envp_truncated": bool(record.get("envp_truncated"))})
                env = classify_environment({str(item.get("name")): "" if item.get("redacted") else str(item.get("value", ""))
                                            for item in record.get("envp") or () if isinstance(item, Mapping)})
                unclassified = max(unclassified, env["unclassified_variable_count"])
                for item in env["environment_facts"]:
                    environment.setdefault(item["name"], item)
            if len(records) > max_commands:
                gaps.append(f"{len(records) - max_commands} exec command(s) omitted by the per-action bound")
        else:
            without_capture += 1
            gaps.append("protected execution capture is not bound to an accepted handoff artifact; only the "
                        "producer's sanitized command identity is available")
        tokens = [token for command in commands for token in command["ordered_tokens"]]
        product.facts.append(Fact(
            "build_action", row.identity,
            {"build_action_id": row.identity, "build_unit_id": payload.get("build_unit_id"),
             "tool": payload.get("tool"), "tool_kind": payload.get("tool_kind"),
             "exact_command_sha256": payload.get("argv_sha256"), "exact_capture_sha256": events_sha,
             "command_facts": commands, "command_meta": meta,
             "environment_facts": sorted(environment.values(), key=lambda item: item["name"]),
             "unclassified_environment_variables": unclassified,
             "producer_environment_facts": payload.get("environment_facts"),
             "security_flags": sorted({token["safe_value"] for token in tokens if token["kind"] == "security_flag"}),
             "source_inputs": sorted({token["safe_value"] for token in tokens
                                      if token["kind"] == "source_input" and "safe_value" in token}),
             "outputs": sorted({token["safe_value"] for token in tokens
                                if token["kind"] == "output" and "safe_value" in token}),
             "produced_artifact_ids": sorted(produced.get(row.identity, ()))[:200],
             "normalization_rule": NORMALIZATION_RULE, "environment_rule": ENVIRONMENT_RULE, "gaps": gaps,
             "protection": "exact argv and environment remain protected run-owned artifacts"},
            "accepted build action joined to its hash-verified protected capture", row.identity, None,
            (row.identity,), "partial" if gaps else "complete",
            text=f"build action {payload.get('tool')} " + " ".join(sorted({token['safe_value'] for token in tokens
                                                                           if token['kind'] == 'security_flag'}))))
    if without_capture:
        product.partial(f"{without_capture} build action(s) have no bound protected capture")
    product.counts = {"build_actions": len(product.facts), "without_capture": without_capture}
    return product
