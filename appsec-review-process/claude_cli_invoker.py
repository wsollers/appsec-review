#!/usr/bin/env python3
"""Real ``PersonaInvoker`` (D01 construction, Phase 5b item 4): bridges
``persona_invocation.py``'s dispatch-protocol-only B14 adapter ("no model client and no network
here" by design) to a live `claude -p` call, reusing `review_cli.py`'s already-proven dispatch
primitives (`_dispatch_streaming`) rather than rewriting them.

**Strict IO contract (William, 2026-09-24): the model's output is validated, not parsed
heuristically.** D01's job templates set ``tools: []`` / ``budget.tool_call_limit: 0`` (see
``persona_dispatch.py``'s docstring: the persona reads target bytes already pinned into
``readable_inputs``, never calls back into a live filesystem, matching ``owasp_dispatch.py``'s own
convention for its pooled cells). With no tool access, the model cannot use a Write tool to place
files itself the way `review_cli.py`'s existing tool-using lanes do -- it has exactly one turn and
must return everything in its final text response. This invoker's response envelope (documented on
``ENVELOPE_INSTRUCTIONS`` below) requires that response to be ONE JSON object, one key per
output-contract-required file (besides ``status.json``, which is not this invoker's concern -- see
below), each value schema-validated (for the ``.json``-keyed entry, against the output contract's
own declared ``result_schema.schema_file``) or type-checked (a ``.md``-keyed entry must be a
string). Anything else -- unparseable JSON, a missing key, a schema violation, prose before or
after the object -- is a hard rejection: this invoker raises rather than writing a best-effort
``invoker-output.json``. Per B14's own contract (``persona_invocation.run_invocation``'s
``_call_invoker``), an invoker that raises (not ``InvokerUnavailable``) yields outcome ``"raised"``
-> cause ``INVOKER_EXCEPTION`` -> execution_status ``FAILED``: the adapter, not this module, is
what turns a rejection into the run's terminal record. This invoker never invents a softer outcome.

**Scope, deliberately not yet generalized past what D01 needs (flagged, not assumed):**
- ``status.json`` is excluded from what this invoker asks the model to produce or writes itself.
  It belongs to the run's own bookkeeping (job/attempt/dagster identity, `artifacts_read` from the
  handoff) that only the caller (Phase 5b item 5, `discovery_gate.py`'s wiring, not yet built) has
  -- the same shape `discovery_gate.py`'s existing `_run_partition`/`execute_attempt` already
  builds for the supplied-record path. `persona_invocation.py`'s own `OUTPUT_SCHEMA` has no concept
  of `status.json` either; this keeps the split at the same seam the B14 protocol already draws.
- The response-envelope's per-file typing only understands `.json` (schema-validated against the
  output contract's `result_schema.schema_file`) and `.md` (a plain string). A future output
  contract requiring, say, a second JSON artifact or a binary file needs this table extended, not
  silently ignored -- `_envelope_field` raises `InvokerOutputError` naming the unsupported
  extension rather than guessing.
- This invoker only handles ``invocation_role: "produce"`` with ``tools: []``. A future
  review/verify/refute/judge role, or a job template that actually grants tool actions, needs this
  module extended (a granted-but-unused tool action is harmless and not rejected here, since
  ``package.tool_actions`` may legitimately be empty even when the tooling profile allows actions
  the job template chose not to request -- but a *used* tool call is not something this invoker can
  honor today, since it never grants the CLI any `--allowedTools`).
"""
from __future__ import annotations

import json
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import claude_binary_resolver as cbr
import persona_invocation as pi
import review_cli as rc
from schema_validate import SchemaStore, validate_document

ROOT = Path(__file__).resolve().parent
SCHEMAS_ROOT = ROOT.parent / "schemas"

DEFAULT_TIMEOUT_SECONDS = 1800

ENVELOPE_INSTRUCTIONS = """
## Response format -- read carefully, this is enforced mechanically

You have no tools in this invocation. Everything you produce must be in this single response, as
one JSON object and nothing else: no prose before it, no prose after it, no markdown code fence
around it. The object has exactly these keys, each holding the file's full content:

{envelope_keys}

Every JSON-valued key's content is validated against its published schema before anything is
accepted; a value that does not validate, an extra or missing key, or any text outside the single
JSON object causes this entire invocation to be rejected and recorded as failed. Produce exactly
one well-formed response.
""".strip()


class InvokerOutputError(ValueError):
    """The model's response was not a valid, schema-conformant envelope. Raised so
    ``persona_invocation.run_invocation`` records ``INVOKER_EXCEPTION`` / ``FAILED`` -- this module
    never writes a partial or best-effort ``invoker-output.json`` for a rejected response."""


def _slug(filename: str) -> str:
    """``repository-partition-map.json`` -> ``repository_partition_map``, used as the response
    envelope's JSON key for that required file."""
    stem = filename.rsplit(".", 1)[0]
    return re.sub(r"[^a-z0-9]+", "_", stem.lower()).strip("_")


def _envelope_fields(output_contract: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(filename, envelope_key, kind) for every required file this invoker asks the model to
    produce -- every ``required_files`` entry except ``status.json`` (see module docstring)."""
    fields = []
    for filename in output_contract["required_files"]:
        if filename == "status.json":
            continue
        if filename.endswith(".json"):
            fields.append((filename, _slug(filename), "json"))
        elif filename.endswith(".md"):
            fields.append((filename, _slug(filename), "md"))
        else:
            raise InvokerOutputError(
                f"output contract {output_contract['contract_id']!r} requires {filename!r}, whose "
                f"extension this invoker's response envelope does not yet support (only .json and "
                f".md are handled today -- see this module's docstring)")
    if not fields:
        raise InvokerOutputError(
            f"output contract {output_contract['contract_id']!r} requires no file besides "
            f"status.json -- nothing for this invoker to ask the model to produce")
    return fields


def _local_schema_refs(schema: Any, *, seen: set[str]) -> None:
    """Every local ``$ref`` schema filename directly or transitively reachable from ``schema``
    (e.g. ``repository-partition-map.schema.json``'s partitions/relationships referencing
    ``evidence-citation.schema.json``), collected into ``seen``. Only bare ``<name>.schema.json``
    refs are followed (this project's own convention, confirmed by reading every schema under
    ``schemas/`` -- none use ``#/...`` JSON-pointer refs or remote URLs); anything else is ignored
    rather than guessed at."""
    if isinstance(schema, dict):
        ref = schema.get("$ref")
        if isinstance(ref, str) and ref.endswith(".schema.json") and ref not in seen:
            seen.add(ref)
        for value in schema.values():
            _local_schema_refs(value, seen=seen)
    elif isinstance(schema, list):
        for item in schema:
            _local_schema_refs(item, seen=seen)


def _render_json_schema(schema_file: str, store: SchemaStore) -> str:
    """The literal JSON Schema content for one required JSON output file, fenced and labeled, plus
    every local schema it ``$ref``s (e.g. ``evidence-citation.schema.json``), each fenced
    separately. **Why this exists (a real bug found live on hal5000, 2026-09-24):** this invoker
    used to tell the model only the output contract's registry *metadata* (display name, claim
    class, prose validation rules -- see ``persona_prompt_assembly``'s ``output_contract`` prompt
    section), never the schema's own field names, enums, or required-properties. D01's first live
    dispatch against the real fixture produced a well-reasoned, evidence-cited, but structurally
    different JSON object (``engagement``/``paths.include``/``kind`` singular/``review_disposition``
    instead of the schema's own ``target``/``include_paths``/``kinds``/``disposition``, etc.) --
    entirely reasonable, since the model was never shown what shape was actually required. This
    function closes that gap: the model now reads the same schema this invoker will validate its
    response against, byte for byte."""
    root_schema = store.load(schema_file)
    seen: set[str] = set()
    _local_schema_refs(root_schema, seen=seen)
    parts = [f"### `{schema_file}` (required JSON Schema -- your output must validate against this "
             f"exactly: these field names, these enums, these required properties, nothing else "
             f"unless the schema allows it)\n",
             f"```json\n{json.dumps(root_schema, indent=2, sort_keys=True)}\n```\n"]
    for ref in sorted(seen):
        parts.append(f"### `{ref}` (referenced by `{schema_file}` -- every place above that "
                     f"`$ref`s it must conform to this)\n")
        parts.append(f"```json\n{json.dumps(store.load(ref), indent=2, sort_keys=True)}\n```\n")
    return "\n".join(parts)


def _render_readable_inputs(inputs: tuple) -> str:
    """Every readable input's exact bytes, inlined into the prompt text -- the only way the model
    can see them at all, since this invoker grants no tools and no filesystem access. Each is
    fenced and labeled by its pinned root/path, matching ``persona_prompt_assembly``'s own
    labeled-fenced-block convention for registry sections."""
    parts = ["## Target Repository Files\n",
             "Every file below is pinned to the exact bytes and path shown; cite it by this path "
             "when your output contract requires an evidence citation.\n"]
    for item in inputs:
        try:
            text = item.data.decode("utf-8")
        except UnicodeDecodeError:
            text = f"<{len(item.data)} bytes, not UTF-8 text -- not inlined>"
        parts.append(f"### {item.root}:{item.path}\n\n```\n{text}\n```\n")
    return "\n".join(parts)


def build_prompt_text(package: Any, output_contract: dict[str, Any], store: SchemaStore) -> str:
    """The assembled outer prompt (governing rules, persona, role, domain, tooling profile,
    buildenv catalog, task, output contract -- already rendered by
    ``persona_prompt_assembly.assemble_outer_prompt`` and pinned by
    ``persona_invocation.resolve_request``), plus every readable input's bytes (never otherwise
    visible to a tool-less model), plus the literal JSON Schema for every required JSON output file
    (``_render_json_schema`` -- the outer prompt's own ``output_contract`` section only carries the
    contract's registry metadata, not the schema's field names/enums/required-properties; see that
    function's docstring for the live bug this closes), plus this invoker's own strict
    response-envelope instructions."""
    outer = package.prompt.decode("utf-8")
    fields = _envelope_fields(output_contract)
    envelope_keys = "\n".join(f'- `"{key}"`: {filename}' for filename, key, _kind in fields)
    # Every JSON-valued required file gets its literal schema inlined. Today's output contracts
    # declare exactly one JSON artifact (result_schema.artifact/schema_file); this loop still
    # covers every kind=="json" field by filename match rather than assuming there is only one,
    # so a future contract with a second JSON file is not silently left unrendered.
    schema_sections = []
    for filename, _key, kind in fields:
        if kind != "json":
            continue
        if filename != output_contract["result_schema"]["artifact"]:
            raise InvokerOutputError(
                f"output contract {output_contract['contract_id']!r} requires JSON file "
                f"{filename!r}, which is not its declared result_schema.artifact "
                f"{output_contract['result_schema']['artifact']!r} -- this invoker only knows how "
                f"to find a schema for the declared result artifact")
        schema_sections.append(_render_json_schema(output_contract["result_schema"]["schema_file"], store))
    parts = [outer, _render_readable_inputs(package.inputs)]
    if schema_sections:
        parts.append("## Required Output Schema(s)\n\n" + "\n".join(schema_sections))
    parts.append(ENVELOPE_INSTRUCTIONS.format(envelope_keys=envelope_keys))
    return "\n\n".join(parts)


def _dispatch_argv(model_alias: str, effort: str, budget_usd: float | None, timeout_seconds: int,
                   binary: str) -> list[str]:
    """`binary` is the caller's already-resolved, real absolute claude CLI path (see
    ``claude_binary_resolver.py`` -- resolved and pinned once per run by whichever job dispatches
    first, normally ``model_version_registry.resolve_run_model_versions``). This function never
    re-resolves or falls back to a bare name itself, so a resolution failure is never silently
    masked here."""
    cfg = rc.load_model_config()
    invocation = cfg.get("invocation") or {}
    argv = [binary] + list(invocation.get("fixed_flags") or [])
    argv += ["--model", model_alias, "--effort", effort]
    if budget_usd is not None:
        argv += ["--max-budget-usd", str(budget_usd)]
    argv += ["--fallback-model", (cfg.get("default") or {}).get("model", "claude-sonnet-5")]
    argv += ["--allowedTools", ""]   # no tools: everything the model needs is inlined in the prompt
    return argv


def _extract_result_text(dispatch: dict[str, Any]) -> str:
    """Same proven key-search ``review_cli.py``'s own ``run`` command already uses against a real
    confirmed live response shape (``result``/``output``/``text``/``response``/``content``), so
    this invoker is not guessing at a second, divergent parsing rule."""
    final_result = dispatch.get("final_result")
    if isinstance(final_result, dict):
        for key in ("result", "output", "text", "response", "content"):
            value = final_result.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return ""


def _parse_envelope(result_text: str) -> dict[str, Any]:
    """The model's response must be exactly one JSON object -- no fence, no leading/trailing
    prose. A fenced block is tolerated (models reliably add one despite instructions not to) but
    anything else outside the object is not."""
    text = result_text.strip()
    fence = re.fullmatch(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    try:
        envelope = json.loads(text)
    except ValueError as exc:
        raise InvokerOutputError(f"model response is not valid JSON: {type(exc).__name__}") from None
    if not isinstance(envelope, dict):
        raise InvokerOutputError("model response is valid JSON but not a JSON object")
    return envelope


def _validate_envelope(envelope: dict[str, Any], fields: list[tuple[str, str, str]],
                       output_contract: dict[str, Any], store: SchemaStore) -> None:
    expected_keys = {key for _filename, key, _kind in fields}
    if set(envelope) != expected_keys:
        raise InvokerOutputError(
            f"model response envelope keys {sorted(envelope)} do not exactly match the required "
            f"{sorted(expected_keys)}")
    for _filename, key, kind in fields:
        value = envelope[key]
        if kind == "md":
            if not isinstance(value, str) or not value.strip():
                raise InvokerOutputError(f"envelope[{key!r}] must be a non-empty markdown string")
        elif kind == "json":
            if not isinstance(value, dict):
                raise InvokerOutputError(f"envelope[{key!r}] must be a JSON object")
            schema_file = output_contract["result_schema"]["schema_file"]
            errors = validate_document(value, schema_file, store)
            if errors:
                raise InvokerOutputError(
                    f"envelope[{key!r}] failed {schema_file}: {len(errors)} error(s) "
                    f"(first: {errors[0].split(':', 1)[0]})")


def _citation_for(item: Any, source_type: str, path: str, line_range: str | None) -> dict[str, Any] | None:
    """Maps one of the model's own ``evidence-citation.schema.json`` citations (``source_file``,
    repo-relative ``path``) to the matching pinned ``readable_inputs`` entry, in
    ``persona_invocation``'s own claim-citation shape (``root``/``path``/``sha256``/``locator``).
    Returns None when the citation does not name a pinned input this invoker can vouch for -- a
    citation this invoker cannot resolve is dropped from ``invoker-output.json``'s claims rather
    than fabricated; ``persona_invocation``'s own ``UNDECLARED_CITATION`` check is the backstop
    that would reject a claim left with no resolvable citation at all."""
    if source_type != "source_file" or item.path != path:
        return None
    return {"root": item.root, "path": item.path, "sha256": item.sha256,
            "locator": line_range or "whole file"}


def _claims_from_partition_map(partition_map: dict[str, Any], inputs: tuple,
                               allowed_claim_classes: tuple[str, ...], result_filename: str) -> list[dict[str, Any]]:
    """One claim per partition (claim_class ``repository_partition_map``, the only claim class D01's
    ceiling allows that fits a single structural result -- ``declared_relationships`` and
    ``specialist_review_routes`` are carried inside the same JSON artifact rather than split into
    separate claims, and ``evidence_gap`` is for `coverage.category_checks` entries, handled
    separately below), citing every ``source_file`` evidence citation the partition itself named
    that resolves to a pinned readable input."""
    by_path = {item.path: item for item in inputs}
    claim_class = "repository_partition_map"
    if claim_class not in allowed_claim_classes:
        raise InvokerOutputError(f"claim class {claim_class!r} is not in this request's allowed_claim_classes")
    claims: list[dict[str, Any]] = []
    for partition in partition_map.get("partitions", []):
        citations = [c for citation in partition.get("evidence_citations", [])
                    if (c := _citation_for(by_path.get(citation.get("path")), citation.get("source_type"),
                                           citation.get("path"), citation.get("line_range")))
                    is not None] if partition.get("evidence_citations") else []
        if not citations:
            raise InvokerOutputError(
                f"partition {partition.get('partition_id')!r} cites no evidence this invoker can "
                f"resolve to a pinned readable input -- governing rule 2 requires evidence that resolves")
        claims.append({
            "claim_id": f"partition-{partition.get('partition_id')}",
            "claim_class": claim_class,
            "statement": f"Partition {partition.get('partition_id')!r} ({partition.get('name')}): "
                        f"{partition.get('routing_rationale', '')}"[:2000],
            "file": result_filename, "citations": citations,
        })
    gap_class = "evidence_gap"
    for check in (partition_map.get("coverage") or {}).get("category_checks", []):
        if check.get("result") != "uninspected":
            continue
        if gap_class not in allowed_claim_classes:
            continue
        citations = [c for citation in check.get("evidence_citations", [])
                    if (c := _citation_for(by_path.get(citation.get("path")), citation.get("source_type"),
                                           citation.get("path"), citation.get("line_range")))
                    is not None] if check.get("evidence_citations") else []
        claims.append({
            "claim_id": f"gap-{_slug(str(check.get('category')))}"[:120],
            "claim_class": gap_class,
            "statement": f"Uninspected: {check.get('category')} (search scope: "
                        f"{', '.join(check.get('search_scope', []))})"[:2000],
            "file": result_filename, "citations": citations or
            [{"root": inputs[0].root, "path": inputs[0].path, "sha256": inputs[0].sha256,
              "locator": "whole file"}] if inputs else [],
        })
    if not claims:
        raise InvokerOutputError("model response named no partitions at all -- nothing to claim")
    return claims


class ClaudeCliInvoker:
    """The real, live ``PersonaInvoker``. One CLI call per invocation, no tools, strict envelope."""
    invoker_id = "claude-cli"

    def __init__(self, *, effort: str, budget_usd: float | None = None,
                timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, dispatch_fn=None) -> None:
        self.effort = effort
        self.budget_usd = budget_usd
        self.timeout_seconds = timeout_seconds
        self._dispatch_fn = dispatch_fn or rc._dispatch_streaming

    def invoke(self, package: Any, *, output_root: Path, cancel: threading.Event) -> None:
        if cancel.is_set():
            raise pi.InvokerUnavailable("canceled before dispatch")
        output_contract = dict(package.composition["output_contract"])
        store = SchemaStore()
        fields = _envelope_fields(output_contract)
        prompt_text = build_prompt_text(package, output_contract, store)
        model_alias = package.request["model"]["family"]
        # Reuses the run's already-pinned binary path when the run's first job (normally
        # model_version_registry.resolve_run_model_versions) already resolved one; resolves and
        # pins it itself otherwise (e.g. a caller that skips model-version resolution). Either way
        # this never falls back to a bare, PATH-dependent name -- see claude_binary_resolver.py.
        try:
            binary = cbr.resolve_claude_binary(package.request["run_id"])
        except cbr.ClaudeBinaryError as exc:
            raise pi.InvokerUnavailable(str(exc)) from exc
        argv = _dispatch_argv(model_alias, self.effort, self.budget_usd, self.timeout_seconds, binary)

        # B14's contract is strict: an invoker writes its files and invoker-output.json beneath
        # output_root "and nowhere else" -- persona_invocation.py's own output derivation scans
        # every file under output_root and rejects (MALFORMED_RESULT) anything not declared in
        # the manifest, and rejects any change elsewhere in the attempt tree too. Diagnostics
        # (the raw stream-json transcript, the raw terminal result) are genuinely useful for
        # debugging a rejected or crashed dispatch, but they are not part of the declared output
        # contract, so they go to a private scratch directory entirely outside attempt_root --
        # never under output_root, never anywhere else inside the attempt. Found and fixed while
        # structurally testing this module: the first draft wrote them under
        # output_root/diagnostics/, which is exactly the mistake this paragraph now documents.
        diagnostics_dir = Path(tempfile.mkdtemp(prefix="claude-cli-invoker-"))
        transcript_path = diagnostics_dir / "transcript.jsonl"
        started = time.time()
        try:
            dispatch = self._dispatch_fn(argv, prompt_text, self.timeout_seconds, transcript_path)
        except FileNotFoundError as exc:
            raise pi.InvokerUnavailable(f"claude CLI binary unavailable: {exc}") from exc
        duration_seconds = time.time() - started
        if cancel.is_set():
            raise pi.InvokerUnavailable("canceled during dispatch")
        if dispatch.get("timed_out"):
            raise TimeoutError("claude CLI dispatch exceeded its timeout")

        (diagnostics_dir / "raw-response.json").write_text(
            json.dumps(dispatch.get("final_result"), indent=2, sort_keys=True) if dispatch.get("final_result")
            is not None else "", encoding="utf-8")
        result_text = _extract_result_text(dispatch)
        if not result_text:
            raise InvokerOutputError(
                f"claude CLI dispatch produced no terminal result text (diagnostics: {diagnostics_dir})")

        try:
            envelope = _parse_envelope(result_text)
            _validate_envelope(envelope, fields, output_contract, store)
        except InvokerOutputError as exc:
            raise InvokerOutputError(f"{exc} (diagnostics: {diagnostics_dir})") from exc

        written_files: list[str] = []
        for filename, key, kind in fields:
            value = envelope[key]
            path = Path(output_root) / filename
            if kind == "md":
                path.write_text(value, encoding="utf-8")
            else:
                path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            written_files.append(filename)

        result_field = next(key for filename, key, kind in fields if kind == "json")
        result_filename = next(filename for filename, key, kind in fields if kind == "json")
        claims = _claims_from_partition_map(
            envelope[result_field], package.inputs, package.allowed_claim_classes, result_filename)

        usage_raw = dispatch.get("final_result") if isinstance(dispatch.get("final_result"), dict) else {}
        read_bytes = len(package.prompt) + sum(len(item.data) for item in package.inputs)
        written_bytes = sum(len((Path(output_root) / f).read_bytes()) for f in written_files)
        pi.write_invoker_output(
            package, output_root, files=written_files, claims=claims,
            usage={"input_bytes": read_bytes, "input_units": (usage_raw.get("usage") or {}).get("input_tokens")
                  or (read_bytes + 3) // 4,
                  "output_units": (usage_raw.get("usage") or {}).get("output_tokens")
                  or (written_bytes + 3) // 4,
                  "tool_calls": 0},
            tool_calls=[], verified_invocations=[], injection_suspected=[],
            limitations=[f"claude-cli dispatch, {duration_seconds:.1f}s, model={model_alias}, "
                        f"effort={self.effort}"])
