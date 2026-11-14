"""Pure, bounded component proposals over authenticated native discovery context."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import PurePosixPath
import re
from typing import Any, Literal

from appsec_review.storage import canonical_json

from .discovery import _domain, _reference, _relative, _text, _within
from .native_inference_contracts import (
    CURATION_SCHEMA, CurationResult, CuratedComponent, NativeInferenceBounds,
    NativeInferenceError, Propose, SdkGroup, inference_identity,
)
from .native_sbom_contracts import (
    DISCOVERY_SCHEMA, Claim, CoverageGap, DiscoveryResult, NativeCandidate, NativeEvidence,
    NativeFile, NativeInputIntegrityError, evidence_identity,
)


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+\-]{0,255}")
_GENERIC = frozenset({
    "include", "includes", "header", "headers", "lib", "libs", "library", "libraries",
    "vendor", "vendors", "third-party", "third_party", "external", "deps", "dependencies",
    "src", "source", "sdk", ".", "",
})
_RULES = (
    "Return the curation schema with integer input_records equal to this batch size. "
    "Candidate references are INPUT IDs. Account for every input as selected, rejected or "
    "uncertain; multiple named libraries may share a noisy input. Keep independently named "
    "components, even inside SDK families. Prefix/namespace similarity alone is not a package "
    "boundary: SDK groups require coherent packaging/header-path context as well. Unfamiliar "
    "framework names are allowed when exact paths support them. Use only supplied context_paths. "
    "Libraries and groups are sorted by name; all reference/path/name lists are sorted and unique. "
    "Each SDK group's candidate_ids and supporting_paths equal its member libraries' unions. "
    "Kinds are library or sdk-component. Do not supply statuses or confidence."
)


class _InvalidProposal(ValueError):
    pass


def _unique(values: Sequence[Any]) -> list[Any]:
    records = {canonical_json(value): value for value in values}
    return [records[key] for key in sorted(records)]


def _unknown() -> Claim:
    return {"value": None, "status": "unknown", "evidence_ids": [], "alternatives": []}


def _oversized_field(value: Any, bound: int) -> bool:
    if isinstance(value, str):
        return len(value.encode()) > bound
    if isinstance(value, Mapping):
        return any(_oversized_field(key, bound) or _oversized_field(item, bound)
                   for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_oversized_field(item, bound) for item in value)
    return False


def _normalized(value: str) -> str:
    return value.casefold().replace("_", "-")


def _named_path(name: str, paths: Sequence[str]) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", name.casefold())
    return bool(compact) and any(
        compact == re.sub(r"[^a-z0-9]", "", PurePosixPath(part).stem.casefold())
        for path in paths for part in path.split("/") if part.casefold() not in _GENERIC
    )


def _strings(value: object, label: str, bounds: NativeInferenceBounds, *,
             nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise _InvalidProposal(f"{label} must be a {'nonempty ' if nonempty else ''}list")
    if any(not isinstance(item, str) or not item or any(ord(char) < 32 for char in item)
           or len(item.encode()) > bounds.field_bytes for item in value):
        raise _InvalidProposal(f"{label} contains an invalid or oversized string")
    if value != sorted(set(value)):
        raise _InvalidProposal(f"{label} must be sorted and unique")
    return value


def _name(value: object, bounds: NativeInferenceBounds) -> str:
    if (not isinstance(value, str) or not _NAME.fullmatch(value)
            or len(value.encode()) > bounds.field_bytes):
        raise _InvalidProposal("invalid or oversized component/group name")
    return value


def _basis(value: object, bounds: NativeInferenceBounds) -> str:
    if (not isinstance(value, str) or not value.strip() or value != value.strip()
            or any(ord(char) < 32 for char in value) or len(value.encode()) > bounds.field_bytes):
        raise _InvalidProposal("invalid or oversized proposal basis")
    return value


def _merge_claim(claims: Sequence[Claim]) -> Claim:
    if all(claim == claims[0] for claim in claims):
        return deepcopy(claims[0])
    known = [claim for claim in claims if claim["status"] != "unknown"]
    if not known:
        return _unknown()
    values = sorted({value for claim in known
                     for value in [claim["value"], *claim["alternatives"]] if value is not None})
    refs = sorted({ref for claim in known for ref in claim["evidence_ids"]})
    conflicted = len(values) > 1 or any(claim["status"] == "conflicted" for claim in known)
    if conflicted:
        return {"value": None, "status": "conflicted", "evidence_ids": refs,
                "alternatives": values}
    return {"value": values[0] if values else None,
            "status": "corroborated" if any(claim["status"] == "corroborated" for claim in known)
            else "inferred", "evidence_ids": refs, "alternatives": []}


def _evidence_matches_file(record: Mapping[str, Any], file: Mapping[str, Any]) -> bool:
    """Whether an evidence record describes the accepted catalog file it names.

    ``sha256`` and ``upstream`` must agree exactly. ``backing`` may legitimately differ in one way:
    the accepted catalog publishes workspace records before their bytes are read, so their
    ``backing`` is null, and the discovery reader fills an exact-byte backing on the record it reads
    (``integration.read_native_file``), which the evidence then carries. Such a filled backing is
    accepted only when its identity is the file's own ``sha256`` and ``size_bytes``.
    """
    if record["sha256"] != file["sha256"] or record["upstream"] != file["upstream"]:
        return False
    if record["backing"] == file["backing"]:
        return True
    filled = record.get("backing")
    return (file.get("backing") is None and isinstance(filled, Mapping)
            and (filled.get("sha256"), filled.get("size_bytes")) == (file["sha256"], file["size_bytes"]))


class _Curation:
    def __init__(self, discovery: DiscoveryResult, files: Sequence[NativeFile],
                 bounds: NativeInferenceBounds) -> None:
        self.bounds = bounds
        self.discovery = deepcopy(discovery)
        self.files: dict[tuple[str, str, str], NativeFile] = {}
        self.evidence: dict[str, NativeEvidence] = {}
        self.sources: dict[str, NativeCandidate] = {}
        self.domains: dict[str, str] = {}
        self.context: dict[str, dict[str, Any]] = {}
        self.effective: dict[str, NativeCandidate] = {}
        self.components: dict[str, CuratedComponent] = {}
        self.inferred_components: set[str] = set()
        self.groups: dict[str, SdkGroup] = {}
        self.decisions: list[dict[str, Any]] = []
        self.gaps: list[CoverageGap] = []
        self.uncertain: set[str] = set()
        self.excluded: set[str] = set()
        self.omitted: set[str] = set()
        self.omitted_files: set[tuple[str, str, str]] = set()
        self.calls = 0
        self._validate_inputs(files)

    def _validate_inputs(self, files: Sequence[NativeFile]) -> None:
        if self.discovery["schema"] != DISCOVERY_SCHEMA:
            raise NativeInputIntegrityError("Unsupported native discovery schema")
        if not isinstance(files, Sequence) or isinstance(files, (str, bytes)):
            raise ValueError("native files must be a finite sequence")
        for file in files:
            _domain(file)
            if "domain" not in file or "backing" not in file:
                raise ValueError("native file requires domain and backing")
            _text(file.get("root_id"), "root_id")
            _reference(file)
            _reference(file.get("upstream"))
            if file["backing"] is not None:
                backing = _reference(file["backing"])
                if (backing["sha256"], backing["size_bytes"]) != (
                        file["sha256"], file["size_bytes"]):
                    raise NativeInputIntegrityError("native backing identity differs from accepted file")
            key = file["domain"], file["root_id"], file["path"]
            if key in self.files and self.files[key] != file:
                raise NativeInputIntegrityError("conflicting accepted native file records")
            self.files[key] = deepcopy(file)
        fingerprints = set()
        for record in self.discovery["evidence"]:
            identifier = record["evidence_id"]
            if evidence_identity(record) != identifier or not record["selector"]:
                raise NativeInputIntegrityError("Unbound or changed native evidence")
            if identifier in self.evidence and self.evidence[identifier] != record:
                raise NativeInputIntegrityError("Conflicting native evidence ID")
            key = record["domain"], record["root_id"], record["path"]
            if key in self.files and not _evidence_matches_file(record, self.files[key]):
                raise NativeInputIntegrityError("native evidence differs from accepted catalog")
            self.evidence[identifier] = record
            fingerprints.add(record["source_fingerprint"])
        if "source_fingerprint" in self.discovery:
            fingerprints.add(self.discovery["source_fingerprint"])
        if len(fingerprints) > 1:
            raise NativeInputIntegrityError("native discovery mixes source fingerprints")
        self.fingerprint = next(iter(fingerprints), "")
        for candidate in self.discovery["candidates"]:
            identifier = candidate["candidate_id"]
            _text(identifier, "candidate_id")
            _text(candidate["native_name"], "native_name")
            _relative(candidate["package_root"], dot=True)
            _text(candidate["root_id"], "root_id")
            if identifier in self.sources and self.sources[identifier] != candidate:
                raise NativeInputIntegrityError("Conflicting native candidate ID")
            refs = set(candidate["evidence_ids"])
            for field in ("identity", "release", "upstream"):
                claim = candidate[field]
                if claim["status"] not in {"unknown", "inferred", "corroborated", "conflicted"}:
                    raise NativeInputIntegrityError("Unknown native claim status")
                if claim["status"] == "corroborated" and (
                        not claim["value"] or not claim["evidence_ids"]):
                    raise NativeInputIntegrityError("Unsupported corroborated native claim")
                refs.update(claim["evidence_ids"])
            refs.update(row["evidence_id"] for row in candidate["observations"]
                        if "evidence_id" in row)
            if not refs <= self.evidence.keys():
                raise NativeInputIntegrityError("Unknown native evidence reference")
            if not self.fingerprint:
                raise NativeInputIntegrityError("Native candidate lacks source identity")
            domains = {self.evidence[ref]["domain"] for ref in refs
                       if self.evidence[ref]["domain"] in {"target", "workspace"}
                       and self.evidence[ref]["root_id"] == candidate["root_id"]}
            prior_curation = candidate["metadata"].get("curation")
            explicit = prior_curation.get("domain") if isinstance(prior_curation, Mapping) else None
            if explicit is not None:
                domains.add(explicit)
            if len(domains) > 1 or (domains and not domains <= {"target", "workspace"}):
                raise NativeInputIntegrityError("Native candidate has ambiguous source domain")
            self.domains[identifier] = next(iter(domains), _domain(candidate))
            self.sources[identifier] = candidate
        for gap in self.discovery["gaps"]:
            if not set(gap["evidence_ids"]) <= self.evidence.keys():
                raise NativeInputIntegrityError("Unknown native gap evidence reference")

    def gap(self, identifier: str, detail: str, *, bound: bool = False) -> None:
        refs = self.sources[identifier]["evidence_ids"] if identifier in self.sources else []
        self.gaps.append({
            "kind": "bounds" if bound else "unsupported_metadata",
            "scope": identifier, "detail": detail.encode()[:self.bounds.field_bytes].decode(
                "utf-8", errors="ignore"), "evidence_ids": sorted(set(refs)),
        })

    def locality(self, identifier: str) -> tuple[str, str, str]:
        source = self.sources[identifier]
        return self.domains[identifier], source["root_id"], source["package_root"]

    def make_context(self, identifier: str) -> dict[str, Any]:
        source = self.sources[identifier]
        domain, root_id, root = self.locality(identifier)
        refs = set(source["evidence_ids"])
        for field in ("identity", "release", "upstream"):
            refs.update(source[field]["evidence_ids"])
        refs.update(row["evidence_id"] for row in source["observations"] if "evidence_id" in row)
        evidence = [self.evidence[ref] for ref in sorted(refs)]
        evidence_paths = {row["path"] for row in evidence
                          if row["domain"] == domain and row["root_id"] == root_id}
        catalog = [file for key, file in sorted(self.files.items())
                   if key[:2] == (domain, root_id) and _within(file["path"], root)]
        catalog.sort(key=lambda file: (file["path"] not in evidence_paths,
                                      PurePosixPath(file["path"]).suffix.casefold()
                                      not in {".h", ".hh", ".hpp", ".hxx", ".inc"},
                                      file["path"]))
        omitted = catalog[self.bounds.files_per_root:]
        if omitted:
            self.omitted_files.update((file["domain"], file["root_id"], file["path"])
                                      for file in omitted)
            self.gap(identifier, f"curation files_per_root: omitted {len(omitted)} catalog paths",
                     bound=True)
        catalog = sorted(catalog[:self.bounds.files_per_root], key=lambda file: file["path"])
        context = {
            **deepcopy(source), "domain": domain, "evidence": deepcopy(evidence),
            "files": deepcopy(catalog),
            "context_paths": sorted(evidence_paths | {file["path"] for file in catalog}),
        }
        self.context[identifier] = context
        return context

    def payload(self, identifiers: list[str]) -> dict[str, Any]:
        return {"schema": CURATION_SCHEMA, "input_records": len(identifiers),
                "candidates": [deepcopy(self.context[identifier]) for identifier in identifiers],
                "rules": _RULES}

    def preserve(self, identifier: str, reason: str, *, bound: bool = False) -> None:
        reason = reason.encode()[:self.bounds.field_bytes].decode("utf-8", errors="ignore")
        self.uncertain.add(identifier)
        if bound:
            self.omitted.add(identifier)
        self.gap(identifier, "curation: " + reason, bound=bound)
        basis = ("Conservative original: " + reason).encode()[:self.bounds.field_bytes].decode(
            "utf-8", errors="ignore")
        self.add_component(self.sources[identifier]["native_name"], "library", [identifier], [],
                           basis, conservative=True)
        self.decisions.append({"candidate_id": identifier, "decision": "uncertain",
                               "reason": reason})

    def _path_evidence(self, identifier: str, path: str) -> list[str]:
        domain, root_id, _ = self.locality(identifier)
        context = self.context[identifier]
        matched = [row["evidence_id"] for row in context["evidence"]
                   if (row["domain"], row["root_id"], row["path"]) == (domain, root_id, path)]
        if matched:
            return matched
        file = self.files[domain, root_id, path]
        record: NativeEvidence = {
            "evidence_id": "", "kind": "catalog_path", "value": path,
            "source_fingerprint": self.fingerprint, "domain": domain, "root_id": root_id,
            "path": path, "sha256": file["sha256"], "upstream": deepcopy(file["upstream"]),
            "backing": deepcopy(file["backing"]), "selector": {"catalog_path": path},
        }
        record["evidence_id"] = evidence_identity(record)
        self.evidence[record["evidence_id"]] = record
        return [record["evidence_id"]]

    def add_component(self, name: str, kind: Literal["library", "sdk-component"],
                      identifiers: list[str], paths: list[str],
                      basis: str, *, conservative: bool = False) -> None:
        name = _normalized(name)
        component_id = inference_identity("component", {"name": name})
        if component_id not in self.components:
            self.components[component_id] = {
                "component_id": component_id, "name": name, "kind": kind,
                "candidate_ids": [], "source_candidate_ids": [], "supporting_paths": [],
                "basis": basis,
            }
        component = self.components[component_id]
        if kind == "sdk-component":
            component["kind"] = "sdk-component"
        component["basis"] = min(component["basis"], basis)
        grouped: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        for identifier in identifiers:
            grouped[self.locality(identifier)].append(identifier)
        for (domain, root_id, root), sources in sorted(grouped.items()):
            identifier = inference_identity("dependency", {
                "source_fingerprint": self.fingerprint, "domain": domain, "root_id": root_id,
                "package_root": root, "name": name,
            })
            originals = [self.sources[value] for value in sorted(sources)]
            same_name = [source for source in originals
                         if _normalized(source["native_name"]) == name]
            local_paths = sorted({path for path in paths for source in sources
                                  if path in self.context[source]["context_paths"]})
            evidence_ids = {ref for source in originals for ref in source["evidence_ids"]}
            for source in sources:
                for path in local_paths:
                    if path in self.context[source]["context_paths"]:
                        evidence_ids.update(self._path_evidence(source, path))
            if same_name:
                candidate = deepcopy(same_name[0])
                for field in ("identity", "release", "upstream"):
                    candidate[field] = _merge_claim([source[field] for source in same_name])
            else:
                candidate = deepcopy(originals[0])
                candidate.update(metadata={}, repository=None, identity={
                    "value": name, "status": "inferred", "evidence_ids": sorted(evidence_ids),
                    "alternatives": [],
                }, release=_unknown(), upstream=_unknown())
            candidate.update(candidate_id=identifier, native_name=name,
                             evidence_ids=sorted(evidence_ids),
                             observations=_unique([row for source in originals
                                                   for row in source["observations"]]))
            candidate["metadata"]["curation"] = {
                "schema": CURATION_SCHEMA, "status": "inferred", "domain": domain,
                "source_candidate_ids": sorted(sources), "component_id": component_id,
                "supporting_paths": local_paths, "basis": basis,
                "conservative": conservative,
            }
            if identifier in self.effective:
                previous = self.effective[identifier]
                for field in ("identity", "release", "upstream"):
                    candidate[field] = _merge_claim([previous[field], candidate[field]])
                candidate["evidence_ids"] = sorted(set(previous["evidence_ids"])
                                                   | set(candidate["evidence_ids"]))
                candidate["observations"] = _unique([*previous["observations"],
                                                     *candidate["observations"]])
                prior = previous["metadata"]["curation"]
                current = candidate["metadata"]["curation"]
                for field in ("source_candidate_ids", "supporting_paths"):
                    current[field] = sorted(set(prior[field]) | set(current[field]))
                current["conservative"] |= prior["conservative"]
                current["basis"] = min(prior["basis"], current["basis"])
                candidate["metadata"] = {**previous["metadata"], **candidate["metadata"]}
            if candidate["release"]["status"] == "conflicted":
                candidate["metadata"].pop("version", None)
            if candidate["upstream"]["status"] == "conflicted":
                candidate["metadata"].pop("repository_url", None)
                candidate["repository"] = None
            for field, kind_name in (("identity", "identity_conflict"),
                                     ("release", "version_conflict"),
                                     ("upstream", "repository_conflict")):
                claim = candidate[field]
                if claim["status"] == "conflicted":
                    self.gaps.append({
                        "kind": kind_name, "scope": identifier,
                        "detail": f"curation retained incompatible local {field} claims",
                        "evidence_ids": sorted(claim["evidence_ids"]),
                    })
            self.effective[identifier] = candidate
            component["candidate_ids"] = sorted(set(component["candidate_ids"]) | {identifier})
        component["source_candidate_ids"] = sorted(set(component["source_candidate_ids"])
                                                    | set(identifiers))
        component["supporting_paths"] = sorted(set(component["supporting_paths"]) | set(paths))

    def validate(self, proposal: object, identifiers: list[str]) -> dict[str, Any]:
        if not isinstance(proposal, Mapping):
            raise _InvalidProposal("proposal must be an object")
        try:
            size = len(canonical_json(proposal))
        except NativeInputIntegrityError:
            raise
        except (ValueError, TypeError, RecursionError) as exc:
            raise _InvalidProposal("proposal is not finite JSON") from exc
        if size > self.bounds.max_payload_bytes:
            raise _InvalidProposal("proposal exceeds max_payload_bytes")
        if set(proposal) != {"schema", "input_records", "libraries", "sdk_groups",
                             "rejected_candidate_ids", "uncertain_candidate_ids"}:
            raise _InvalidProposal("proposal has missing or unknown fields")
        if (proposal["schema"] != CURATION_SCHEMA or type(proposal["input_records"]) is not int
                or proposal["input_records"] != len(identifiers)):
            raise _InvalidProposal("proposal schema/input_records mismatch")
        allowed = set(identifiers)
        rejected = set(_strings(proposal["rejected_candidate_ids"], "rejected IDs", self.bounds))
        uncertain = set(_strings(proposal["uncertain_candidate_ids"], "uncertain IDs", self.bounds))
        if not (rejected | uncertain) <= allowed or rejected & uncertain:
            raise _InvalidProposal("rejected/uncertain IDs are unowned or overlap")
        libraries = proposal["libraries"]
        groups = proposal["sdk_groups"]
        if not isinstance(libraries, list) or not isinstance(groups, list):
            raise _InvalidProposal("libraries and sdk_groups must be lists")
        named: dict[str, dict[str, Any]] = {}
        selected: set[str] = set()
        for library in libraries:
            if not isinstance(library, Mapping) or set(library) != {
                    "name", "kind", "candidate_ids", "supporting_paths", "basis"}:
                raise _InvalidProposal("invalid library fields")
            name = _name(library["name"], self.bounds)
            if not isinstance(library["kind"], str) or library["kind"] not in {
                    "library", "sdk-component"}:
                raise _InvalidProposal("invalid library kind")
            _basis(library["basis"], self.bounds)
            refs = set(_strings(library["candidate_ids"], "library IDs", self.bounds, nonempty=True))
            paths = set(_strings(library["supporting_paths"], "library paths", self.bounds,
                                 nonempty=True))
            if not refs <= allowed:
                raise _InvalidProposal("library references unowned candidate IDs")
            owners = {ref: set(self.context[ref]["context_paths"]) for ref in refs}
            if (not paths <= set().union(*owners.values())
                    or any(not paths & owned for owned in owners.values())):
                raise _InvalidProposal("library paths are not exact accepted context for its IDs")
            for ref in refs:
                if (_normalized(self.sources[ref]["native_name"]) != _normalized(name)
                        and not _named_path(name, sorted(paths & owners[ref]))):
                    raise _InvalidProposal("renamed library lacks name-specific path evidence")
            key = _normalized(name)
            if key in named:
                raise _InvalidProposal("duplicate normalized library name")
            named[key] = dict(library)
            selected.update(refs)
        if list(named) != sorted(named):
            raise _InvalidProposal("libraries must be sorted by normalized name")
        if selected & (rejected | uncertain):
            raise _InvalidProposal("selected candidates cannot be rejected or uncertain")
        group_names = []
        for group in groups:
            if not isinstance(group, Mapping) or set(group) != {
                    "name", "component_names", "candidate_ids", "supporting_paths", "basis"}:
                raise _InvalidProposal("invalid SDK group fields")
            group_names.append(_normalized(_name(group["name"], self.bounds)))
            _basis(group["basis"], self.bounds)
            members = _strings(group["component_names"], "group components", self.bounds,
                               nonempty=True)
            keys = [_normalized(member) for member in members]
            if len(keys) < 2 or len(set(keys)) != len(keys) or not set(keys) <= named.keys():
                raise _InvalidProposal("SDK group must reference distinct selected components")
            if any(named[key]["kind"] != "sdk-component" for key in keys):
                raise _InvalidProposal("SDK group member must have sdk-component kind")
            refs = set(_strings(group["candidate_ids"], "group IDs", self.bounds, nonempty=True))
            paths = set(_strings(group["supporting_paths"], "group paths", self.bounds, nonempty=True))
            if (refs != {ref for key in keys for ref in named[key]["candidate_ids"]}
                    or paths != {path for key in keys for path in named[key]["supporting_paths"]}):
                raise _InvalidProposal("SDK group reference/path unions differ from members")
            if not self.coherent_group([named[key] for key in keys]):
                raise _InvalidProposal("prefix similarity lacks coherent SDK packaging context")
        if group_names != sorted(set(group_names)):
            raise _InvalidProposal("SDK groups must be sorted and unique")
        return {**proposal, "unaccounted": sorted(allowed - selected - rejected - uncertain)}

    def coherent_group(self, libraries: list[dict[str, Any]]) -> bool:
        common = set.intersection(*[
            {(self.domains[ref], self.sources[ref]["root_id"]) for ref in library["candidate_ids"]}
            for library in libraries
        ])
        if not common:
            return False
        for domain, root_id in sorted(common):
            shared_roots = set.intersection(*[
                {self.sources[ref]["package_root"] for ref in library["candidate_ids"]
                 if (self.domains[ref], self.sources[ref]["root_id"]) == (domain, root_id)}
                for library in libraries
            ])
            if any(root != "." and (PurePosixPath(root).name.casefold() == "sdk"
                                    or PurePosixPath(root).name.casefold() not in _GENERIC)
                   for root in shared_roots):
                return True
            directories = []
            for library in libraries:
                local_paths = {path for ref in library["candidate_ids"]
                               if (self.domains[ref], self.sources[ref]["root_id"]) == (domain, root_id)
                               for path in library["supporting_paths"]
                               if path in self.context[ref]["context_paths"]}
                directories.extend(PurePosixPath(path).parts[:-1] for path in local_paths)
            prefix = []
            for parts in zip(*directories):
                if len(set(parts)) != 1:
                    break
                prefix.append(parts[0])
            meaningful = any(part.casefold() not in _GENERIC for part in prefix)
            packaging = any(part.casefold() in {"include", "includes", "header", "headers", "sdk"}
                            or part.casefold().endswith(("-sdk", "_sdk", ".framework"))
                            for part in prefix)
            if meaningful and packaging:
                return True
        return False

    def apply(self, proposal: dict[str, Any], identifiers: list[str]) -> None:
        selected = set()
        for library in proposal["libraries"]:
            name = _normalized(library["name"])
            component_id = inference_identity("component", {"name": name})
            refs = library["candidate_ids"]
            if (component_id not in self.inferred_components
                    and len(self.inferred_components) >= self.bounds.component_limit):
                for ref in refs:
                    self.preserve(ref, f"component_limit omitted proposed component {name}", bound=True)
                continue
            self.add_component(name, library["kind"], refs, library["supporting_paths"],
                               library["basis"])
            self.inferred_components.add(component_id)
            selected.update(refs)
            for ref in refs:
                self.decisions.append({"candidate_id": ref, "decision": "selected",
                                       "component_id": component_id, "basis": library["basis"]})
        for identifier in sorted(selected):
            original = self.sources[identifier]
            selected_names = {_normalized(library["name"]) for library in proposal["libraries"]
                              if identifier in library["candidate_ids"]}
            protected = any(original[field]["status"] in {"corroborated", "conflicted"}
                            for field in ("identity", "release", "upstream"))
            specific = original["native_name"].casefold() not in _GENERIC and _named_path(
                original["native_name"], [PurePosixPath(path).name
                                          for path in self.context[identifier]["context_paths"]])
            if _normalized(original["native_name"]) not in selected_names and (protected or specific):
                self.preserve(identifier, "independently named or corroborated original retained")
        for identifier in proposal["rejected_candidate_ids"]:
            if any(self.sources[identifier][field]["status"] in {"corroborated", "conflicted"}
                   for field in ("identity", "release", "upstream")):
                self.preserve(identifier, "proposal cannot reject corroborated or conflicted original")
            else:
                self.excluded.add(identifier)
                self.decisions.append({"candidate_id": identifier, "decision": "rejected"})
        for identifier in proposal["uncertain_candidate_ids"]:
            self.preserve(identifier, "proposal marked input uncertain")
        for identifier in proposal["unaccounted"]:
            self.preserve(identifier, "proposal left input unaccounted")
        for group in proposal["sdk_groups"]:
            component_ids = sorted(inference_identity("component", {"name": _normalized(name)})
                                   for name in group["component_names"])
            group_id = inference_identity("sdk-group", {"name": _normalized(group["name"]),
                                                       "component_ids": component_ids})
            if not set(component_ids) <= self.components.keys():
                self.gap(group_id, "curation group omitted because member component was bounded",
                         bound=True)
                continue
            if group_id not in self.groups and len(self.groups) >= self.bounds.group_limit:
                self.gap(group_id, f"curation group_limit: omitted SDK group {group['name']}",
                         bound=True)
                continue
            previous = self.groups.get(group_id)
            self.groups[group_id] = {
                "group_id": group_id, "name": _normalized(group["name"]),
                "component_ids": component_ids,
                "supporting_paths": sorted(set(group["supporting_paths"])
                                           | set(previous["supporting_paths"] if previous else [])),
                "basis": min(previous["basis"], group["basis"]) if previous else group["basis"],
            }

    def batch(self, identifiers: list[str], propose: Propose | None) -> None:
        payload = self.payload(identifiers)
        if len(canonical_json(payload)) > self.bounds.max_payload_bytes:
            if len(identifiers) > 1:
                middle = len(identifiers) // 2
                self.batch(identifiers[:middle], propose)
                self.batch(identifiers[middle:], propose)
            else:
                self.preserve(identifiers[0], "max_payload_bytes omitted input context", bound=True)
            return
        if self.calls >= self.bounds.max_calls:
            for identifier in identifiers:
                self.preserve(identifier, "max_calls omitted input batch", bound=True)
            return
        if propose is None:
            for identifier in identifiers:
                self.preserve(identifier, "proposer unavailable")
            return
        self.calls += 1
        try:
            proposal = propose("curate", payload)
        except NativeInferenceError as exc:
            for identifier in identifiers:
                self.preserve(identifier, f"proposal failed ({exc.kind}): {exc}")
            return
        try:
            validated = self.validate(proposal, identifiers)
        except _InvalidProposal as exc:
            for identifier in identifiers:
                self.preserve(identifier, f"invalid proposal: {exc}")
            return
        self.apply(validated, identifiers)

    def finish(self) -> CurationResult:
        discovery = self.discovery
        memberships: dict[str, set[str]] = defaultdict(set)
        for group in self.groups.values():
            for component_id in group["component_ids"]:
                memberships[component_id].add(group["group_id"])
        for component_id, component in self.components.items():
            for identifier in component["candidate_ids"]:
                self.effective[identifier]["metadata"]["curation"]["sdk_group_ids"] = sorted(
                    memberships[component_id])
        discovery["candidates"] = sorted(self.effective.values(), key=lambda row: row["candidate_id"])
        discovery["evidence"] = [self.evidence[key] for key in sorted(self.evidence)]
        discovery["gaps"] = _unique([*discovery["gaps"], *self.gaps])
        for field in ("identity", "release"):
            prefix = "identities_" if field == "identity" else "releases_"
            for status in ("unknown", "inferred", "corroborated", "conflicted"):
                key = prefix + status
                discovery["metrics"][key] = sum(candidate[field]["status"] == status
                                                 for candidate in discovery["candidates"])
        discovery["metrics"]["candidates_total"] = len(discovery["candidates"])
        for key in discovery["metrics"].keys() & discovery["coverage"].keys():
            discovery["coverage"][key] = discovery["metrics"][key]
        metrics = {
            "input_candidates": len(self.sources), "curated_components": len(self.components),
            "sdk_groups": len(self.groups), "excluded_candidates": len(self.excluded),
            "uncertain_candidates": len(self.uncertain), "omitted_candidates": len(self.omitted),
            "omitted_files": len(self.omitted_files),
        }
        discovery["coverage"]["curation"] = {"schema": CURATION_SCHEMA, **metrics,
                                             "grouping_status": "inferred"}
        return {
            "schema": CURATION_SCHEMA, "discovery": discovery,
            "components": sorted(self.components.values(), key=lambda row: (row["name"],
                                                                           row["component_id"])),
            "sdk_groups": sorted(self.groups.values(), key=lambda row: (row["name"], row["group_id"])),
            "decisions": _unique(self.decisions), "gaps": _unique(self.gaps), "metrics": metrics,
        }


def curate_native_components(
    discovery: DiscoveryResult, files: Sequence[NativeFile], *,
    propose: Propose | None, bounds: NativeInferenceBounds,
) -> CurationResult:
    """Curate names and inferred SDK families without I/O or transport.

    The callback receives a detached, byte-bounded context and must return ``CURATION_SCHEMA``.
    Its ``input_records`` is the integer batch size; proposal references always use input IDs.
    Returned components instead reference effective, domain-local candidate IDs. Bounds limit
    inference, never the retention of conservative originals and corroborated claims.
    """
    if not isinstance(bounds, NativeInferenceBounds) or (propose is not None and not callable(propose)):
        raise ValueError("NativeInferenceBounds and a callable proposer (or None) are required")
    curation = _Curation(discovery, files, bounds)
    identifiers = sorted(curation.sources)
    eligible = []
    for identifier in identifiers:
        context = curation.make_context(identifier)
        if _oversized_field(context, bounds.field_bytes):
            curation.preserve(identifier, "field_bytes omitted oversized input context", bound=True)
        else:
            eligible.append(identifier)
    for offset in range(0, len(eligible), bounds.batch_candidates):
        curation.batch(eligible[offset:offset + bounds.batch_candidates], propose)
    return curation.finish()


__all__ = ["curate_native_components"]
