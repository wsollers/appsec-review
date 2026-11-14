"""Closed documentation metadata and offline Markdown checks; no runtime guidance loading."""

from __future__ import annotations

import html
import json
from pathlib import Path
import re
import unicodedata
from urllib.parse import unquote, urlsplit


KINDS = frozenset({
    "architecture", "operations", "process", "task", "walk", "review", "schema",
    "history", "generated",
})
SUBSYSTEMS = frozenset({
    "images and deployment", "target acquisition and build", "code intelligence",
    "scanners and evidence collection", "review inference and guidance",
    "runtime interchange", "reporting and metrics", "testing and operations", "overview",
})
FIELDS = frozenset({"title", "kind", "subsystem", "status", "jobs", "last reconciled"})
BLOCK = re.compile(
    r"<!-- generated:begin job=(job_[a-z0-9_]+) -->\n.*?<!-- generated:end -->",
    re.S,
)
HISTORICAL = re.compile(r"<!-- historical:begin -->.*?<!-- historical:end -->", re.S)
CODE_SPAN = re.compile(r"(?<!`)(`+)(?!`)([^`\n]+?)(?<!`)\1(?!`)")


def frontmatter(text: str) -> tuple[dict, str]:
    """Read the documented YAML subset: one-line scalars and JSON-style string lists."""
    if not text.startswith("---\n"):
        raise ValueError("missing YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError("unterminated YAML frontmatter")
    result = {}
    for line in text[4:end].splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.partition(":")
        if not separator or key not in FIELDS or key in result:
            raise ValueError(f"unknown or duplicate frontmatter key: {key}")
        raw = raw.strip()
        if not raw:
            raise ValueError(f"empty frontmatter value: {key}")
        value = json.loads(raw) if raw.startswith(('"', "[")) else raw
        if key == "jobs":
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError("jobs must be a one-line array of strings")
            if value != sorted(set(value)):
                raise ValueError("jobs must be sorted and unique")
        elif not isinstance(value, str):
            raise ValueError(f"frontmatter value must be text: {key}")
        result[key] = value
    return result, text[end + 5:]


def with_frontmatter(metadata: dict, body: str) -> str:
    lines = ["---"]
    lines.extend(f"{key}: {json.dumps(value, ensure_ascii=False)}"
                 for key, value in metadata.items())
    return "\n".join(lines) + "\n---\n" + body


def validate_frontmatter(metadata: dict, *, jobs: set[str], reconciled: str) -> None:
    required = FIELDS - {"jobs"}
    if required - metadata.keys():
        raise ValueError(f"missing frontmatter fields: {sorted(required - metadata.keys())}")
    if not metadata["title"].strip():
        raise ValueError("empty title")
    for field, allowed in (("kind", KINDS), ("subsystem", SUBSYSTEMS),
                           ("status", {"current", "historical"})):
        if metadata[field] not in allowed:
            raise ValueError(f"unknown {field}: {metadata[field]}")
    if metadata["last reconciled"] != reconciled:
        raise ValueError("last reconciled differs from docs/docs-sync.json")
    if set(metadata.get("jobs", [])) - jobs:
        raise ValueError("frontmatter names unknown jobs")


def prose(text: str, *, inline: bool = True, comments: bool = True) -> str:
    """Mask examples without losing line positions, including nested-length code fences."""
    lines = []
    fence = None
    for line in text.splitlines(keepends=True):
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence):
                fence = None
            lines.append("\n" if line.endswith("\n") else "")
        elif match:
            fence = match[1]
            lines.append("\n" if line.endswith("\n") else "")
        else:
            lines.append(line)
    value = "".join(lines)
    if comments:
        value = re.sub(r"<!--.*?-->", lambda m: "\n" * m[0].count("\n"), value, flags=re.S)
    if inline:
        value = re.sub(r"(`+)(?!`)(.*?)(?<!`)\1(?!`)",
                       lambda m: " " * len(m[0]), value, flags=re.S)
    return value


def slug(value: str) -> str:
    value = html.unescape(re.sub(r"<[^>]*>", "", value)).lower()
    value = re.sub(r"!?\[([^]]*)\]\([^)]*\)", r"\1", value)
    value = value.replace("`", "")
    value = "".join(char for char in value
                    if char in "_-" or char.isspace()
                    or unicodedata.category(char)[0] in {"L", "N"})
    return re.sub(r"\s+", "-", value.strip())


def anchors(text: str) -> set[str]:
    value = prose(text, inline=False)
    result = set(re.findall(r"<a\s+(?:[^>]*?\s)?(?:id|name)=[\"']([^\"']+)", value))
    counts = {}
    lines = value.splitlines()
    for index, line in enumerate(lines):
        heading = re.match(r"^\s{0,3}#{1,6}\s+(.+?)(?:\s+#+)?\s*$", line)
        title = heading[1] if heading else None
        if title is None and index + 1 < len(lines) and line.strip():
            if re.fullmatch(r"\s{0,3}(?:=+|-+)\s*", lines[index + 1]):
                title = line
        if title is None:
            continue
        base = slug(title)
        count = counts.get(base, 0)
        counts[base] = count + 1
        result.add(f"{base}-{count}" if count else base)
    return result


def links(text: str) -> list[str]:
    value = prose(text)
    references = {
        " ".join(match[1].lower().split()): match[2].strip("<>")
        for match in re.finditer(r"(?m)^\s{0,3}\[([^]]+)\]:\s*(<[^>]+>|\S+)", value)
    }
    result = []
    # Balanced destination parentheses support paths such as file_(draft).md.
    for match in re.finditer(r"!?\[([^\]\n]*)\](\(|\[[^\]\n]*\])?", value):
        suffix = match[2]
        if suffix == "(":
            start = match.end()
            depth, end = 1, start
            while end < len(value) and depth:
                char = value[end]
                if char == "\\":
                    end += 2
                    continue
                depth += (char == "(") - (char == ")")
                end += 1
            if depth:
                continue
            destination = value[start:end - 1].strip()
            if destination.startswith("<"):
                destination = destination.partition(">")[0][1:]
            else:
                destination = re.split(r"\s+[\"']", destination, maxsplit=1)[0]
            result.append(re.sub(r"\\([()])", r"\1", destination))
        else:
            if value[match.end():].startswith(":"):
                continue
            label = (suffix[1:-1] if suffix and suffix != "[]" else match[1])
            normalized = " ".join(label.lower().split())
            if normalized in references:
                result.append(references[normalized])
            elif suffix:
                result.append(f"unresolved-reference:{label}")
    return result


def link_errors(root: Path, documents: dict[str, str]) -> list[str]:
    errors = []
    cache = {}
    for path, text in sorted(documents.items()):
        _, body = frontmatter(text)
        for destination in links(body):
            if destination.startswith("unresolved-reference:"):
                errors.append(f"{path}: {destination}")
                continue
            parsed = urlsplit(destination)
            if parsed.scheme or parsed.netloc:
                continue
            relative = unquote(parsed.path)
            target = ((root / path).parent / relative).resolve() if relative else (root / path)
            if not target.is_relative_to(root.resolve()):
                errors.append(f"{path}: link escapes repository: {destination}")
                continue
            if not target.exists():
                errors.append(f"{path}: missing link: {destination}")
                continue
            if parsed.fragment and target.suffix == ".md":
                if target not in cache:
                    content = documents.get(target.relative_to(root).as_posix())
                    if content is None:
                        content = target.read_text(encoding="utf-8")
                    if content.startswith("---\n"):
                        _, content = frontmatter(content)
                    cache[target] = anchors(content)
                if unquote(parsed.fragment) not in cache[target]:
                    errors.append(f"{path}: missing anchor: {destination}")
    return sorted(set(errors))


def identifier_errors(text: str, inventory: dict, *, planning_registry: bool = False) -> list[str]:
    metadata, body = frontmatter(text)
    if metadata["status"] == "historical" or planning_registry:
        return []
    body = BLOCK.sub("", body)
    value = prose(body, inline=False, comments=False)
    value = CODE_SPAN.sub(
        lambda match: match[0].replace("<!-- historical:", "&lt;!-- historical:"), value)
    historical = list(HISTORICAL.finditer(value))
    if (value.count("<!-- historical:begin -->") != len(historical)
            or value.count("<!-- historical:end -->") != len(historical)
            or any(match[0].count("<!-- historical:begin -->") != 1 for match in historical)):
        raise ValueError("unbalanced or nested historical markers")
    value = HISTORICAL.sub("", value)
    value = re.sub(r"<!--.*?-->", "", value, flags=re.S)
    known = inventory["identifiers"]
    errors = []
    for match in CODE_SPAN.finditer(value):
        token = match[2]
        context = value[max(0, match.start() - 70):match.start()].lower()
        category = None
        if re.fullmatch(r"job_[a-z0-9_]+", token):
            if (token not in known.get("fields_and_functions", [])
                    and token not in inventory.get("unregistered_inputs", {})):
                category = "jobs"
        elif re.fullmatch(r"(?:appsec-review/)?[a-z][a-z0-9_/-]*/[1-9]\d*", token):
            category = "schemas"
        elif re.search(r"\b(?:task|unit)\s+$", context) and re.fullmatch(r"[a-z_]+\.[a-z_]+", token):
            category = "tasks"
        elif re.search(r"\bdataset\s+$", context) and re.fullmatch(r"[a-z_]+", token):
            category = "datasets"
        elif re.search(r"\bgap (?:cause|code)\s+$", context) and re.fullmatch(r"[a-z_]+", token):
            category = "gaps"
        if category and token not in known[category]:
            errors.append(f"unknown {category} identifier: {token}")
    return sorted(set(errors))


def authored_job_errors(text: str, job_id: str, job: dict) -> list[str]:
    """Check the authored page boundary; source accuracy remains a source-review obligation."""
    metadata, body = frontmatter(text)
    errors = []
    if metadata.get("jobs") != [job_id] or metadata.get("kind") != "operations":
        errors.append("canonical job page must name exactly its job")
    blocks = list(BLOCK.finditer(body))
    if len(blocks) != 1 or blocks[0][1] != job_id:
        errors.append("expected exactly one matching generated job block")
    authored = BLOCK.sub("", body)
    if "the authored process and acceptance description are tracked by" in authored:
        errors.append("generated-page placeholder has not been replaced")
    lines = authored.splitlines()
    visible = prose(authored, inline=False).splitlines()
    starts = [(index, match[1]) for index, line in enumerate(visible)
              if (match := re.fullmatch(r"## (.+)", line))]
    sections = {}
    for position, (start, name) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        if name in sections:
            errors.append(f"duplicate authored section: {name}")
        sections[name] = "\n".join(lines[start + 1:end]).strip()
    required = {"Purpose", "Process", "Dataflow", "Gaps", "Acceptance", "Resume and invalidation"}
    if job["model_configuration"] or job["specialized_workers"]:
        required.add("Model usage")
    for name in sorted(required):
        if not sections.get(name):
            errors.append(f"missing authored section: {name}")
    process = sections.get("Process", "")
    step_headers = list(re.finditer(r"(?m)^### `([^`]+)`\s*$", process))
    if {match[1] for match in step_headers} != set(job["steps"]):
        errors.append("Process must have one exact step heading per configured step")
    if len(step_headers) != len(job["steps"]):
        errors.append("Process repeats or omits a configured step")
    for position, match in enumerate(step_headers):
        end = step_headers[position + 1].start() if position + 1 < len(step_headers) else len(process)
        if not re.search(r"(?m)^\d+\. ", process[match.end():end]):
            errors.append(f"step lacks numbered pseudocode: {match[1]}")
    dataflow = sections.get("Dataflow", "")
    if "```mermaid" not in dataflow or job_id not in dataflow:
        errors.append("Dataflow must contain an authored Mermaid view naming the job")
    acceptance = sections.get("Acceptance", "")
    for label in ("A. Inputs", "B. Independent comparison", "C. Gaps", "D. Baseline"):
        if not re.search(rf"\*\*{re.escape(label)}:?\*\*", acceptance):
            errors.append(f"Acceptance must state the charter check: {label}")
    return errors
