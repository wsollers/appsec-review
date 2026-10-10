"""Derive the SEI CERT source index from a local checkout of the official standards repository.

The SEI publishes its C, C++, Java, and Android standards from
``github.com/cmu-sei/secure-coding-standards``. This module reads only page metadata from a
reviewed local checkout: identifiers, official titles, chapter, canonical URL, CWE tags and
related-guideline links, named exception identifiers, and the C++ chapters' statements about
which CERT C rules also apply to C++. Standard prose and code examples are never copied.

The checkout is data. Nothing in it is executed, and the index records its exact commit and the
SHA-256 of every page used so each mapping resolves to the source it was derived from.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

SITE_ROOT = "https://cmu-sei.github.io/secure-coding-standards"
SOURCE_REPOSITORY = "https://github.com/cmu-sei/secure-coding-standards"

# content directory -> (inventory language, URL slug, identifier suffix pattern)
STANDARDS: dict[str, tuple[str, str, str]] = {
    "4.sei-cert-c-coding-standard": ("c", "sei-cert-c-coding-standard", r"-C"),
    "5.sei-cert-cpp-coding-standard": ("cpp", "sei-cert-cpp-coding-standard", r"-CPP"),
    "6.sei-cert-oracle-coding-standard-for-java": ("java", "sei-cert-oracle-coding-standard-for-java", r"-J"),
    "3.android-secure-coding-standard": ("android", "android-secure-coding-standard", r"(?:-[JXC])?"),
}

_HEADING = re.compile(r"^#\s+(?P<id>[A-Z]{3}\d{2}(?:-[A-Z]+)?)\.?\s+(?P<title>.+?)\s*$", re.MULTILINE)
_EXCEPTION = re.compile(r"\*\*\s*(?P<id>[A-Z]{3}\d{2}(?:-[A-Z]+)?-EX\d+)\s*[:.]?\s*\*\*")
_CWE_TAG = re.compile(r"^\s*-\s*cwe-(\d+)\s*$", re.MULTILINE)
_CWE_LINK = re.compile(r"cwe\.mitre\.org/data/definitions/(\d+)\.html")
_C_RULE_LINK = re.compile(r"\[(?P<id>[A-Z]{3}\d{2}-C)\.[^\]]*\]\(/sei-cert-c-coding-standard/rules/")
_NUMERIC_PREFIX = re.compile(r"^\d+\.")


def _strip_prefix(part: str) -> str:
    return _NUMERIC_PREFIX.sub("", part)


def _front_matter_tags(text: str) -> list[str]:
    if not text.startswith("---"):
        return []
    end = text.find("\n---", 3)
    block = text[3:end] if end > 0 else ""
    return sorted({line.strip()[2:].strip() for line in block.splitlines() if line.strip().startswith("- ")})


def _related_guidelines(text: str) -> str:
    match = re.search(r"^##\s+Related Guidelines\s*$", text, re.MULTILINE)
    if not match:
        return ""
    following = re.search(r"^##\s+(?!#)", text[match.end():], re.MULTILINE)
    return text[match.end(): match.end() + following.start()] if following else text[match.end():]


def _url(slug: str, relative: PurePosixPath) -> str:
    parts = [_strip_prefix(part) for part in relative.with_suffix("").parts]
    return f"{SITE_ROOT}/{slug}/{'/'.join(parts)}"


def _category(relative: PurePosixPath) -> str:
    chapter = _strip_prefix(relative.parts[1]) if len(relative.parts) > 2 else ""
    match = re.search(r"-([a-z]{3})$", chapter)
    return match.group(1).upper() if match else ""


def _rule_pages(content: Path, directory: str) -> list[Path]:
    rules = content / directory
    candidates = [path for path in rules.iterdir() if path.is_dir() and _strip_prefix(path.name) == "rules"]
    if len(candidates) != 1:
        raise ValueError(f"{directory}: expected exactly one rules directory")
    return sorted(path for path in candidates[0].rglob("*.md") if not path.name.endswith("index.md"))


def _c_rules_applying_to_cpp(content: Path) -> dict[str, str]:
    applies: dict[str, str] = {}
    root = content / "5.sei-cert-cpp-coding-standard"
    for index in sorted(_rule_pages_index(root)):
        text = index.read_text(encoding="utf-8")
        marker = text.find("also apply in C++")
        if marker < 0:
            continue
        for match in _C_RULE_LINK.finditer(text[marker:]):
            applies[match.group("id")] = index.relative_to(content).as_posix()
    return applies


def _rule_pages_index(root: Path) -> list[Path]:
    rules = next(path for path in root.iterdir() if path.is_dir() and _strip_prefix(path.name) == "rules")
    return [path for path in rules.rglob("*index.md")]


def _own_exceptions(identifier: str, text: str) -> list[str]:
    """Exceptions defined for this rule, without suffix-less aliases of a suffixed definition."""
    found = {value for value in _EXCEPTION.findall(text) if value[:5] == identifier[:5]}
    suffixed = {value for value in found if value.startswith(identifier + "-EX")}
    return sorted(value for value in found
                  if value in suffixed or f"{identifier}-{value.rsplit('-', 1)[1]}" not in suffixed)


def git_revision(checkout: Path) -> tuple[str, str]:
    def run(*argv: str) -> str:
        return subprocess.run(["git", "-C", str(checkout), *argv], check=True, capture_output=True,
                              text=True, timeout=30).stdout.strip()
    return run("rev-parse", "HEAD"), run("log", "-1", "--format=%cI")


def build_source_index(checkout: Path, *, retrieved: str) -> dict[str, Any]:
    """Return the deterministic source index for every rule page in the four standards."""
    content = checkout / "content"
    revision, committed = git_revision(checkout)
    applies_to_cpp = _c_rules_applying_to_cpp(content)
    entries: list[dict[str, Any]] = []
    for directory, (language, slug, suffix) in STANDARDS.items():
        for page in _rule_pages(content, directory):
            text = page.read_text(encoding="utf-8")
            heading = _HEADING.search(text)
            relative = PurePosixPath(page.relative_to(content / directory).as_posix())
            if heading is None or not re.fullmatch(r"[A-Z]{3}\d{2}" + suffix, heading.group("id")):
                continue
            tags = _front_matter_tags(text)
            if language != "android" and "rule" not in tags:
                continue
            identifier = heading.group("id")
            cwe_tags = {int(value) for value in _CWE_TAG.findall(text)}
            cwe_links = {int(value) for value in _CWE_LINK.findall(_related_guidelines(text))}
            entries.append({
                "key": identifier,
                "id": identifier,
                "language": language,
                "category": _category(relative) or identifier[:3],
                "title": heading.group("title").strip(),
                "url": _url(slug, relative),
                "source_path": page.relative_to(checkout).as_posix(),
                "source_sha256": hashlib.sha256(page.read_bytes()).hexdigest(),
                "cwe": [f"CWE-{value}" for value in sorted(cwe_tags | cwe_links)],
                # Only exceptions defined for this page's own rule; cross-references are excluded.
                "exceptions": _own_exceptions(identifier, text),
                "applies_to_cpp": (applies_to_cpp.get(identifier) is not None) if language == "c" else None,
                "applies_to_cpp_source": applies_to_cpp.get(identifier) if language == "c" else None,
                "development_status": "work-in-progress" if language == "android" else "published",
            })
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry["id"]] = counts.get(entry["id"], 0) + 1
    for entry in entries:
        if counts[entry["id"]] > 1:
            # The draft Android standard reuses some identifiers for different rules. Both pages are
            # kept and the collision is recorded rather than silently choosing one.
            if entry["language"] != "android":
                raise ValueError(f"duplicate CERT identifier in official source: {entry['id']}")
            entry["key"] = f"{entry['id']}@{entry['category']}"
            entry["source_identifier_conflict"] = True
    keys = [entry["key"] for entry in entries]
    if len(keys) != len(set(keys)):
        raise ValueError("official source identifiers could not be disambiguated")
    entries.sort(key=lambda item: (item["language"], item["key"]))
    return {
        "schema": "appsec-review/sei-cert-source-index/1",
        "authority": "Carnegie Mellon University Software Engineering Institute",
        "source_repository": SOURCE_REPOSITORY,
        "source_revision": revision,
        "source_committed_at": committed,
        "retrieved": retrieved,
        "site_root": SITE_ROOT,
        "url_resolution": ("Canonical URLs are derived from the official repository content path and its "
                           "published base path; live page resolution is verified separately when network "
                           "policy permits."),
        "license_note": "Metadata only. No CERT standard prose or examples are copied.",
        "entries": entries,
    }
