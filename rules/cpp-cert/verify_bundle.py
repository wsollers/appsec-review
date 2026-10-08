#!/usr/bin/env python3
"""Verify the pinned C/C++ CERT rule assets without network access."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_sha256(path: Path) -> tuple[int, str]:
    files = sorted(item for item in path.rglob("*") if item.is_file())
    digest = hashlib.sha256()
    for item in files:
        relative = item.relative_to(path).as_posix().encode()
        digest.update(relative + b"\0" + sha256(item).encode() + b"\n")
    return len(files), digest.hexdigest()


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> int:
    lock = json.loads((ROOT / "bundle-lock.json").read_text(encoding="utf-8"))
    coverage = json.loads((ROOT / "coverage.json").read_text(encoding="utf-8"))
    if lock.get("schema") != "appsec-review/cpp-cert-rule-bundle-lock/1":
        fail("unexpected bundle-lock schema")
    if coverage.get("schema") != "appsec-review/cpp-cert-coverage/1":
        fail("unexpected coverage schema")

    for artifact in lock["artifacts"]:
        path = ROOT / artifact["path"]
        if artifact["kind"] == "file":
            actual = sha256(path)
        elif artifact["kind"] == "tree":
            count, actual = tree_sha256(path)
            if count != artifact["file_count"]:
                fail(f"{artifact['path']}: expected {artifact['file_count']} files, found {count}")
        else:
            fail(f"{artifact['path']}: unknown artifact kind")
        if actual != artifact["sha256"]:
            fail(f"{artifact['path']}: digest mismatch")

    queries = sorted((ROOT / "codeql/cert/rules").rglob("*.ql"))
    cert_rules = {item.parent.name for item in queries}
    inventory = coverage["inventory"]
    if len(queries) != inventory["codeql_queries"]:
        fail("CodeQL query inventory does not match coverage.json")
    if len(cert_rules) != inventory["codeql_cert_rules"]:
        fail("CodeQL CERT rule inventory does not match coverage.json")

    semgrep_text = (ROOT / "semgrep/cpp-cert-gap-rules.yml").read_text(encoding="utf-8")
    local_ids = set(re.findall(r"^\s*- id: (appsec-review\.cpp-cert\.[a-z0-9-]+)$", semgrep_text, re.MULTILINE))
    if len(local_ids) != inventory["local_semgrep_rules"]:
        fail("Semgrep rule inventory does not match coverage.json")

    seen_cert: set[str] = set()
    referenced_local: set[str] = set()
    for entry in coverage["priorities"]:
        cert = entry["cert"]
        if cert in seen_cert:
            fail(f"duplicate priority entry: {cert}")
        seen_cert.add(cert)
        for query in entry["codeql"]:
            if not (ROOT / query).is_file():
                fail(f"missing CodeQL query: {query}")
        referenced_local.update(entry["semgrep"])
    if referenced_local != local_ids:
        fail("coverage.json and the local Semgrep rule IDs differ")

    print(
        f"verified {len(queries)} CodeQL queries across {len(cert_rules)} CERT rules, "
        f"{len(local_ids)} local Semgrep rules, and {len(lock['artifacts'])} locked artifacts"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"rule bundle verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
