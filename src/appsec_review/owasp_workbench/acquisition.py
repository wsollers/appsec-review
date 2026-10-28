"""Reproducible, opt-in acquisition of the supported English OWASP catalogs.

Only public pinned OWASP data is fetched. Nothing is executed. The lock contains the complete
upstream inventory and blob identities, independently of profile selection and assessment rules.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.request import Request, urlopen

from appsec_review.storage import atomic_json
from .standards import CATALOG_SCHEMA, SUPPORTED_FAMILIES, digest


PINS = {
    "ASVS": ("OWASP/ASVS", "5cf9b032440be53ce345ab3c130fda46ba1ce7a2", "5.0.0",
             "v5.0.0_release", "LICENSE.md",
             r"5\.0/docs_en/OWASP_Application_Security_Verification_Standard_5\.0\.0_en\.json"),
    "MASVS": ("OWASP/owasp-masvs", "8e133d09f4140518ed04cc254b18be9ff4990ffc", "2.1.0",
              "v2.1.0", "License.md", r"controls/MASVS-[A-Z]+-\d+\.md"),
    "MASTG": ("OWASP/owasp-mastg", "990472dbcffe126f5556045d60270c4ffdfdde72", "2.0.0",
              "v2.0.0", "License.md", r"tests(?:-beta)?/(?:android|ios)/[^/]+/MASTG-TEST-\d+\.md"),
    "OWASP_API_TOP_10": ("OWASP/API-Security", "e85ddfa5a936d4656840ac250c039c7057e66b0d", "2023",
                         "2023", "LICENSE", r"editions/2023/en/0xa[1-9a]-[^/]+\.md"),
    "OWASP_TOP_10": ("OWASP/Top10", "66ebc4798d2ca72973967a20264bdeb70dcf0a13", "2025",
                     "2025", "LICENSE", r"2025/docs/en/A\d\d_2025-[^/]+\.md"),
}
NORMALIZER = "owasp-english-catalog/1"


def _read(url: str) -> bytes:
    with urlopen(Request(url, headers={"User-Agent": "appsec-review-catalog-acquisition/1"}),
                 timeout=60) as response:
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("OWASP source exceeds acquisition byte bound")
    return data


def _blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def normalize(family: str, files: Mapping[str, bytes]) -> list[dict[str, Any]]:
    """Translate only declared upstream records, never synthesize control text."""
    records: list[dict[str, Any]] = []
    for path, data in sorted(files.items()):
        text = data.decode("utf-8-sig")
        source = {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "git_blob": _blob(data)}
        if family == "ASVS":
            document = json.loads(text)
            if document["Version"] != PINS[family][2]:
                raise ValueError("ASVS upstream version differs from pin")
            for chapter in document["Requirements"]:
                domain = {
                    "V6": "authentication_session", "V7": "authentication_session",
                    "V8": "authorization_access_control", "V11": "cryptography_data_protection",
                    "V14": "cryptography_data_protection", "V15": "build_supply_chain",
                }.get(chapter["Shortcode"], "api_web")
                for section in chapter["Items"]:
                    for item in section["Items"]:
                        level = int(item["L"])
                        records.append({
                            "id": item["Shortcode"], "title": section["Name"],
                            "text": item["Description"], "levels": list(range(level, 4)),
                            "domain": domain, "component_roles": [], "evidence_mode": "static_source",
                            "required_tools": ["find", "read_excerpt"], "source": source,
                        })
        elif family == "MASVS":
            native = Path(path).stem
            match = re.search(r"(?ms)^## Control\s*\n(.*?)(?=^## |\Z)", text)
            if match is None or not match[1].strip():
                raise ValueError(f"MASVS source lacks a control: {path}")
            records.append({
                "id": native, "title": native, "text": match[1].strip(), "description": text,
                # MASVS 2 removed verification levels. L1/L2 are local selection aliases for ALL
                # controls, not upstream certification profiles.
                "profiles": ["L1", "L2"], "profile_basis": "all-controls; MASVS 2 has no levels",
                "domain": "mobile_platform", "component_roles": [],
                "evidence_mode": "static_source", "required_tools": ["find", "read_excerpt"],
                "source": source,
            })
        elif family == "MASTG":
            import yaml
            if not text.startswith("---"):
                raise ValueError(f"MASTG source lacks metadata: {path}")
            metadata = yaml.safe_load(text.split("---", 2)[1])
            records.append({
                "id": Path(path).stem, "title": str(metadata["title"]), "text": text,
                "supports": list(metadata.get("masvs_v2_id") or ()),
                "profiles": list(metadata.get("profiles") or ()),
                "status": metadata.get("status", "unspecified"), "source": source,
            })
        else:
            title = next((line.lstrip("# ").strip() for line in text.splitlines()
                          if line.startswith("# ")), Path(path).stem)
            native = ("API" + str(int(Path(path).name[3], 16)) + ":2023"
                      if family == "OWASP_API_TOP_10" else Path(path).name[:3] + ":2025")
            records.append({"id": native, "title": title, "text": text, "source": source})
    ids = [row["id"] for row in records]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError(f"{family} upstream inventory is empty or duplicated")
    return sorted(records, key=lambda row: row["id"])


def acquire(family: str, destination: Path, *, read=_read) -> dict[str, Any]:
    repo, commit, version, ref, license_path, pattern = PINS[family]
    revision = json.loads(read(f"https://api.github.com/repos/{repo}/git/commits/{commit}"))
    if revision.get("sha") != commit:
        raise ValueError("OWASP commit differs from immutable pin")
    tree_id = revision["tree"]["sha"]
    tree_bytes = read(f"https://api.github.com/repos/{repo}/git/trees/{tree_id}?recursive=1")
    tree = json.loads(tree_bytes)
    if tree.get("truncated") or tree.get("sha") != tree_id:
        raise ValueError("OWASP upstream tree is truncated or differs from the immutable pin")
    selected = {row["path"]: row["sha"] for row in tree["tree"]
                if row["type"] == "blob" and re.fullmatch(pattern, row["path"])}
    if not selected or len(selected) > 2000:
        raise ValueError("OWASP source inventory is empty or exceeds acquisition bound")
    license_blob = next(row["sha"] for row in tree["tree"] if row["path"] == license_path)

    def fetch(path: str) -> tuple[str, bytes]:
        data = read(f"https://raw.githubusercontent.com/{repo}/{commit}/{path}")
        if _blob(data) != ({**selected, license_path: license_blob})[path]:
            raise ValueError(f"OWASP upstream blob integrity mismatch: {path}")
        return path, data

    with ThreadPoolExecutor(max_workers=4) as pool:
        files = dict(pool.map(fetch, [*sorted(selected), license_path]))
    license_text = files.pop(license_path).decode("utf-8-sig")
    if not re.search(r"(?i)(Attribution.ShareAlike 4\.0|by-sa/4\.0)", license_text):
        raise ValueError(f"{family} license needs separate review; no catalog was published")
    records = normalize(family, files)
    inventory = {path: {"git_blob": selected[path], "sha256": hashlib.sha256(data).hexdigest()}
                 for path, data in sorted(files.items())}
    document = {
        "schema": CATALOG_SCHEMA, "family": family, "version": version,
        "authority": SUPPORTED_FAMILIES[family], "fixture": False,
        "upstream": {"repository": f"https://github.com/{repo}", "commit": commit,
                     "ref": ref, "license": "CC-BY-SA-4.0"},
        "acquisition": {
            "normalizer": NORMALIZER, "tree_sha256": hashlib.sha256(tree_bytes).hexdigest(),
            "tree_commit": commit, "tree_id": tree_id, "path_pattern": pattern, "sources": inventory,
            "declared_ids": [row["id"] for row in records],
            "declared_ids_sha256": digest([row["id"] for row in records]),
            "normalized_records_sha256": digest(records), "completeness": "complete",
            "exclusions": [], "language": "en",
        },
        "distribution": {
            "attribution": f"OWASP {family} contributors; {repo}@{commit}",
            "changes": "English record extraction and routing metadata; upstream text preserved.",
            "license_url": "https://creativecommons.org/licenses/by-sa/4.0/",
            "license_source": {"path": license_path, "git_blob": license_blob},
            "license_text": license_text,
        },
        "records": records,
    }
    atomic_json(destination, document)
    return {"catalog_path": destination.as_posix(), "catalog_sha256": digest(document),
            "version": version, **document["upstream"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", choices=tuple(PINS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(acquire(args.family, args.output), indent=2))


if __name__ == "__main__":
    main()
