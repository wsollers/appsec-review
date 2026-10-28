"""Reproducible, opt-in acquisition of the supported English OWASP catalogs.

Only public pinned OWASP data is fetched. Nothing is executed. The lock contains the complete
upstream inventory and blob identities, independently of profile selection and assessment rules.
The reviewed inventory/content pins must change explicitly when an upstream revision or normalizer
changes. Updating a configured catalog hash alone never qualifies a different snapshot as complete.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
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
NORMALIZATION_CHANGES = "English record extraction and routing metadata; upstream text preserved."


@dataclass(frozen=True, slots=True)
class InventoryPin:
    tree_id: str
    source_count: int
    sources_sha256: str
    record_count: int
    ids_sha256: str
    records_sha256: str
    license_blob: str


# Reviewed acquisition locks, independent of catalog/configuration hashes. Changing an outer hash
# must not bless dropped IDs, altered upstream text, or invented routing/profile metadata.
INVENTORY_PINS = {
    "ASVS": InventoryPin(
        "ca24f0859050dd1008e8d62b2d576c6eefedc8d4", 1,
        "8e67cd6c83e985de01b2ddd571bbcb7af79c574c5faca1ce58de3370e36dab4f", 345,
        "bea1f8542150ce789c44f0fd5d03a3d6f6df3b4b1e131626cf97ff978f7d4cce",
        "6b8a50a627da090d5ae2ac8f715cb75ad980806fdf33de915b56c1fdce5a8522",
        "2d58298e6eda10e7204abb52722efbc840db2390"),
    "MASVS": InventoryPin(
        "790d1c3bfe88a2aff402d7041eac815075aec136", 24,
        "3fe2404774a979c30f4749a43787e22837bf1a395b9bc629ec2b93b23a0f0fb9", 24,
        "61debc6cc6d4eb8de5e94746768b14f01119ef72f88eed7a9a302c3214914825",
        "a3bbeda1890fd9f63006a5569ae80161329b031d33afd9fab0f706edbaee4dcb",
        "9c3961efe4cad0b29cd49bbeb06ae4b66f9cc027"),
    "MASTG": InventoryPin(
        "ed5ddbfd4d50ee95c693fc7588792a20c3286819", 292,
        "04704fb09f16eb7865c6bfb6140fea3d86999f93e1173001dfb4bfee3996f08e", 292,
        "407fad30e847ed796ff21fdaa054e7d70570c9c36e816c67d3ee7ce36afbfa30",
        "f3791eba26dfbc322ae1244ded5f63c0ad4b03357f0a42cecb6f984a6ed260f0",
        "bf3f89d72ab3ae01eb8e06c24b80a1be4ca169d2"),
    "OWASP_API_TOP_10": InventoryPin(
        "4b3e6f55b6fca93f3cdbfeab726e65f7aa4710aa", 10,
        "6bdcb88d1d6c3cef506fbbf88bca8cc5c2dc2a8756f244212cd51956fede4fd5", 10,
        "0880d174c84c5724fec1ec790f84210b256b4d7e54f74c39066f4dcdfd4b1556",
        "0c6b0538ee5413c17f69edf6f546583e13a5c8f33b0312e6531498ce5cb0963e",
        "2660aada441d3271b820138d6848166de670bcf5"),
    "OWASP_TOP_10": InventoryPin(
        "c1844adf5884e0fd2230953eee3b97cc9c565292", 10,
        "79478b46b275f23e9263569e81c652c43f0b7c56af4d51ba8df44b1dd8d38441", 10,
        "569b7fc1024011931a8ea4051fc81209364f7a7007cc4814c252302f7b951c47",
        "d1b654196f27064990b72408cda5d6158f04ebdfca20a672430913b25c7ab86d",
        "73cad4dc2aac1d217ae4ae5ce8b5dbe762eec7b8"),
}


def validate_complete_catalog(document: Mapping[str, Any]) -> None:
    """Verify a full snapshot against reviewed pins, not self-declared completeness.

    The raw API-response hash is capture metadata, not a Git tree identity. Tree membership,
    exact source bytes, IDs and deterministic normalized content have independent lock pins.
    """
    family = document["family"]
    repo, commit, version, ref, license_path, pattern = PINS[family]
    pin = INVENTORY_PINS[family]
    if (document.get("fixture") is not False or document.get("version") != version
            or document.get("authority") != SUPPORTED_FAMILIES[family]
            or document.get("upstream") != {
                "repository": f"https://github.com/{repo}", "commit": commit,
                "ref": ref, "license": "CC-BY-SA-4.0"}):
        raise ValueError(f"{family} complete catalog differs from the supported upstream identity")
    acquisition = document.get("acquisition")
    if (not isinstance(acquisition, Mapping)
            or acquisition.get("normalizer") != NORMALIZER
            or acquisition.get("tree_commit") != commit
            or acquisition.get("tree_id") != pin.tree_id
            or not re.fullmatch(r"[0-9a-f]{64}", str(acquisition.get("tree_sha256", "")))
            or acquisition.get("path_pattern") != pattern
            or acquisition.get("language") != "en"
            or acquisition.get("completeness") != "complete"
            or acquisition.get("exclusions") != []):
        raise ValueError(f"{family} complete catalog lacks a supported pinned acquisition")
    records = document.get("records")
    declared = acquisition.get("declared_ids")
    if (not isinstance(records, list) or len(records) != pin.record_count
            or any(not isinstance(record, Mapping) or not isinstance(record.get("id"), str)
                   for record in records)
            or not isinstance(declared, list) or len(declared) != pin.record_count
            or declared != sorted(record["id"] for record in records)
            or digest(declared) != pin.ids_sha256
            or acquisition.get("declared_ids_sha256") != pin.ids_sha256):
        raise ValueError(f"{family} catalog differs from the pinned upstream ID inventory")
    if (digest(records) != pin.records_sha256
            or acquisition.get("normalized_records_sha256") != pin.records_sha256):
        raise ValueError(f"{family} catalog differs from the pinned normalized records")
    inventory = acquisition.get("sources")
    if (not isinstance(inventory, Mapping) or len(inventory) != pin.source_count
            or digest(inventory) != pin.sources_sha256):
        raise ValueError(f"{family} catalog differs from the pinned source inventory")
    used = set()
    for record in records:
        source = record.get("source")
        if not isinstance(source, Mapping):
            raise ValueError(f"{family} record lacks resolving acquisition provenance")
        path = source.get("path")
        if (not isinstance(path, str) or path not in inventory or not re.fullmatch(pattern, path)
                or inventory[path] != {key: source.get(key) for key in ("git_blob", "sha256")}):
            raise ValueError(f"{family} record lacks resolving acquisition provenance")
        used.add(path)
    if used != set(inventory):
        raise ValueError(f"{family} catalog source inventory is not fully represented")
    distribution = document.get("distribution")
    if (not isinstance(distribution, Mapping)
            or distribution.get("attribution") != f"OWASP {family} contributors; {repo}@{commit}"
            or distribution.get("changes") != NORMALIZATION_CHANGES
            or distribution.get("license_url") != "https://creativecommons.org/licenses/by-sa/4.0/"
            or distribution.get("license_source") != {
                "path": license_path, "git_blob": pin.license_blob}
            or not isinstance(distribution.get("license_text"), str)
            or _blob(distribution["license_text"].encode("utf-8")) != pin.license_blob):
        raise ValueError(f"{family} catalog distribution attribution or pinned license is incomplete")


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
    if family not in PINS:
        raise ValueError(f"unsupported OWASP family: {family}")
    records: list[dict[str, Any]] = []
    for path, data in sorted(files.items()):
        if not re.fullmatch(PINS[family][5], path):
            raise ValueError(f"{family} source path is outside the pinned inventory: {path}")
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
            native = PurePosixPath(path).stem
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
                "id": PurePosixPath(path).stem, "title": str(metadata["title"]), "text": text,
                "supports": list(metadata.get("masvs_v2_id") or ()),
                "profiles": list(metadata.get("profiles") or ()),
                "status": metadata.get("status", "unspecified"), "source": source,
            })
        else:
            title = next((line.lstrip("# ").strip() for line in text.splitlines()
                          if line.startswith("# ")), PurePosixPath(path).stem)
            native = ("API" + str(int(PurePosixPath(path).name[3], 16)) + ":2023"
                      if family == "OWASP_API_TOP_10" else PurePosixPath(path).name[:3] + ":2025")
            records.append({"id": native, "title": title, "text": text, "source": source})
    ids = [row["id"] for row in records]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError(f"{family} upstream inventory is empty or duplicated")
    return sorted(records, key=lambda row: row["id"])


def acquire(family: str, destination: Path, *, read=_read) -> dict[str, Any]:
    if family not in PINS:
        raise ValueError(f"unsupported OWASP family: {family}")
    repo, commit, version, ref, license_path, pattern = PINS[family]
    pin = INVENTORY_PINS[family]
    revision = json.loads(read(f"https://api.github.com/repos/{repo}/git/commits/{commit}"))
    if revision.get("sha") != commit:
        raise ValueError("OWASP commit differs from immutable pin")
    tree_id = revision["tree"]["sha"]
    if tree_id != pin.tree_id:
        raise ValueError("OWASP commit tree differs from the immutable pin")
    tree_bytes = read(f"https://api.github.com/repos/{repo}/git/trees/{tree_id}?recursive=1")
    tree = json.loads(tree_bytes)
    if tree.get("truncated") is not False or tree.get("sha") != tree_id:
        raise ValueError("OWASP upstream tree is truncated or differs from the immutable pin")
    entries = tree.get("tree")
    if (not isinstance(entries, list) or any(
            not isinstance(row, Mapping) or not isinstance(row.get("path"), str)
            or row.get("type") not in {"blob", "tree", "commit"}
            or not re.fullmatch(r"[0-9a-f]{40}", str(row.get("sha", ""))) for row in entries)
            or len({row["path"] for row in entries}) != len(entries)):
        raise ValueError("OWASP upstream tree inventory is invalid or duplicated")
    selected = {row["path"]: row["sha"] for row in entries
                if row["type"] == "blob" and re.fullmatch(pattern, row["path"])}
    if len(selected) != pin.source_count:
        raise ValueError("OWASP source inventory differs from the pinned source count")
    licenses = [row for row in entries if row["path"] == license_path and row["type"] == "blob"]
    if len(licenses) != 1 or licenses[0]["sha"] != pin.license_blob:
        raise ValueError("OWASP upstream license differs from the immutable pin")
    license_blob = pin.license_blob

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
            "changes": NORMALIZATION_CHANGES,
            "license_url": "https://creativecommons.org/licenses/by-sa/4.0/",
            "license_source": {"path": license_path, "git_blob": license_blob},
            "license_text": license_text,
        },
        "records": records,
    }
    validate_complete_catalog(document)
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
