"""Acceptance tests for gap punch list P41 (appsec-multi-vuln case-081/082, 2026-10-03): base images were
inventoried as FROM text only, so an end-of-life base with vulnerable OS packages yielded no component,
and ``repo:tag@sha256:...`` put the tag into ``repository``.

Offline: the registry is an in-memory fake behind the cache's transport seam, and the image layers are
tiny tarballs built from tests/fixtures/gap-punchlist/baseimages/layers/.

See docs/TODO/gap-punchlist-hello-autotools-2026-10-03.md.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import registry_paths  # noqa: E402,F401

import validate_job_output as validator  # noqa: E402
import vendor_evidence_workers as workers  # noqa: E402
from schema_validate import validate_document  # noqa: E402

try:
    import base_image_cache as cache  # noqa: E402
except ImportError:
    cache = None

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "gap-punchlist" / "baseimages"
EOL_TABLE = ROOT.parent / "data" / "base-image-eol.json"
JOB = "02-iac-config-scan"
NOW = "2026-10-03T00:00:00Z"
CASE_081 = "sha256:0cee610aaf530adfbddf9ce6e679d57c67882f37b6aeaac1ce027e1e13dad4d5"
CASE_082 = "sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"
INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def layer(files: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name); info.size = len(data); info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def tree(name: str) -> dict[str, bytes]:
    base = FIXTURE / "layers" / name
    return {p.relative_to(base).as_posix(): p.read_bytes() for p in sorted(base.rglob("*")) if p.is_file()}


class FakeRegistry:
    """OCI distribution API for one repository: anonymous bearer token (the Docker Hub dance), an image
    index with an arm64 manifest listed before the amd64 one, and blobs redirected to a CDN that rejects
    a forwarded Authorization header."""

    def __init__(self, repository: str, tag: str, layers: list[bytes], *, serve_as: str | None = None):
        self.repository, self.blobs, self.calls = repository, {}, []
        config = json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers"}}).encode()
        self.blobs[sha(config)] = config
        for data in layers:
            self.blobs[sha(data)] = data
        manifest = json.dumps({"schemaVersion": 2, "mediaType": MANIFEST,
                               "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                                          "digest": sha(config), "size": len(config)},
                               "layers": [{"mediaType": LAYER, "digest": sha(d), "size": len(d)} for d in layers]}).encode()
        other = json.dumps({"schemaVersion": 2, "mediaType": MANIFEST, "config": {"digest": sha(b"x"), "size": 1},
                            "layers": []}).encode()
        index = json.dumps({"schemaVersion": 2, "mediaType": INDEX, "manifests": [
            {"mediaType": MANIFEST, "digest": sha(other), "size": len(other),
             "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"}},
            {"mediaType": MANIFEST, "digest": sha(manifest), "size": len(manifest),
             "platform": {"architecture": "amd64", "os": "linux"}}]}).encode()
        self.manifests = {sha(manifest): manifest, sha(other): other, sha(index): index, tag: index}
        if serve_as:
            self.manifests[serve_as] = index
        self.index_digest, self.manifest_digest = sha(index), sha(manifest)

    def __call__(self, method: str, url: str, headers: dict[str, str]):
        self.calls.append(url)
        if url.startswith("https://auth.docker.io/token?"):
            self.assert_scope = url
            return 200, {"content-type": "application/json"}, json.dumps({"token": "anon"}).encode()
        if url.startswith("https://cdn.example/"):
            if "Authorization" in headers:
                return 400, {}, b"two auth mechanisms"
            return 200, {}, self.blobs[url.rsplit("/", 1)[1]]
        prefix = f"https://registry-1.docker.io/v2/{self.repository}/"
        if not url.startswith(prefix):
            return 404, {}, b""
        if headers.get("Authorization") != "Bearer anon":
            return 401, {"www-authenticate": 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",'
                                             f'scope="repository:{self.repository}:pull"'}, b""
        kind, _, ref = url[len(prefix):].partition("/")
        if kind == "manifests" and ref in self.manifests:
            body = self.manifests[ref]
            return 200, {"content-type": json.loads(body)["mediaType"], "docker-content-digest": sha(body)}, body
        if kind == "blobs" and ref in self.blobs:
            return 307, {"location": "https://cdn.example/blob/" + ref}, b""
        return 404, {}, b""


class BaseImageTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.cache_root = self.folder / "base-images"

    def source(self, files: dict[str, str]) -> Path:
        root = self.folder / "source"
        for name, text in files.items():
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
        return root

    def documents(self, root: Path) -> dict:
        return workers.build_documents(JOB, root, run_id="run-p41", attempt_id="attempt-p41",
                                       source_snapshot_sha256="sha256:" + "a" * 64,
                                       base_image_root=self.cache_root, now=NOW)

    def debian(self, *, serve_as=None) -> FakeRegistry:
        status = tree("debian-10")["var/lib/dpkg/status"]
        upgrade = status + b"\nPackage: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 7.64.0-4\n"
        return FakeRegistry("library/debian", "buster-20190708-slim",
                            [layer(tree("debian-10")), layer({"var/lib/dpkg/status": upgrade,
                                                              "etc/.wh.motd": b""})], serve_as=serve_as)

    def test_p41_from_reference_splits_repository_tag_and_digest(self):
        """P41: ``repo:tag@digest`` keeps the tag out of ``repository``; flags and stage aliases are not images."""
        root = self.source({"case-081/Dockerfile": (FIXTURE / "case-081/Dockerfile").read_text(),
                            "case-082/Dockerfile": (FIXTURE / "case-082/Dockerfile").read_text(),
                            "multi/Dockerfile": "FROM --platform=linux/amd64 registry.example:5000/team/base:1.2 AS build\n"
                                                "FROM build\nFROM scratch\n"})
        records = workers._scan_base_images(root, ["case-081/Dockerfile", "case-082/Dockerfile", "multi/Dockerfile"])
        got = [(r["reference_form"], r["repository"], r["tag"], r["digest"]) for r in records]
        self.assertEqual(got, [("literal", "debian", "buster-20190708-slim", CASE_081),
                               ("literal", "alpine", "3.24.2", CASE_082),
                               ("literal", "registry.example:5000/team/base", "1.2", None),
                               ("build-stage-alias", None, None, None), ("scratch", None, None, None)])
        self.assertEqual([r["mutable"] for r in records], [False, False, True, None, None])

    def test_p41_unfetched_image_is_a_gap_not_an_empty_inventory(self):
        """P41: a base image absent from the host cache is unresolved, and the inventory tool is partial with a named gap."""
        self.assertIsNotNone(cache, "P41: no host-side base-image cache module")
        root = self.source({"case-081/Dockerfile": (FIXTURE / "case-081/Dockerfile").read_text()})
        image = self.documents(root)["base-image-inventory.json"]["base_images"][0]
        self.assertEqual((image["resolution"]["status"], image["resolution"]["reason"]), ("unresolved", "cache-unavailable"))
        cache.publish_refs(self.cache_root, {}, NOW)
        documents = self.documents(root)
        image = documents["base-image-inventory.json"]["base_images"][0]
        self.assertEqual((image["resolution"]["status"], image["resolution"]["reason"]), ("unresolved", "not-in-cache"))
        self.assertEqual(image["package_inventory"]["status"], "not-inventoried")
        self.assertEqual(image["components"], [])
        gaps = {g["gap_id"]: g["kind"] for g in documents["coverage.json"]["gaps"]}
        self.assertEqual(gaps.get("gap-dockerfile-base-image-inventory-base-images-unresolved"), "tool-instance-partial")
        self.assertEqual(documents["status"], "OK_WITH_GAPS")
        self.assertEqual(self.validated(root), [])

    def test_p41_eol_debian_base_is_inventoried_from_the_cache(self):
        """P41: a digest-pinned Debian 10 base resolves on the host, is inventoried offline from its dpkg
        database as pkg:deb components, is flagged end-of-life from the pinned table, and validates."""
        self.assertIsNotNone(cache, "P41: no host-side base-image cache module")
        registry = self.debian()
        token = f"debian:buster-20190708-slim@{registry.index_digest}"
        refs = cache.fetch([token], self.cache_root, transport=registry, now=NOW)
        self.assertEqual([e["status"] for e in refs["entries"].values()], ["resolved"])
        root = self.source({"Dockerfile": f"FROM {token}\n"})
        documents = self.documents(root)
        image = documents["base-image-inventory.json"]["base_images"][0]
        self.assertEqual(image["resolution"]["status"], "resolved")
        self.assertEqual(image["resolution"]["resolved"]["manifest"], {"digest": registry.manifest_digest})
        self.assertEqual(image["resolution"]["resolved"]["platform"], "linux/amd64")
        self.assertFalse(image["mutable"])
        purls = {c["purl"] for c in image["components"]}
        self.assertIn("pkg:deb/debian/zlib1g@1:1.2.11.dfsg-1?arch=amd64&distro=debian-10", purls)
        self.assertIn("pkg:deb/debian/apt@1.8.2?arch=amd64&distro=debian-10", purls)
        self.assertIn("pkg:deb/debian/curl@7.64.0-4?arch=amd64&distro=debian-10", purls)  # upper layer wins
        self.assertFalse(any("removed-tool" in p for p in purls))
        zlib = next(c for c in image["components"] if c["name"] == "zlib1g")
        self.assertEqual(zlib["source_package"], "zlib")
        system = image["operating_system"]
        self.assertEqual((system["id"], system["version_id"]), ("debian", "10"))
        self.assertEqual((system["eol_status"], system["eol"]["support_end"]), ("end-of-life", "2024-06-30"))
        self.assertTrue(system["eol"]["source_url"].startswith("https://"))
        tool = next(i for i in documents["tool-results.json"]["tool_instances"]
                    if i["tool_id"] == "dockerfile-base-image-inventory")
        self.assertEqual(tool["terminal_status"], "OK")
        self.assertEqual(validate_document(documents["base-image-inventory.json"],
                                           "iac-config-base-image-inventory.schema.json"), [])
        self.assertEqual(self.validated(root), [])

    def validated(self, root: Path) -> list[str]:
        """Materialize through the redactor and run the real V06 contract verifier."""
        run = self.folder / "run-p41"
        attempt = run / "data/jobs" / JOB / "whole/attempts" / f"attempt-p41-{len(list(self.folder.rglob('attempt-p41-*')))}"
        documents = workers.build_documents(JOB, root, run_id="run-p41", attempt_id=attempt.name,
                                            source_snapshot_sha256=self.source_sha(run),
                                            base_image_root=self.cache_root, now=NOW)
        workers.materialize_attempt(documents, attempt, dagster_run_id="dagster-p41",
                                    started_at="2026-10-03T00:00:00Z", finished_at="2026-10-03T00:00:01Z")
        contract = json.loads(registry_paths.contract(workers.SPECS[JOB][0]).read_text())
        errors = validator.validate_vendor_prepass_attempt(attempt, contract, run_id="run-p41", job_id=JOB,
            attempt_id=attempt.name, node_status=documents["status"], orchestration=validator.OrchestrationFacts(
                "dagster-p41", self.source_sha(run), validator.datetime.fromisoformat("2026-10-03T00:00:00+00:00")))
        return errors

    def source_sha(self, run: Path) -> str:
        manifest = run / "inputs" / "artifact-manifest.json"
        if not manifest.exists():
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes(json.dumps({"run_id": "run-p41"}, sort_keys=True).encode() + b"\n")
        return sha(manifest.read_bytes())

    def test_p41_tag_only_reference_is_mutable_and_records_resolved_digest(self):
        """P41: a tag-only reference resolves on the host to a digest; the record says it was mutable."""
        self.assertIsNotNone(cache, "P41: no host-side base-image cache module")
        registry = FakeRegistry("library/alpine", "3.24.2", [layer(tree("alpine-3.24"))])
        cache.fetch(["alpine:3.24.2"], self.cache_root, transport=registry, now=NOW)
        documents = self.documents(self.source({"Dockerfile": "FROM alpine:3.24.2\n"}))
        image = documents["base-image-inventory.json"]["base_images"][0]
        self.assertTrue(image["mutable"])
        self.assertEqual((image["resolution"]["status"], image["resolution"]["resolved"]["index"]),
                         ("resolved", {"digest": registry.index_digest}))
        self.assertEqual(image["resolution"]["resolved"]["at"], NOW)
        self.assertIn("pkg:apk/alpine/musl@1.2.5-r10?arch=x86_64&distro=alpine-3.24.2",
                      {c["purl"] for c in image["components"]})
        self.assertEqual(image["operating_system"]["eol_status"], "supported")

    def test_p41_registry_content_not_matching_the_pinned_digest_is_refused(self):
        """P41: the cache is content-addressed; a registry answer for case-081's digest that does not hash
        to it is a fetch failure and the image stays an explicit gap."""
        self.assertIsNotNone(cache, "P41: no host-side base-image cache module")
        token = (FIXTURE / "case-081/Dockerfile").read_text().split("FROM ", 1)[1].split()[0]
        refs = cache.fetch([token], self.cache_root, transport=self.debian(serve_as=CASE_081), now=NOW)
        entry = next(iter(refs["entries"].values()))
        self.assertEqual((entry["status"], entry["cause"]), ("failed", "digest-mismatch"))
        documents = self.documents(self.source({"case-081/Dockerfile": (FIXTURE / "case-081/Dockerfile").read_text()}))
        image = documents["base-image-inventory.json"]["base_images"][0]
        self.assertEqual((image["resolution"]["status"], image["resolution"]["reason"]), ("unresolved", "digest-mismatch"))
        self.assertEqual(image["components"], [])

    def test_p41_rate_limited_registry_falls_back_to_a_configured_mirror(self):
        """P41 live smoke (2026-10-03): Docker Hub answered 429 for the shared egress IP; a configured
        mirror serves the same content-addressed blobs, and the entry records which host served them."""
        self.assertIsNotNone(cache, "P41: no host-side base-image cache module")
        registry = self.debian()

        def transport(method, url, headers):
            if url.startswith("https://registry-1.docker.io/"):
                return 429, {}, b""
            return registry(method, url.replace("https://mirror.example/", "https://registry-1.docker.io/"), headers)
        token = f"debian:buster-20190708-slim@{registry.index_digest}"
        refs = cache.fetch([token], self.cache_root, transport=transport, now=NOW, mirrors={"docker.io": "mirror.example"})
        entry = next(iter(refs["entries"].values()))
        self.assertEqual((entry["status"], entry["served_by"]), ("resolved", "mirror.example"))

    def test_p41_distroless_status_d_entries_are_installed_packages(self):
        """P41: distroless images keep one dpkg entry per file under status.d/, with no Status field."""
        self.assertIsNotNone(cache, "P41: no host-side base-image cache module")
        files = {"etc/os-release": b'ID=debian\nVERSION_ID="12"\n',
                 "var/lib/dpkg/status.d/libssl3": b"Package: libssl3\nVersion: 3.0.15-1~deb12u1\nArchitecture: amd64\n"
                                                 b"Source: openssl\n",
                 "var/lib/dpkg/status.d/libssl3.md5sums": b"0" * 32 + b"  usr/lib/libssl.so.3\n"}
        registry = FakeRegistry("distroless/base", "nonroot", [layer(files)])
        token = f"distroless/base@{registry.index_digest}"
        cache.fetch([token], self.cache_root, transport=registry, now=NOW)
        image = self.documents(self.source({"Dockerfile": f"FROM {token}\n"}))["base-image-inventory.json"]["base_images"][0]
        self.assertEqual([c["purl"] for c in image["components"]],
                         ["pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12"])
        self.assertEqual(image["package_inventory"], {"status": "inventoried", "reason": None})

    def test_p41_tampered_cached_blob_is_a_gap(self):
        """P41: every cached blob is re-hashed on read; a changed layer is not inventoried."""
        self.assertIsNotNone(cache, "P41: no host-side base-image cache module")
        registry = self.debian()
        token = f"debian:buster-20190708-slim@{registry.index_digest}"
        cache.fetch([token], self.cache_root, transport=registry, now=NOW)
        first = next(d for d, b in registry.blobs.items() if b.startswith(b"\x1f\x8b"))
        (self.cache_root / "blobs" / "sha256" / first.split(":")[1]).write_bytes(layer({"etc/os-release": b"ID=x\n"}))
        image = self.documents(self.source({"Dockerfile": f"FROM {token}\n"}))["base-image-inventory.json"]["base_images"][0]
        self.assertEqual((image["resolution"]["status"], image["resolution"]["reason"]), ("unresolved", "blob-hash-mismatch"))
        self.assertEqual(image["components"], [])

    def test_p41_eol_table_is_pinned_and_cited(self):
        """P41: the EOL table covers Debian 8-13, Ubuntu LTS 16.04-24.04 and Alpine 3.x, each with a source."""
        self.assertTrue(EOL_TABLE.is_file(), "P41: data/base-image-eol.json is missing")
        table = json.loads(EOL_TABLE.read_text())
        listed = {(d, r["version"]): r for d, v in table["distributions"].items() for r in v["releases"]}
        for key in [("debian", str(n)) for n in range(8, 14)] + [("ubuntu", v) for v in
                    ("16.04", "18.04", "20.04", "22.04", "24.04")] + [("alpine", "3.20"), ("alpine", "3.24")]:
            self.assertIn(key, listed)
        for release in listed.values():
            self.assertTrue(release["source_url"].startswith("https://"))
            self.assertRegex(release["support_end"], r"^\d{4}-\d{2}-\d{2}$")
        self.assertEqual(listed[("debian", "10")]["support_end"], "2024-06-30")

    def test_p41_host_step_fetches_base_images_outside_b13(self):
        """P41: prepare-host.sh fills the cache with network; the job itself only reads it."""
        script = (ROOT.parent / "orchestrator" / "prepare-host.sh").read_text()
        self.assertTrue("base_image_cache.py fetch" in script, "P41: prepare-host.sh does not fetch base images")


if __name__ == "__main__":
    unittest.main()
