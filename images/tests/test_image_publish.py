"""Shared images (ADR-0033): publish on one host, pull on another, with fake docker, zstd and rclone.

    python3 -B -m unittest images.tests.test_image_publish
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

from images import image_build

IMAGES = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMAGES))
import registry_records as rr  # noqa: E402

# A docker stand-in. Local image ids are host-specific (FAKE_DOCKER_HOST salts them), as Docker
# Engine and Docker Desktop's containerd store disagree on the id of the same loaded bytes.
FAKE_DOCKER = textwrap.dedent('''\
    #!/usr/bin/env python3
    import hashlib, json, os, sys
    local_path = os.environ["FAKE_DOCKER_LOCAL"]
    local = json.load(open(local_path)) if os.path.exists(local_path) else {}
    def local_id(content):
        return "sha256:" + hashlib.sha256((os.environ["FAKE_DOCKER_HOST"] + content).encode()).hexdigest()
    args = sys.argv[1:]
    if args[:1] == ["info"]:
        print("27.0"); sys.exit(0)
    if args[:2] == ["image", "inspect"]:
        if args[-1] not in local: sys.exit(1)
        print(local_id(local[args[-1]])); sys.exit(0)
    if args[0] == "save":
        if args[1] not in local: sys.exit(1)
        sys.stdout.write(json.dumps({"tag": args[1], "content": local[args[1]]})); sys.exit(0)
    if args[0] == "load":
        image = json.loads(sys.stdin.read())
        local[image["tag"]] = image["content"]
        print("Loaded image: " + image["tag"])
    else:
        sys.exit(2)
    json.dump(local, open(local_path, "w"))
''')
# zstd stand-in: -c copies stdin (or the named file) to stdout either way.
FAKE_ZSTD = textwrap.dedent('''\
    #!/usr/bin/env python3
    import sys
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    data = open(files[0], "rb").read() if files else sys.stdin.buffer.read()
    sys.stdout.buffer.write(data)
''')
# rclone stand-in: "copyto SRC DST", where "drive:" names the FAKE_RCLONE_ROOT folder.
FAKE_RCLONE = textwrap.dedent('''\
    #!/usr/bin/env python3
    import os, shutil, sys
    def path(value):
        return os.path.join(os.environ["FAKE_RCLONE_ROOT"], value[len("drive:"):]) if value.startswith("drive:") else value
    assert sys.argv[1] == "copyto"
    source, target = path(sys.argv[2]), path(sys.argv[3])
    if not os.path.exists(source):
        print("not found", file=sys.stderr); sys.exit(3)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.copyfile(source, target)
''')


class Hosts(unittest.TestCase):
    """Two checkouts of the same images tree (publisher, puller) with separate build state and Docker."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.tools = {}
        for name, script in (("docker", FAKE_DOCKER), ("zstd", FAKE_ZSTD), ("rclone", FAKE_RCLONE)):
            self.tools[name] = self.root / name
            self.tools[name].write_text(script, encoding="utf-8")
            self.tools[name].chmod(0o755)
        self.lock = self.root / "published.lock.json"
        self.drive = self.root / "drive"          # the Google Drive folder, as hal5000 sees it
        self.stores = {"publisher": str(self.drive / "appsec-review" / "images"),   # a folder
                       "puller": "drive:appsec-review/images"}                     # an rclone remote
        self.checkouts = {name: self.root / name / "images" for name in ("publisher", "puller")}
        for images in self.checkouts.values():
            self.image(images, "base-one", "FROM scratch\n")
            self.image(images, "tool-one", "FROM base-one:local\n", requires=["base-one:local"])

    def image(self, images, image_id, dockerfile, requires=(), prebuild=()):
        folder = images / image_id
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "Dockerfile").write_text(dockerfile, encoding="utf-8")
        (folder / "image.json").write_text(json.dumps({
            "schema": image_build.SCHEMA,
            "builds": [{"image_id": image_id, "tag": f"{image_id}:local", "dockerfile": "Dockerfile",
                        "context": ".", "build_args": {}, "requires_images": list(requires),
                        "prebuild": list(prebuild), "timeout_seconds": 60}],
        }), encoding="utf-8")

    def on(self, host):
        images = self.checkouts[host]
        return mock.patch.dict(os.environ, {
            "APPSEC_IMAGES_ROOT": str(images), "APPSEC_IMAGE_BUILD_STATE": str(images / ".build-state"),
            "APPSEC_IMAGE_PUBLISH_LOCK": str(self.lock), "APPSEC_DOCKER_BIN": str(self.tools["docker"]),
            "APPSEC_ZSTD_BIN": str(self.tools["zstd"]), "APPSEC_RCLONE_BIN": str(self.tools["rclone"]),
            "APPSEC_IMAGE_STORE": self.stores[host], "FAKE_RCLONE_ROOT": str(self.drive),
            "FAKE_DOCKER_HOST": host, "FAKE_DOCKER_LOCAL": str(self.root / f"{host}-docker.json"),
        })

    def fake_build(self, image_id, attempt="2026-09-30T120000Z-0000beef"):
        """What a successful image_build.run leaves behind, without running docker build."""
        build = image_build.load_builds()[image_id]
        local = Path(os.environ["FAKE_DOCKER_LOCAL"])
        content = json.loads(local.read_text()) if local.exists() else {}
        content[build["tag"]] = f"{image_id}-{attempt}"
        local.write_text(json.dumps(content))
        image_build.atomic_json(image_build.state_root() / image_id / "latest.json", {
            "image_id": image_id, "tag": build["tag"], "fingerprint": image_build.fingerprint(build)[0],
            "image_digest": image_build.image_id_of(build, build["tag"]), "attempt_id": attempt,
            "finished_at": "2026-09-30T12:00:00+00:00"})

    def publish_all(self):
        with self.on("publisher"):
            self.fake_build("base-one")
            self.fake_build("tool-one")
            return [image_build.publish(i) for i in ("base-one", "tool-one")]

    def pull_all(self):
        with self.on("puller"):
            builds = image_build.load_builds()
            lock = image_build.load_publish_lock()
            return [image_build.pull(i, builds, lock) for i in image_build.pull_order(["tool-one"], builds)]

    def test_publish_then_pull_gives_the_puller_valid_records(self):
        self.assertEqual(self.publish_all(), ["PUBLISHED", "PUBLISHED"])
        entry = json.loads(self.lock.read_text())["images"]["tool-one"]
        archive = Path(self.stores["publisher"]) / entry["archive"]
        self.assertEqual("sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest(), entry["archive_sha256"])
        self.assertEqual(sorted(p.name for p in archive.parent.iterdir()),   # no .part left behind
                         sorted(e["archive"] for e in json.loads(self.lock.read_text())["images"].values()))

        self.assertEqual(self.pull_all(), ["PULLED", "PULLED"])
        with self.on("puller"):
            state = json.loads((image_build.state_root() / "tool-one" / "latest.json").read_text())
            self.assertEqual((state["fingerprint"], state["attempt_id"]), (entry["fingerprint"], entry["attempt_id"]))
            # The puller's own image id, which differs from the publisher's for the same bytes.
            build = image_build.load_builds()["tool-one"]
            self.assertEqual(state["image_digest"], image_build.image_id_of(build, "tool-one:local"))
            records = rr.collect_records(images_root=self.checkouts["puller"],
                                         state_root=image_build.state_root(), image_ids=("tool-one",))
            self.assertEqual(records["tool-one"]["build_fingerprint_sha256"], entry["fingerprint"])
        with self.on("publisher"):
            published_id = json.loads((image_build.state_root() / "tool-one" / "latest.json").read_text())["image_digest"]
        self.assertNotEqual(published_id, state["image_digest"])

    def test_second_pull_and_second_publish_are_no_ops(self):
        self.publish_all()
        self.pull_all()
        self.assertEqual(self.pull_all(), ["CURRENT", "CURRENT"])
        with self.on("publisher"):
            self.assertEqual(image_build.publish("tool-one"), "CURRENT")

    def test_changed_sources_make_the_lock_stale(self):
        self.publish_all()
        (self.checkouts["puller"] / "tool-one" / "Dockerfile").write_text("FROM base-one:local\nRUN true\n")
        self.assertEqual(self.pull_all(), ["PULLED", "STALE"])

    def test_changed_sources_are_reported_as_drifted(self):
        with self.on("publisher"):
            self.fake_build("base-one")
            self.fake_build("tool-one")
            self.assertEqual(image_build.drifted_images(["base-one", "tool-one", "never-built"]), [])
            scripts = self.checkouts["publisher"] / "tool-one" / "scripts"
            scripts.mkdir()
            (scripts / "lane.sh").write_text("#!/bin/sh\n")   # a COPY'd script changed, Dockerfile not
            self.assertEqual(image_build.drifted_images(), ["tool-one"])

    def test_rebuilt_base_makes_the_dependent_stale_until_republished(self):
        self.publish_all()
        with self.on("publisher"):
            self.fake_build("base-one", attempt="2026-09-30T130000Z-0000cafe")
            self.assertEqual(image_build.publish("base-one"), "PUBLISHED")
            with self.assertRaisesRegex(image_build.Blocked, "NOT_CURRENT"):
                image_build.publish("tool-one")
        self.assertEqual(self.pull_all(), ["PULLED", "STALE"])

    def test_unpublished_and_not_current(self):
        self.assertEqual(self.pull_all(), ["UNPUBLISHED", "UNPUBLISHED"])
        with self.on("publisher"):
            with self.assertRaisesRegex(image_build.Blocked, "NOT_CURRENT"):
                image_build.publish("base-one")

    def test_git_clone_commit_travels_in_the_lock(self):
        for images in self.checkouts.values():
            self.image(images, "cloned-one", "FROM scratch\n",
                       prebuild=[{"kind": "git_clone", "url": "https://example.invalid/x.git",
                                  "dest": "src", "depth": 1}])
        clone = self.checkouts["publisher"] / "cloned-one" / "src"
        clone.mkdir()
        git = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@t", "PATH": os.environ["PATH"]}
        subprocess.run(["git", "init", "-q"], cwd=clone, check=True, env=git)
        subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "x"], cwd=clone, check=True, env=git)
        with self.on("publisher"):
            self.fake_build("cloned-one")
            self.assertEqual(image_build.publish("cloned-one"), "PUBLISHED")
        head = json.loads(self.lock.read_text())["images"]["cloned-one"]["clone_heads"]["src"]
        self.assertEqual(len(head), 40)
        with self.on("puller"):   # no clone on this host
            builds = image_build.load_builds()
            self.assertEqual(image_build.pull("cloned-one", builds, image_build.load_publish_lock()), "PULLED")

    def test_rekey_moves_a_current_legacy_build_without_rebuilding(self):
        with self.on("publisher"):
            self.fake_build("base-one")
            self.fake_build("tool-one")
            builds = image_build.load_builds()
            path = image_build.state_root() / "tool-one" / "latest.json"
            state = json.loads(path.read_text())
            legacy = image_build.fingerprint(builds["tool-one"], legacy_requires=True)[0]
            path.write_text(json.dumps(dict(state, fingerprint=legacy)))
            self.assertEqual(image_build.rekey("tool-one", builds), "REKEYED")
            self.assertEqual(json.loads(path.read_text()), state)
            self.assertEqual(image_build.rekey("tool-one", builds), "UNCHANGED")
            path.write_text(json.dumps(dict(state, fingerprint="sha256:" + "1" * 64)))
            self.assertEqual(image_build.rekey("tool-one", builds), "STALE")

    def test_archive_that_does_not_match_the_lock_is_not_loaded(self):
        self.publish_all()
        entry = json.loads(self.lock.read_text())["images"]["base-one"]
        (Path(self.stores["publisher"]) / entry["archive"]).write_bytes(b"half-synced")
        with self.on("puller"):
            builds = image_build.load_builds()
            with self.assertRaisesRegex(image_build.BuildFailed, "PULL_ARCHIVE_MISMATCH"):
                image_build.pull("base-one", builds, image_build.load_publish_lock())
            self.assertFalse((image_build.state_root() / "base-one" / "latest.json").exists())
            self.assertFalse((image_build.state_root() / "base-one" / "transfer").exists())

    def test_missing_store_setting_blocks(self):
        self.publish_all()
        with self.on("puller"), mock.patch.dict(os.environ, {"APPSEC_IMAGE_STORE": ""}):
            builds = image_build.load_builds()
            with self.assertRaisesRegex(image_build.Blocked, "IMAGE_STORE_UNSET"):
                image_build.pull("base-one", builds, image_build.load_publish_lock())

    def test_malformed_lock_entry_is_refused(self):
        self.lock.write_text(json.dumps({"schema": image_build.LOCK_SCHEMA, "images": {
            "base-one": {"archive": "../../etc/passwd", "archive_sha256": "sha256:" + "0" * 64,
                         "fingerprint": "sha256:" + "0" * 64, "attempt_id": "a", "finished_at": "b"}}}))
        with self.on("puller"):
            builds = image_build.load_builds()
            with self.assertRaises(image_build.BuildFailed):
                image_build.pull("base-one", builds, image_build.load_publish_lock())


if __name__ == "__main__":
    unittest.main()
