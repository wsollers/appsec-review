"""Pinned-container argv adapter (B13): hostile requests, pure argv/path parity, on-disk verifier.

Nothing here needs a docker daemon. Hostile cases prove rejection *before* any process or file:
the docker control call and the child runner are replaced by mocks that must never be called, and
the attempt directory must still be empty. Produced attempts use a scripted docker so the on-disk
verifier is exercised in every layout, including the code-server (which has no docker socket).
``test_container_execution_live.py`` repeats the important ones against a real daemon.
"""
from __future__ import annotations

from copy import deepcopy
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_execution as ce  # noqa: E402
import container_execution_support as support  # noqa: E402
import permission_capabilities as pc  # noqa: E402
from schema_validate import SCHEMAS_DIR, SchemaStore, validate_document  # noqa: E402
from worker_adapters import PinnedContainerAdapter, UnsupportedWorkerAdapter, WorkerRequest  # noqa: E402
from worker_result import validate_worker_result  # noqa: E402

MARKER = support.MARKER
SCHEMAS = ("container-image.schema.json", "pinned-container-request.schema.json",
           "pinned-container-result.schema.json")
SUPPORTED_KEYWORDS = {"$schema", "$id", "title", "description", "type", "required", "properties",
                      "additionalProperties", "enum", "const", "pattern", "items", "minItems", "$ref"}


def can_symlink() -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        try:
            os.symlink(tmp, Path(tmp) / "probe", target_is_directory=True)
        except (OSError, NotImplementedError):
            return False
    return True


SYMLINKS = can_symlink()
if os.name == "posix" and not SYMLINKS:     # a POSIX host must never skip the symlink cases
    raise RuntimeError("POSIX host cannot create symlinks; refusing to skip the link tests")


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.attempt = self.root / "attempt"
        self.attempt.mkdir()
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / "source.c").write_text("int main(void){return 0;}\n", encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def rejected(self, request, pattern: str, runtime=None, **ids) -> str:
        """The request is refused, before any process or file, without echoing the marker."""
        with mock.patch.object(ce, "_docker", side_effect=AssertionError("docker was called")) as docker, \
                mock.patch.object(ce.deterministic_child, "execute_child",
                                  side_effect=AssertionError("a child was started")) as child:
            with self.assertRaises(ce.ContainerRequestError) as caught:
                support.run(runtime or support.runtime(), self.attempt, request, **ids)
        self.assertFalse(docker.called or child.called)
        self.assertEqual(list(self.attempt.iterdir()), [], "a rejected request left evidence behind")
        message = str(caught.exception)
        self.assertRegex(message, pattern)
        self.assertNotIn(MARKER, message)
        return message


# ---- schemas and registry ------------------------------------------------------------------------

class SchemaConventionTests(unittest.TestCase):
    def walk(self, node, name, trail="$"):
        if isinstance(node, dict):
            if "properties" in node or node.get("type") == "object" or (
                    isinstance(node.get("type"), list) and "object" in node["type"]):
                self.assertIs(node.get("additionalProperties"), False, f"{name} {trail} is open")
                self.assertEqual(sorted(node["required"]), sorted(node["properties"]),
                                 f"{name} {trail}: every declared property must be required")
            for key, value in node.items():
                if key == "properties":
                    for prop, child in value.items():
                        self.walk(child, name, f"{trail}.{prop}")
                    continue
                self.assertIn(key, SUPPORTED_KEYWORDS, f"{name} {trail}: unsupported keyword {key}")
                if key == "pattern":
                    self.assertTrue(value.startswith("^") and value.endswith("\\Z"), f"{name} {trail}")
                if key == "$ref":
                    self.assertTrue((SCHEMAS_DIR / value).is_file(), f"{name} {trail}: $ref sibling")
                if key == "items":
                    self.walk(value, name, trail + "[]")

    def test_schemas_are_closed_required_and_inside_the_supported_subset(self):
        for name in SCHEMAS:
            with self.subTest(schema=name):
                self.walk(json.loads((SCHEMAS_DIR / name).read_text(encoding="utf-8")), name)

    def test_request_schema_has_no_property_for_a_docker_option(self):
        schema = json.loads((SCHEMAS_DIR / SCHEMAS[1]).read_text(encoding="utf-8"))
        self.assertEqual(sorted(schema["properties"]), sorted([
            "schema", "run_id", "job_id", "attempt_id", "image", "argv", "environment",
            "target_mounts", "scratch_path", "log_path", "network", "permission", "limits"]))
        self.assertEqual(sorted(schema["properties"]["target_mounts"]["items"]["properties"]),
                         ["container_path", "host_path"])
        self.assertEqual(tuple(schema["properties"]["environment"]["items"]["properties"]["name"]["enum"]),
                         ce.ENVIRONMENT_NAMES)
        self.assertEqual(sorted(schema["properties"]["limits"]["properties"]), sorted(ce.LIMIT_BOUNDS))

    def test_result_schema_cause_enum_is_the_adapter_cause_table(self):
        schema = json.loads((SCHEMAS_DIR / SCHEMAS[2]).read_text(encoding="utf-8"))
        self.assertEqual(set(schema["properties"]["cause"]["enum"]), set(ce.STATUS_BY_CAUSE))
        self.assertEqual(set(ce.SUMMARIES), set(ce.STATUS_BY_CAUSE))
        self.assertEqual(set(schema["properties"]["execution_status"]["enum"]),
                         set(ce.STATUS_BY_CAUSE.values()))
        self.assertEqual(sorted(schema["properties"]["files"]["items"]["properties"]["path"]["enum"]),
                         list(ce.ATTEMPT_FILES))


class ImageRegistryTests(Sandbox):
    def write(self, name: str, **over):
        record = {**support.fixture_record(), **over}
        directory = self.root / "images"
        directory.mkdir(exist_ok=True)
        (directory / name).write_text(json.dumps(record), encoding="utf-8")
        return directory

    def test_tracked_registry_loads_and_pins_the_fixture_by_digest(self):
        registry = ce.load_image_registry(ce.IMAGES_DIR)
        record = registry[support.FIXTURE_IMAGE_ID]
        self.assertRegex(ce.image_reference(record), r"\Adocker\.io/library/alpine@sha256:[0-9a-f]{64}\Z")
        for value in registry.values():
            self.assertNotRegex(ce.image_reference(value).split("@")[0], r":[A-Za-z]")

    def test_registry_records_cannot_carry_a_tag_a_bare_name_or_a_short_digest(self):
        for field, value in (("repository", "docker.io/library/alpine:latest"),
                             ("repository", "docker.io/library/alpine:3.17"),
                             ("repository", "alpine"), ("repository", "latest"),
                             ("repository", "Docker.io/library/alpine"),
                             ("repository", "--privileged/x"),
                             ("digest", "sha256:" + "a" * 63), ("digest", "latest"),
                             ("digest", "sha256:" + "a" * 64 + "\n")):
            with self.subTest(field=field, value=value):
                directory = self.write("fixture-harmless.json", **{field: value})
                with self.assertRaisesRegex(ce.ContainerRequestError, "invalid container image record"):
                    ce.load_image_registry(directory)

    def test_registry_file_name_is_bound_to_image_id_and_empty_registry_fails(self):
        directory = self.write("other-name.json")
        with self.assertRaisesRegex(ce.ContainerRequestError, "image_id and file name must agree"):
            ce.load_image_registry(directory)
        for missing in (self.root / "no-such-dir", self.target):
            with self.assertRaisesRegex(ce.ContainerRequestError, "missing or empty"):
                ce.load_image_registry(missing)

    def test_request_image_must_be_the_registered_id_at_the_registered_digest(self):
        good = support.request(self.target, ["/bin/true"])
        other_digest = "sha256:" + "b" * 64
        cases = [
            ({"image_id": "not-registered", "digest": good["image"]["digest"]}, "not a registered"),
            ({"image_id": support.FIXTURE_IMAGE_ID, "digest": other_digest}, "not the digest registered"),
            ({"image_id": "alpine:latest", "digest": good["image"]["digest"]}, "closed schema"),
            ({"image_id": "latest", "digest": good["image"]["digest"]}, "not a registered"),
            ({"image_id": "alpine", "digest": good["image"]["digest"]}, "not a registered"),
            ({"image_id": support.FIXTURE_IMAGE_ID, "digest": "latest"}, "closed schema"),
            ({"image_id": support.FIXTURE_IMAGE_ID, "digest": good["image"]["digest"],
              "tag": "latest"}, "closed schema"),
            ("docker.io/library/alpine:latest", "closed schema"),
            ("--privileged " + MARKER, "closed schema"),
        ]
        for image, pattern in cases:
            with self.subTest(image=image):
                self.rejected({**good, "image": image}, pattern)

    def test_the_reference_comes_from_the_registry_record_not_the_request(self):
        record = support.fixture_record()
        resolved = ce.resolve_image({"image_id": record["image_id"], "digest": record["digest"]},
                                    {record["image_id"]: record})
        self.assertEqual(ce.image_reference(resolved), f"{record['repository']}@{record['digest']}")
        with self.assertRaisesRegex(ce.ContainerRequestError, "repository@sha256"):
            ce.build_docker_argv(**{**golden_arguments("posix"), "image_ref": "alpine:latest"})


# ---- hostile argv, environment, limits -----------------------------------------------------------

class HostileRequestTests(Sandbox):
    def test_argv_must_be_a_bounded_array_of_clean_strings(self):
        good = support.request(self.target, ["/bin/true"])
        cases = [
            ("/bin/echo " + MARKER, "closed schema"),                     # a shell string
            ([], "closed schema"),
            (["/bin/echo", 7], r"argv\[1\] is not a string"),
            (["/bin/echo", None], r"argv\[1\] is not a string"),
            (["/bin/echo", ["nested", MARKER]], r"argv\[1\] is not a string"),
            (["/bin/echo", MARKER + "\x00"], r"argv\[1\] contains a NUL"),
            (["/bin/echo", MARKER + "\nsecond"], r"argv\[1\] contains a NUL, newline"),
            (["/bin/echo", "a\rb"], r"argv\[1\] contains"),
            (["/bin/echo"] * (ce.MAX_ARGV_MEMBERS + 1), "more than 256 members"),
            (["/bin/echo", "x" * (ce.MAX_ARGV_MEMBER_CHARS + 1)], r"argv\[1\] is longer"),
            (["/bin/echo"] + ["y" * 4000] * 20, "in total"),
            (["echo", MARKER], r"argv\[0\] must be one normalized absolute path"),
            (["--privileged", MARKER], r"argv\[0\] must be one normalized absolute path"),
            (["", MARKER], r"argv\[0\] must be one normalized absolute path"),
            (["/bin/../bin/echo"], r"argv\[0\] must be one normalized absolute path"),
            (["/bin//echo"], r"argv\[0\] must be one normalized absolute path"),
            (["/bin/./echo"], r"argv\[0\] must be one normalized absolute path"),
            (["/bin/sh", "-c", "echo " + MARKER], "shell executable"),
            (["/bin/bash", "-lc", MARKER], "shell executable"),
            (["/usr/bin/PwSh", MARKER], "shell executable"),
        ]
        for argv, pattern in cases:
            with self.subTest(argv=str(argv)[:60]):
                self.rejected({**good, "argv": argv}, pattern)

    def test_docker_options_in_argv_never_reach_docker_as_options(self):
        hostile = ["/bin/echo", "--privileged", "--cap-add=ALL", "-v", "/:/host", "--network=host",
                   "--entrypoint=/bin/sh", "-e", "X", "--", "--user=0"]
        benign = ["/bin/echo", "hello"]
        built = {name: ce.build_docker_argv(**{**golden_arguments("posix"), "argv": argv})
                 for name, argv in (("hostile", hostile), ("benign", benign))}
        image = golden_arguments("posix")["image_ref"]
        split = {name: value.index(image) for name, value in built.items()}
        self.assertEqual(built["hostile"][:split["hostile"]], built["benign"][:split["benign"]])
        self.assertEqual(list(built["hostile"][split["hostile"] + 1:]), hostile[1:])

    def test_environment_is_an_allow_list_with_no_passthrough(self):
        good = support.request(self.target, ["/bin/true"])
        for environment in ([{"name": "LD_PRELOAD", "value": MARKER}],
                            [{"name": "PATH", "value": "/x"}],
                            [{"name": "HOME", "value": "/root"}],
                            [{"name": "LANG"}],
                            [{"name": "LANG", "value": "C\n--privileged"}],
                            [{"name": "LANG", "value": "x" * 257}],
                            ["LANG"], {"LANG": "C"}):
            with self.subTest(environment=str(environment)[:50]):
                self.rejected({**good, "environment": environment}, "closed schema")
        self.rejected({**good, "environment": [{"name": "TZ", "value": "UTC"}] * 2}, "repeats a name")
        with self.assertRaisesRegex(ce.ContainerRequestError, "allow-list"):
            ce.build_docker_argv(**{**golden_arguments("posix"),
                                    "environment": [{"name": "LD_PRELOAD", "value": "x"}]})

    def test_docker_client_environment_drops_docker_and_unlisted_host_variables(self):
        host = {"PATH": "/usr/bin", "HOME": "/home/u", "DOCKER_HOST": "tcp://evil:2375",
                "DOCKER_CONTEXT": "evil", "DOCKER_CONFIG": "/x", "DOCKER_TLS_VERIFY": "0",
                "AWS_SESSION": MARKER, "LD_PRELOAD": "/x.so"}
        self.assertEqual(ce.docker_client_environment(host, None), {"PATH": "/usr/bin", "HOME": "/home/u"})
        self.assertEqual(ce.docker_client_environment(host, "unix:///run/d.sock")["DOCKER_HOST"],
                         "unix:///run/d.sock")
        self.assertEqual(ce.docker_client_environment({}, None), {"PATH": os.defpath})

    def test_every_limit_is_required_and_bounded(self):
        good = support.request(self.target, ["/bin/true"])
        for name, (low, high) in ce.LIMIT_BOUNDS.items():
            without = deepcopy(good)
            del without["limits"][name]
            with self.subTest(limit=name, case="omitted"):
                self.rejected(without, "closed schema")
            for value, pattern in ((low - 1, "within"), (high + 1, "within"), (0, "within"),
                                   (-1, "within"), (True, "closed schema"), (1.5, "closed schema"),
                                   (str(low), "closed schema"), (None, "closed schema")):
                with self.subTest(limit=name, value=value):
                    self.rejected({**good, "limits": {**good["limits"], name: value}},
                                  pattern if pattern != "within" else rf"limits\.{name} must be an integer within")
        self.rejected({**good, "limits": {**good["limits"], "privileged": 1}}, "closed schema")

    def test_every_top_level_property_is_required_and_no_other_is_accepted(self):
        good = support.request(self.target, ["/bin/true"])
        for name in good:
            with self.subTest(omitted=name):
                self.rejected({key: value for key, value in good.items() if key != name}, "closed schema")
        for extra in ("privileged", "cap_add", "user", "workdir", "devices", "docker_args", "volumes"):
            with self.subTest(extra=extra):
                self.rejected({**good, extra: MARKER}, "closed schema")
        for value in (None, [], "request", 7):
            with self.subTest(request=value):
                self.rejected(value, "closed schema")
        self.rejected({**good, "argv": ["/bin/echo", b"bytes"]}, "not a JSON document")

    def test_request_identity_is_bound_to_the_worker_request_it_arrived_in(self):
        good = support.request(self.target, ["/bin/true"])
        for name in ("run_id", "job_id", "attempt_id"):
            with self.subTest(edited_request=name):
                self.rejected({**good, name: "other-" + name.replace("_", "-")}, rf"request\.{name} is not the")
            with self.subTest(edited_worker_request=name):
                self.rejected(good, rf"request\.{name} is not the", **{name: "other-party"})

    def test_network_shape_is_exact(self):
        good = support.request(self.target, ["/bin/true"])
        destination = {"scheme": "https", "host": "api.example.test", "port": 443}
        cases = [
            ({"mode": "none", "destinations": [destination]}, "cannot list destinations"),
            ({"mode": "granted-fixed-destinations", "destinations": []}, "at least one destination"),
            ({"mode": "host", "destinations": []}, "closed schema"),
            ({"mode": "bridge", "destinations": []}, "closed schema"),
            ({"mode": "none"}, "closed schema"),
            ({"mode": "granted-fixed-destinations", "destinations": [{**destination, "port": 0}]}, "within 1..65535"),
            ({"mode": "granted-fixed-destinations", "destinations": [{**destination, "port": 65536}]}, "within 1..65535"),
            ({"mode": "granted-fixed-destinations", "destinations": [{**destination, "port": True}]}, "closed schema"),
            ({"mode": "granted-fixed-destinations", "destinations": [{**destination, "host": "*.example.test"}]}, "closed schema"),
            ({"mode": "granted-fixed-destinations", "destinations": [destination, destination]}, "repeat"),
        ]
        for network, pattern in cases:
            with self.subTest(network=str(network)[:70]):
                self.rejected({**good, "network": network}, pattern)


# ---- mounts and run-owned paths ------------------------------------------------------------------

class HostileMountTests(Sandbox):
    def mount(self, host_path, container_path="/workspace"):
        return support.request(None, ["/bin/true"], target_mounts=[
            {"host_path": host_path, "container_path": container_path}])

    def test_mount_strings_cannot_carry_options_modes_or_relative_spellings(self):
        target = str(self.target)
        cases = [
            (target + ":rw", "does not exist"),
            (target + ",readonly=false", "comma"),
            (target + ",bind-propagation=shared", "comma"),
            (target + '"', "double quote"),
            (target + "\n" + MARKER, "control character"),
            (" " + target, "outer whitespace"),
            ("target", "absolute"), ("./target", "absolute"), ("", "non-empty"),
            ("//" + target.lstrip("/"), "single leading"),
            (target + "/", "empty segments"), (target + "/.", "empty segments"),
            (str(self.root) + "/./target", "empty segments"),
            (str(self.root) + "/other/../target", "empty segments"),
            ("/", "filesystem root"),
            ("x" * (ce.MAX_PATH_CHARS + 1), "bounded"),
        ] if os.name == "posix" else []
        for host_path, pattern in cases:
            with self.subTest(host_path=host_path[:60]):
                self.rejected(self.mount(host_path), pattern)
        for bad in (7, None, [target], {"path": target}):
            with self.subTest(host_path=bad):
                self.rejected(self.mount(bad), "closed schema")

    def test_container_paths_are_an_allow_list(self):
        for container_path in ("/", "/scratch", "/tmp", "/proc", "/etc", "/workspace:rw", "/workspace/",
                               "/workspace,readonly=false", "workspace", "/inputs/", "/inputs/../etc",
                               "/inputs/A", "/var/run/docker.sock", "/inputs/a/b"):
            with self.subTest(container_path=container_path):
                self.rejected(self.mount(str(self.target), container_path), "closed schema")
        two = support.request(None, ["/bin/true"], target_mounts=[
            {"host_path": str(self.target), "container_path": "/inputs/a"},
            {"host_path": str(self.root / "second"), "container_path": "/inputs/a"}])
        self.rejected(two, "share one container path")
        many = support.request(None, ["/bin/true"], target_mounts=[
            {"host_path": str(self.target), "container_path": f"/inputs/m{i}"} for i in range(ce.MAX_MOUNTS + 1)])
        self.rejected(many, "more than 16 target mounts")

    def test_a_mount_may_not_be_a_file_a_socket_or_missing(self):
        self.rejected(self.mount(str(self.target / "source.c")), "not a directory")
        self.rejected(self.mount(str(self.root / "missing")), "does not exist")

    @unittest.skipUnless(os.name == "posix", "POSIX socket and system paths")
    def test_the_docker_socket_the_root_and_system_directories_are_refused(self):
        import socket
        path = self.root / "docker.sock"
        server = socket.socket(socket.AF_UNIX)
        try:
            server.bind(str(path))
            self.rejected(self.mount(str(path)), "not a directory")
            runtime = support.runtime(docker_host="unix://" + str(path))
            self.rejected(self.mount(str(self.root)), "docker socket", runtime=runtime)
        finally:
            server.close()
        for system in ("/proc", "/sys", "/dev", "/etc", "/run", "/var/run", "/var", "/proc/self", "/etc/ssl"):
            if Path(system).is_dir() and os.path.realpath(system) == system:
                with self.subTest(system=system):
                    self.rejected(self.mount(system), "the attempt|host system directory")

    def test_the_attempt_its_ancestors_and_its_descendants_are_refused(self):
        (self.attempt / "inputs").mkdir()
        try:
            for path in (self.attempt, self.root, self.root.parent, self.attempt / "inputs"):
                with self.subTest(path=str(path)):
                    with mock.patch.object(ce, "_docker", side_effect=AssertionError), \
                            mock.patch.object(ce.deterministic_child, "execute_child", side_effect=AssertionError):
                        with self.assertRaisesRegex(ce.ContainerRequestError, "the attempt"):
                            support.run(support.runtime(), self.attempt, self.mount(str(path)))
        finally:
            (self.attempt / "inputs").rmdir()

    def test_the_host_home_its_ancestors_and_credential_directories_are_refused(self):
        home = self.root / "home" / "user"
        (home / ".ssh").mkdir(parents=True)
        (home / ".config" / "gcloud").mkdir(parents=True)
        (home / "projects" / "target").mkdir(parents=True)
        with mock.patch.object(ce.Path, "home", return_value=home):
            for path in (home, home.parent, home / ".ssh", home / ".config" / "gcloud"):
                with self.subTest(path=str(path)):
                    self.rejected(self.mount(str(path)), "host home|credential directory")
            expose, enter = ce.sensitive_locations(homes=[home], attempt_root=self.attempt, docker_host=None)
            self.assertEqual(ce.checked_mount_sources(
                [{"host_path": str(home / "projects" / "target"), "container_path": "/workspace"}],
                flavor=support.runtime().host_flavor, expose=expose, enter=enter),
                [(str(home / "projects" / "target"), "/workspace")])

    @unittest.skipUnless(SYMLINKS, "host cannot create symlinks")
    def test_two_spellings_of_one_directory_are_never_both_accepted(self):
        (self.root / "alias").symlink_to(self.target, target_is_directory=True)
        (self.root / "via").symlink_to(self.root, target_is_directory=True)
        (self.root / "to-attempt").symlink_to(self.attempt, target_is_directory=True)
        self.rejected(self.mount(str(self.root / "alias")), "not a directory")
        self.rejected(self.mount(str(self.root / "via" / "target")), "through a link")
        self.rejected(self.mount(str(self.root / "to-attempt")), "not a directory")
        same = support.request(None, ["/bin/true"], target_mounts=[
            {"host_path": str(self.target), "container_path": "/inputs/one"},
            {"host_path": str(self.target), "container_path": "/inputs/two"}])
        self.rejected(same, "same directory as an earlier target mount")

    def test_a_link_inside_the_target_is_not_followed_by_the_host(self):
        if SYMLINKS:
            (self.target / "escape").symlink_to(self.attempt, target_is_directory=True)
        expose, enter = ce.sensitive_locations(homes=[], attempt_root=self.attempt, docker_host=None)
        pairs = ce.checked_mount_sources([{"host_path": str(self.target), "container_path": "/workspace"}],
                                         flavor=support.runtime().host_flavor, expose=expose, enter=enter)
        self.assertEqual(pairs, [(str(self.target), "/workspace")])

    def test_scratch_and_log_paths_are_single_normalized_run_owned_and_new(self):
        good = support.request(self.target, ["/bin/true"])
        cases = [
            ({"scratch_path": "../scratch"}, "closed schema"),
            ({"scratch_path": "/scratch"}, "closed schema"),
            ({"scratch_path": "a/./b"}, "closed schema"),
            ({"scratch_path": "a//b"}, "closed schema"),
            ({"scratch_path": "a/../b"}, "closed schema"),
            ({"scratch_path": ""}, "closed schema"),
            ({"scratch_path": "scratch:rw"}, "closed schema"),
            ({"scratch_path": "scratch,readonly"}, "closed schema"),
            ({"log_path": "C:\\logs"}, "closed schema"),
            ({"scratch_path": "out", "log_path": "out"}, "must not be equal or contain"),
            ({"scratch_path": "out", "log_path": "out/logs"}, "must not be equal or contain"),
            ({"scratch_path": "logs/container/scratch"}, "must not be equal or contain"),
            ({"scratch_path": "OUT", "log_path": "out/logs"}, "must not be equal or contain"),
        ]
        for over, pattern in cases:
            with self.subTest(over=over):
                self.rejected({**good, **over}, pattern)

    def test_existing_or_linked_scratch_and_log_locations_are_refused(self):
        good = support.request(self.target, ["/bin/true"])
        for name in ("scratch", "logs/container"):
            path = self.attempt.joinpath(*name.split("/"))
            path.mkdir(parents=True)
            with self.subTest(existing=name):
                with mock.patch.object(ce, "_docker", side_effect=AssertionError), \
                        self.assertRaisesRegex(ce.ContainerRequestError, "must not exist"):
                    support.run(support.runtime(), self.attempt, good)
            path.rmdir()
        if SYMLINKS:
            outside = self.root / "outside"
            outside.mkdir()
            (self.attempt / "logs").rmdir()
            (self.attempt / "logs").symlink_to(outside, target_is_directory=True)
            with mock.patch.object(ce, "_docker", side_effect=AssertionError), \
                    self.assertRaisesRegex(ce.ContainerRequestError, "crosses a link"):
                support.run(support.runtime(), self.attempt, good)
            self.assertEqual(list(outside.iterdir()), [])

    def test_attempt_root_must_be_a_real_absolute_directory(self):
        good = support.request(self.target, ["/bin/true"])
        for root in (Path("relative"), self.root / "missing", self.target / "source.c"):
            with self.subTest(root=str(root)):
                with self.assertRaisesRegex(ce.ContainerRequestError, "attempt_root must be"):
                    support.run(support.runtime(), root, good)


# ---- Windows-host / Linux-worker parity (pure) ----------------------------------------------------

def golden_arguments(flavor: str) -> dict:
    windows = flavor == "windows"
    return {
        "docker_executable": r"C:\Program Files\Docker\docker.exe" if windows else "/usr/bin/docker",
        "name": "appsec-" + "0" * 32,
        "user": "10001:10001" if windows else "1000:1000",
        "image_ref": "docker.io/library/alpine@sha256:" + "f" * 64,
        "limits": support.limits(),
        "environment": [{"name": "LANG", "value": "C"}, {"name": "TZ", "value": "UTC"}],
        "mounts": [(r"D:\review targets\repo (1)" if windows else "/srv/review targets/repo (1)", "/workspace")],
        "scratch_source": r"C:\runs\r1\attempt\scratch" if windows else "/srv/runs/r1/attempt/scratch",
        "argv": ["/usr/bin/tool", "--format", "json", "/workspace"],
    }


class ParityTests(unittest.TestCase):
    def test_posix_host_paths(self):
        for good in ("/srv/target", "/srv/review targets/repo (1)", "/a", "/mnt/c/Users/x", "/srv/a:b"):
            self.assertEqual(ce.translate_host_path(good, "posix"), good)
        for bad in ("", "srv/target", "./srv", "//srv/target", "/", "/srv/", "/srv//t", "/srv/./t", "/srv/../t",
                    "/srv/t,ro", '/srv/"t', "/srv/t\x00", "/srv/t\n", " /srv/t", "/srv/t ", "C:\\srv",
                    "\\\\server\\share", "~/target", 7, None, b"/srv"):
            with self.subTest(bad=bad), self.assertRaises(ce.ContainerRequestError) as caught:
                ce.translate_host_path(bad, "posix")
            if isinstance(bad, str) and len(bad) > 3:
                self.assertNotIn(bad, str(caught.exception))

    def test_windows_host_paths(self):
        for good in ("C:\\targets\\repo", "d:\\Review Targets\\repo (1)", "C:\\a", "E:\\x.y\\z-1_2"):
            self.assertEqual(ce.translate_host_path(good, "windows"), good)
        bad_paths = (
            "\\\\server\\share\\repo", "//server/share/repo", "\\\\?\\C:\\targets", "\\\\.\\pipe\\docker_engine",
            "C:", "C:\\", "C:targets", "C:/targets/repo", "C:\\targets/repo", "\\targets", "targets\\repo",
            "/c/targets", "/mnt/c/targets", "C:\\targets\\", "C:\\targets\\\\repo", "C:\\targets\\.\\repo",
            "C:\\targets\\..\\repo", "C:\\targets\\repo:stream", "C:\\targets\\repo.", "C:\\targets\\repo ",
            "C:\\targets\\CON", "C:\\targets\\nul.txt", "C:\\targets\\COM1", "C:\\targets\\a<b", "C:\\targets\\a|b",
            "C:\\targets\\a?b", "C:\\targets\\a*b", "C:\\targets,ro", "C:\\targets\\\"x\"", "C:\\targets\\x\n",
            "CC:\\targets", "1:\\targets", "")
        for bad in bad_paths:
            with self.subTest(bad=bad), self.assertRaises(ce.ContainerRequestError):
                ce.translate_host_path(bad, "windows")
        with self.assertRaisesRegex(ce.ContainerRequestError, "flavor"):
            ce.translate_host_path("/srv/t", "cygwin")

    def expected(self, flavor: str) -> list[str]:
        arguments = golden_arguments(flavor)
        source, scratch = arguments["mounts"][0][0], arguments["scratch_source"]
        return [
            arguments["docker_executable"], "run", "--name", arguments["name"],
            "--label", "appsec-review.adapter=appsec-review/pinned-container-adapter/1.0",
            "--label", "appsec-review.container=" + arguments["name"],
            "--pull", "never", "--log-driver", "none", "--network", "none",
            "--hostname", "appsec-worker", "--add-host", "appsec-worker:127.0.0.1",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--workdir", "/scratch", "--env", "HOME=/tmp",
            "--user", arguments["user"], "--pids-limit", "32", "--memory", "67108864",
            "--memory-swap", "67108864", "--cpus", "0.500",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=4194304",
            "--env", "LANG=C", "--env", "TZ=UTC",
            "--mount", f"type=bind,source={source},target=/workspace,readonly",
            "--mount", f"type=bind,source={scratch},target=/scratch",
            "--entrypoint=/usr/bin/tool", arguments["image_ref"], "--format", "json", "/workspace"]

    def test_docker_argv_is_the_same_list_on_both_hosts_except_for_host_spellings(self):
        built = {}
        for flavor in ("posix", "windows"):
            arguments = golden_arguments(flavor)
            for source in (arguments["mounts"][0][0], arguments["scratch_source"]):
                self.assertEqual(ce.translate_host_path(source, flavor), source)
            built[flavor] = list(ce.build_docker_argv(**arguments))
            self.assertEqual(built[flavor], self.expected(flavor))
            self.assertTrue(all(isinstance(member, str) for member in built[flavor]))
        self.assertEqual(len(built["posix"]), len(built["windows"]))
        differing = {a for a, b in zip(built["posix"], built["windows"]) if a != b}
        posix = golden_arguments("posix")
        self.assertEqual(differing, {
            posix["docker_executable"], posix["user"],
            f"type=bind,source={posix['mounts'][0][0]},target=/workspace,readonly",
            f"type=bind,source={posix['scratch_source']},target=/scratch"})

    def test_cpu_millis_render_without_floating_point(self):
        for millis, text in ((100, "0.100"), (1000, "1.000"), (2500, "2.500"), (64000, "64.000"), (1001, "1.001")):
            built = ce.build_docker_argv(**{**golden_arguments("posix"),
                                            "limits": support.limits(cpu_millis=millis)})
            self.assertEqual(built[built.index("--cpus") + 1], text)

    def test_build_refuses_a_root_user_a_foreign_name_and_any_omitted_argument(self):
        for field, value in (("user", "0:0"), ("user", "0:1000"), ("user", "root"), ("user", "1000"),
                             ("user", "1000:1000 --privileged"), ("name", "my-container"),
                             ("name", "appsec-" + "0" * 32 + " --privileged")):
            with self.subTest(field=field, value=value), self.assertRaises(ce.ContainerRequestError):
                ce.build_docker_argv(**{**golden_arguments("posix"), field: value})
        for name in golden_arguments("posix"):
            arguments = golden_arguments("posix")
            del arguments[name]
            with self.subTest(omitted=name), self.assertRaises(TypeError):
                ce.build_docker_argv(**arguments)

    def test_assert_boundary_rejects_every_widening_of_a_built_argv(self):
        arguments = golden_arguments("posix")
        image = arguments["image_ref"]
        good = ce.build_docker_argv(**arguments)
        ce.assert_boundary(good, image)
        at = good.index(image)

        def inserted(*extra):
            return good[:at - 1] + extra + good[at - 1:]

        def without(flag, width):
            index = good.index(flag)
            return good[:index] + good[index + width:]

        def replaced(old, new):
            index = good.index(old)
            return good[:index] + (new,) + good[index + 1:]

        widened = [
            inserted("--privileged"), inserted("--cap-add", "SYS_ADMIN"), inserted("--network", "host"),
            inserted("-v", "/:/host"), inserted("--volume", "/:/host"), inserted("--device", "/dev/kmsg"),
            inserted("--pid", "host"), inserted("--ipc", "host"), inserted("--userns", "host"),
            inserted("--env", "AWS_SESSION"), inserted("--env-file", "/x"), inserted("-e", "X=1"),
            inserted("--mount", "type=bind,source=/srv/x,target=/inputs/x"),
            inserted("--mount", "type=volume,source=x,target=/inputs/x,readonly"),
            inserted("--security-opt", "seccomp=unconfined"), inserted("--user", "0:0"),
            inserted("--pull", "always"), inserted("--rm"),
            without("--read-only", 1), without("--cap-drop", 2), without("--network", 2),
            without("--pids-limit", 2), without("--memory", 2), without("--cpus", 2),
            without("--tmpfs", 2), without("--user", 2), without("--pull", 2),
            replaced("none", "json-file"), replaced("ALL", "NET_RAW"),
            good[:good.index("--network") + 1] + ("bridge",) + good[good.index("--network") + 2:],
            replaced("no-new-privileges", "seccomp=unconfined"), replaced("never", "always"),
            replaced("run", "exec"),
        ]
        for index, command in enumerate(widened):
            with self.subTest(case=index), self.assertRaises(ce.ContainerRequestError):
                ce.assert_boundary(tuple(command), image)

    def test_boundary_constant_is_equivalent_to_the_audit_native_wrapper(self):
        wrapper = ROOT.parent / "images" / "audit-native" / "run.sh"
        if not wrapper.is_file():
            self.skipTest("images/ is not mounted in this layout (code-server); the constant is still tested")
        text = wrapper.read_text(encoding="utf-8")
        built = " ".join(ce.build_docker_argv(**golden_arguments("posix")))
        for flag in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                     "--pids-limit", "--memory ", "--memory-swap", "--cpus", "--user", "--hostname", "--add-host"):
            with self.subTest(flag=flag):
                self.assertIn(flag, text)
                self.assertIn(flag, built)
        self.assertIn("/tmp:rw,noexec,nosuid,nodev,size=", text)
        self.assertIn("/tmp:rw,noexec,nosuid,nodev,size=", built)
        self.assertIn(":/workspace:ro", text)
        self.assertIn("target=/workspace,readonly", built)
        self.assertIn(":/scratch:rw", text)
        for never in ("--privileged", "docker.sock", "--cap-add", " exec,", "--network bridge", "$"):
            self.assertNotIn(never, built)
        self.assertEqual(ce.boundary_sha256(), ce.boundary_sha256())
        with mock.patch.object(ce, "BOUNDARY_FLAGS", ce.BOUNDARY_FLAGS + ("--privileged",)):
            self.assertNotEqual(ce.boundary_sha256(), BOUNDARY_SHA)

    def test_container_name_is_run_owned_derivable_and_distinct_per_attempt(self):
        name = ce.container_name(**support.IDS)
        self.assertRegex(name, r"\Aappsec-[0-9a-f]{32}\Z")
        self.assertEqual(name, ce.container_name(**support.IDS))
        for field in support.IDS:
            self.assertNotEqual(name, ce.container_name(**{**support.IDS, field: "another"}))
        self.assertNotEqual(ce.container_name("a", "b-c", "d"), ce.container_name("a-b", "c", "d"))
        for bad in ("", "a b", "--rm", "a/b", 7):
            with self.subTest(bad=bad), self.assertRaises(ce.ContainerRequestError):
                ce.container_name(bad, "job", "attempt")


BOUNDARY_SHA = ce.boundary_sha256()


# ---- no optional safety inputs -------------------------------------------------------------------

class RequiredInputTests(Sandbox):
    def test_no_safety_function_has_a_defaulted_parameter(self):
        for function in (ce.run_container, ce.verify_container_result, ce.load_verified_result,
                         ce.to_worker_envelope, ce.build_docker_argv, ce.checked_mount_sources,
                         ce.sensitive_locations, ce.translate_host_path, ce.docker_client_environment,
                         ce.assert_boundary, ce.resolve_image, ce.fingerprint_material, ce.container_name,
                         ce.request_mount_sources, ce.attempt_paths, ce._outcome, ce._command_record_errors,
                         ce._events_errors):
            for name, parameter in inspect.signature(function).parameters.items():
                with self.subTest(function=function.__name__, parameter=name):
                    self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_omitting_any_runtime_field_or_execution_argument_is_a_type_error(self):
        fields = {f: getattr(support.runtime(), f) for f in ce.ContainerRuntime.__dataclass_fields__}
        for name in fields:
            with self.subTest(runtime_field=name), self.assertRaises(TypeError):
                ce.ContainerRuntime(**{k: v for k, v in fields.items() if k != name})
        call = {**support.IDS, "attempt_root": self.attempt, "request": support.request(self.target, ["/bin/true"])}
        for name in call:
            with self.subTest(run_argument=name), self.assertRaises(TypeError):
                ce.run_container(support.runtime(), **{k: v for k, v in call.items() if k != name})
        check = {**support.IDS, "request": call["request"], "images_dir": ce.IMAGES_DIR, **support.host_facts()}
        for name in check:
            with self.subTest(verify_argument=name), self.assertRaises(TypeError):
                ce.verify_container_result(self.attempt, **{k: v for k, v in check.items() if k != name})

    def test_runtime_fields_are_validated_before_anything_else(self):
        good = support.request(self.target, ["/bin/true"])
        cases = [
            ({"docker_executable": Path("docker")}, "docker_executable"),
            ({"docker_executable": self.root / "missing"}, "docker_executable"),
            ({"docker_executable": "/usr/bin/docker"}, "docker_executable"),
            ({"docker_host": "evil host"}, "docker_host"), ({"docker_host": 7}, "docker_host"),
            ({"host_flavor": "cygwin"}, "host_flavor"),
            ({"container_user": "0:0"}, "non-root"), ({"container_user": "root"}, "non-root"),
            ({"container_user": "0:1000"}, "non-root"), ({"container_user": "1000:1000 --privileged"}, "non-root"),
            ({"images_dir": str(ce.IMAGES_DIR)}, "images_dir"),
            ({"source_snapshot_sha256": "a" * 64}, "source_snapshot_sha256"),
            ({"registry_ceiling": "none"}, "registry_ceiling"),
            ({"clock": "now"}, "clock"), ({"clock": lambda: "yesterday"}, "clock must return"),
            ({"cancel": None}, "cancel"), ({"cancel": False}, "cancel"),
        ]
        for over, pattern in cases:
            with self.subTest(over=str(over)[:50]):
                self.rejected(good, pattern, runtime=support.runtime(**over))
        with self.assertRaises(TypeError):
            support.run({"docker_executable": "/usr/bin/docker"}, self.attempt, good)
        if SYMLINKS:
            link = self.root / "docker-link"
            link.symlink_to(support.runtime().docker_executable)
            self.rejected(good, "non-link", runtime=support.runtime(docker_executable=link))


# ---- scripted docker: outcomes, permission gate, verifier ----------------------------------------

class ScriptedDocker:
    """Stands in for the docker control calls and the child runner. It does what the real ones do
    to the attempt (the four child files), so the produced attempt is a producible state."""

    def __init__(self, *, client_exit=0, state="default", stdout=b"out\n", stderr=b"", metadata=None,
                 raises=None, version=0, image=0, leftover=False):
        self.calls: list[list[str]] = []
        self.child_specs = []
        self.client_exit, self.stdout, self.stderr = client_exit, stdout, stderr
        self.state = ({"Status": "exited", "ExitCode": client_exit, "OOMKilled": False}
                      if state == "default" else state)
        self.metadata, self.raises = metadata or {}, raises
        self.version, self.image, self.leftover = version, image, leftover

    def docker(self, runtime, arguments):
        self.calls.append(list(arguments))
        verb = arguments[0]
        if verb == "version":
            return self.version, b"29.0.0\n"
        if verb == "image":
            return self.image, b"sha256:x\n"
        if verb == "inspect":
            return (1, b"") if self.state is None else (0, json.dumps(self.state).encode())
        if verb == "ps":
            return 0, (b"deadbeef\n" if self.leftover else b"")
        return 0, b""

    def child(self, spec, *, cancel=None, observer=None):
        self.child_specs.append(spec)
        if self.raises is not None:
            raise self.raises
        log_dir = Path(spec.log_dir)
        retained = {"stdout": self.stdout[:spec.stdout_limit_bytes], "stderr": self.stderr[:spec.stderr_limit_bytes]}
        streams = {}
        for name, data in (("stdout", self.stdout), ("stderr", self.stderr)):
            (log_dir / f"{name}.log").write_bytes(retained[name])
            streams[name] = {"observed_bytes": len(data), "written_bytes": len(retained[name]),
                             "dropped_bytes": len(data) - len(retained[name]),
                             "truncated": len(data) > len(retained[name])}
        # What deterministic_child records: a START event, then one document -- the redacted argv
        # it ran, its limits, its client environment names and its outcome -- as the END event
        # and as command.json.
        from execution_state import redact_argv
        started = {"schema": "appsec-review/deterministic-child/1.0", "argv": redact_argv(list(spec.argv)),
                   "argv_prefix": redact_argv(list(spec.argv_prefix)), "cwd": str(spec.cwd),
                   "started_at": "2026-09-20T12:00:00+00:00", "timeout_seconds": spec.timeout_seconds,
                   "log_limits": {"stdout": spec.stdout_limit_bytes, "stderr": spec.stderr_limit_bytes},
                   "environment_keys": sorted(spec.env), "exit_code": None, "signal": None,
                   "timed_out": False, "cancelled": False}
        metadata = {**started, "exit_code": self.client_exit,
                    "signal": -self.client_exit if self.client_exit < 0 else None, "streams": streams,
                    "ended_at": "2026-09-20T12:00:01+00:00", "duration_seconds": 1.25, **self.metadata}
        (log_dir / "events.jsonl").write_text("".join(
            json.dumps({"time": "2026-09-20T12:00:00+00:00", "event": kind, **details}, sort_keys=True) + "\n"
            for kind, details in (("START", started), ("END", metadata))), encoding="utf-8")
        (log_dir / "command.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n",
                                              encoding="utf-8")
        return metadata

    def patches(self):
        return (mock.patch.object(ce, "_docker", side_effect=self.docker),
                mock.patch.object(ce.deterministic_child, "execute_child", side_effect=self.child))


class ScriptedCase(Sandbox):
    def produce(self, request=None, scripted=None, runtime=None):
        request = request or support.request(self.target, ["/bin/echo", "hello"])
        scripted = scripted or ScriptedDocker()
        first, second = scripted.patches()
        with first, second:
            result = support.run(runtime or support.runtime(), self.attempt, request)
        return request, scripted, result

    @property
    def log_dir(self) -> Path:
        return self.attempt / "logs" / "container"


class OutcomeTests(ScriptedCase):
    def test_every_outcome_has_a_distinct_cause_is_removed_and_verifies_from_disk(self):
        exited = {"Status": "exited", "OOMKilled": False}
        cases = {
            None: ScriptedDocker(),
            "CONTAINER_EXIT_NONZERO": ScriptedDocker(client_exit=3),
            "TIMEOUT": ScriptedDocker(client_exit=-9, metadata={"timed_out": True, "error": "TimeoutError: x"}),
            "CANCELED": ScriptedDocker(client_exit=-9, metadata={"cancelled": True, "error": "InterruptedError: x"}),
            "LOG_WRITE_FAILED": ScriptedDocker(metadata={"error": "diagnostic stream failure: OSError: disk"}),
            "OOM_KILLED": ScriptedDocker(client_exit=137, state={**exited, "ExitCode": 137, "OOMKilled": True}),
            "WORKER_LOST": ScriptedDocker(client_exit=137, state={**exited, "ExitCode": 137}),
            "CONTAINER_START_FAILED": ScriptedDocker(client_exit=127, state={"Status": "created", "ExitCode": 127,
                                                                            "OOMKilled": False}),
            "CLEANUP_FAILED": ScriptedDocker(leftover=True),
            "DOCKER_UNAVAILABLE": ScriptedDocker(version=1),
            "IMAGE_NOT_PROVISIONED": ScriptedDocker(image=1),
        }
        for cause, scripted in cases.items():
            with self.subTest(cause=cause):
                self.tearDown()
                self.setUp()
                request, scripted, result = self.produce(scripted=scripted)
                self.assertEqual(result["cause"], cause)
                self.assertEqual(result["execution_status"], ce.STATUS_BY_CAUSE[cause])
                self.assertEqual(result["container_removed"], cause != "CLEANUP_FAILED")
                self.assertEqual(support.verify(self.attempt, request), [])
                started = bool(scripted.child_specs)
                self.assertEqual(started, cause not in ce.BLOCKED_CAUSES and cause != "CLEANUP_FAILED")
                if started:
                    self.assertEqual(scripted.calls[-2], ["rm", "--force", "--volumes",
                                                          ce.container_name(**support.IDS)])
                    self.assertEqual(scripted.calls[-1][0], "ps", "removal must be proven, and proven last")
                envelope = self.envelope(request)
                self.assertEqual(validate_worker_result(envelope), [])
                self.assertEqual((envelope["worker_kind"], envelope["acceptance_status"], envelope["cause"]),
                                 ("pinned_container", "NOT_ACCEPTED", cause))
                self.assertEqual(envelope["execution_status"], ce.STATUS_BY_CAUSE[cause])
                self.assertEqual(validate_document(ce.thaw(result), SCHEMAS[2]), [])

    def envelope(self, request, **over):
        record = support.fixture_record()
        arguments = {**support.IDS, "request": request, "images_dir": ce.IMAGES_DIR, **support.host_facts(),
                     "input_fingerprint": ce.fingerprint_material(request, record)["sha256"],
                     "output_contract": "fixture-contract", "output_paths": [],
                     "resume_command": "python -B launch_job.py --run-id run-b13", **over}
        return ce.to_worker_envelope(self.attempt, **arguments)

    def test_classification_table(self):
        exited = {"exit_code": 0, "exited": True, "created": False, "oom_killed": False}
        base = {"exit_code": 0, "timed_out": False, "cancelled": False}
        table = [
            ((base, exited, False), (None, 0)),
            (({**base, "exit_code": 2}, {**exited, "exit_code": 2}, False), ("CONTAINER_EXIT_NONZERO", 2)),
            ((base, exited, True), ("CANCELED", None)),
            ((None, None, False), ("LOG_WRITE_FAILED", None)),
            (({**base, "error": "OSError: diagnostic stream logging failed"}, exited, False), ("LOG_WRITE_FAILED", None)),
            (({**base, "timed_out": True, "cancelled": True}, exited, False), ("CANCELED", None)),
            (({**base, "error": "OSError: cannot start"}, None, False), ("WORKER_LOST", None)),
            ((base, None, False), ("WORKER_LOST", None)),
            (({**base, "exit_code": None}, exited, False), ("WORKER_LOST", None)),
            (({**base, "exit_code": 125}, None, False), ("CONTAINER_START_FAILED", None)),
            (({**base, "exit_code": 0}, {**exited, "exited": False}, False), ("WORKER_LOST", None)),
            (({**base, "exit_code": 0}, {**exited, "exit_code": 5}, False), ("WORKER_LOST", 5)),
            (({**base, "exit_code": 137}, {**exited, "exit_code": 137}, False), ("WORKER_LOST", 137)),
            (({**base, "exit_code": 126}, {**exited, "exit_code": 126}, False), ("CONTAINER_EXIT_NONZERO", 126)),
        ]
        for arguments, expected in table:
            with self.subTest(expected=expected):
                self.assertEqual(ce._classify(*arguments), expected)

    def test_interrupts_are_recorded_removed_and_reraised_with_their_type(self):
        for interrupt in (KeyboardInterrupt(), SystemExit(3)):
            with self.subTest(interrupt=type(interrupt).__name__):
                self.tearDown()
                self.setUp()
                scripted = ScriptedDocker(raises=interrupt)
                with self.assertRaises(type(interrupt)):
                    self.produce(scripted=scripted)
                self.assertIn("rm", [call[0] for call in scripted.calls[-2:]])
                result = json.loads((self.log_dir / ce.RESULT_FILE).read_text(encoding="utf-8"))
                self.assertEqual((result["cause"], result["execution_status"]), ("CANCELED", "CANCELED"))

    def test_a_result_that_cannot_be_persisted_is_an_error_never_a_success(self):
        scripted = ScriptedDocker()
        real = ce.atomic_bytes

        def failing(path, value):
            if Path(path).name == ce.RESULT_FILE:
                raise OSError("disk full")
            return real(path, value)
        first, second = scripted.patches()
        with first, second, mock.patch.object(ce, "atomic_bytes", side_effect=failing):
            with self.assertRaises(ce.ContainerExecutionError):
                support.run(support.runtime(), self.attempt, support.request(self.target, ["/bin/true"]))
        self.assertIn("rm", [call[0] for call in scripted.calls])

    def test_child_spec_is_shell_free_bounded_and_run_owned(self):
        request = support.request(self.target, ["/bin/echo", "x"], limits=support.limits(
            timeout_seconds=7, stdout_limit_bytes=11, stderr_limit_bytes=13))
        _, scripted, _ = self.produce(request=request)
        spec = scripted.child_specs[0]
        self.assertEqual((spec.timeout_seconds, spec.stdout_limit_bytes, spec.stderr_limit_bytes), (7, 11, 13))
        self.assertEqual(spec.argv[:4], spec.argv_prefix)
        self.assertEqual(spec.argv[1], "run")
        self.assertEqual((Path(spec.owner_root), Path(spec.log_dir)), (self.attempt, self.log_dir))
        self.assertNotIn("DOCKER_CONTEXT", spec.env)
        ce.assert_boundary(spec.argv, ce.image_reference(support.fixture_record()))
        self.assertIn(f"type=bind,source={self.attempt / 'scratch'},target=/scratch", spec.argv)
        self.assertIn(f"type=bind,source={self.target},target=/workspace,readonly", spec.argv)

    def test_returned_result_is_deeply_immutable(self):
        _, _, result = self.produce()
        with self.assertRaises(TypeError):
            result["execution_status"] = "OK"
        with self.assertRaises(TypeError):
            result["streams"]["stdout"]["written_bytes"] = 0
        with self.assertRaises((TypeError, AttributeError)):
            result["files"].append({})
        self.assertEqual(ce.thaw(result), json.loads((self.log_dir / ce.RESULT_FILE).read_text(encoding="utf-8")))


class PermissionGateTests(ScriptedCase):
    DESTINATION = {"scheme": "https", "host": "api.example.test", "port": 443}
    NETWORK = ("fixed-network-destination", DESTINATION)

    def blocked(self, request, cause, runtime=None):
        request, scripted, result = self.produce(request=request, runtime=runtime)
        self.assertEqual((result["execution_status"], result["cause"]), ("BLOCKED", cause))
        self.assertEqual(scripted.child_specs, [], "a container was started behind a closed gate")
        self.assertEqual(scripted.calls, [], "docker was contacted behind a closed gate")
        self.assertFalse((self.attempt / "scratch").exists())
        self.assertEqual(support.verify(self.attempt, request), [])
        self.tearDown()
        self.setUp()

    def test_default_is_network_none_under_a_granted_empty_decision(self):
        request, scripted, result = self.produce()
        self.assertEqual(result["execution_status"], "OK")
        argv = scripted.child_specs[0].argv
        self.assertEqual(argv[argv.index("--network") + 1], "none")

    def test_wrong_party_and_wrong_state_decisions_block_before_docker(self):
        target = self.target
        good = support.permission()
        denied = support.permission([self.NETWORK])
        denied["grants"] = []
        denied["decision"] = pc.evaluate(denied["requirement"], [], support.context())
        self.assertEqual(denied["decision"]["decision"], "DENIED")
        other_job = support.permission(job_id="another-job")
        other_run = support.permission(run_id="another-run")
        edited = deepcopy(good)
        edited["decision"]["evaluated_at"] = "2026-09-19T12:00:00Z"
        rehashed = deepcopy(edited)
        rehashed["decision"]["decision_sha256"] = pc.decision_sha256(rehashed["decision"])
        widened = support.permission([self.NETWORK])
        widened["decision"] = good["decision"]
        swapped = support.permission([self.NETWORK])
        swapped["requirement"] = good["requirement"]
        for label, permission in (("denied", denied), ("other job", other_job), ("other run", other_run),
                                  ("edited", edited), ("decision for another requirement", widened),
                                  ("requirement swapped under a decision", swapped)):
            with self.subTest(case=label):
                self.blocked(support.request(target, ["/bin/true"], permission=permission), "PERMISSION_DENIED")
                target = self.target
        with self.subTest(case="consistently rehashed edit of an unbound timestamp still re-derives"):
            request, _, result = self.produce(request=support.request(self.target, ["/bin/true"], permission=rehashed))
            self.assertEqual(result["execution_status"], "OK")

    def test_grants_are_re_evaluated_at_the_runtime_clock_not_trusted_from_the_record(self):
        permission = support.permission([self.NETWORK])
        late = support.runtime(clock=lambda: "2026-09-22T00:00:00Z")
        self.blocked(support.request(self.target, ["/bin/true"], permission=permission), "PERMISSION_DENIED",
                     runtime=late)
        other_snapshot = support.runtime(source_snapshot_sha256="sha256:" + "b" * 64)
        self.blocked(support.request(self.target, ["/bin/true"], permission=permission), "PERMISSION_DENIED",
                     runtime=other_snapshot)
        ceiling = support.runtime(registry_ceiling=[])
        self.blocked(support.request(self.target, ["/bin/true"], permission=permission), "PERMISSION_DENIED",
                     runtime=ceiling)

    def test_network_is_never_opened(self):
        ask = {"mode": "granted-fixed-destinations", "destinations": [self.DESTINATION]}
        self.blocked(support.request(self.target, ["/bin/true"], network=ask), "NETWORK_NOT_GRANTED")
        for field, value in (("port", 8443), ("host", "other.example.test"), ("scheme", "http")):
            with self.subTest(edited=field):
                near = {"mode": ask["mode"], "destinations": [{**self.DESTINATION, field: value}]}
                self.blocked(support.request(self.target, ["/bin/true"], network=near,
                                             permission=support.permission([self.NETWORK])), "NETWORK_NOT_GRANTED")
        restore = ("package-restore", {**self.DESTINATION, "ecosystem": "npm"})
        self.blocked(support.request(self.target, ["/bin/true"], network=ask,
                                     permission=support.permission([restore])), "NETWORK_NOT_GRANTED")
        self.blocked(support.request(self.target, ["/bin/true"], network=ask,
                                     permission=support.permission([self.NETWORK])),
                     "NETWORK_ENFORCEMENT_UNAVAILABLE")

    def test_no_granted_capability_adds_a_docker_capability_device_or_network(self):
        everything = [
            self.NETWORK, ("debugger-ptrace", {"attach_mode": "ptrace-child", "command_profile_id": "profile-1"}),
            ("target-execution", {"command_profile_id": "profile-1", "target_path": "."}),
            ("target-mutation", {"mutation_mode": "run-owned-copy", "target_path": "."}),
        ]
        permission = support.permission(everything)
        if permission["decision"]["decision"] != "GRANTED":
            self.fail("fixture grant is not GRANTED: " + str(permission["decision"]["reasons"]))
        request, scripted, result = self.produce(request=support.request(self.target, ["/bin/true"],
                                                                         permission=permission))
        self.assertEqual(result["execution_status"], "OK")
        argv = scripted.child_specs[0].argv
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual([m for m in argv if m in ("--cap-add", "--privileged", "--device")], [])
        self.assertEqual(sum(1 for m in argv if m.startswith("type=bind") and not m.endswith(",readonly")), 1)

    def test_fingerprint_follows_the_request_and_the_capability_set_not_grant_timestamps(self):
        record = support.fixture_record()
        base = support.request(self.target, ["/bin/echo", "x"])
        value = ce.fingerprint_material(base, record)["sha256"]
        later = deepcopy(base)
        later["permission"] = support.permission(now="2026-09-20T13:00:00Z")
        self.assertNotEqual(ce.request_sha256(base), ce.request_sha256(later))
        self.assertEqual(ce.fingerprint_material(later, record)["sha256"], value)
        changes = [
            {"argv": ["/bin/echo", "y"]}, {"limits": support.limits(pids=33)},
            {"limits": support.limits(timeout_seconds=61)}, {"scratch_path": "scratch2"},
            {"environment": []}, {"target_mounts": []},
            {"permission": support.permission([self.NETWORK])},
        ]
        seen = {value}
        for change in changes:
            seen.add(ce.fingerprint_material({**base, **deepcopy(change)}, record)["sha256"])
        seen.add(ce.fingerprint_material(base, {**record, "purpose": "edited"})["sha256"])
        self.assertEqual(len(seen), len(changes) + 2)
        denied = deepcopy(base)
        denied["permission"]["decision"] = pc.evaluate(
            support.permission([self.NETWORK])["requirement"], [], support.context())
        with self.assertRaises(pc.PermissionDenied):
            ce.fingerprint_material(denied, record)


class VerifierCase(ScriptedCase):
    def result(self) -> dict:
        return json.loads((self.log_dir / ce.RESULT_FILE).read_text(encoding="utf-8"))

    def write(self, result: dict, rehash: bool):
        if rehash:
            result["result_sha256"] = ce.result_sha256(result)
        (self.log_dir / ce.RESULT_FILE).write_bytes(ce.canonical_request_bytes(result))

    def assert_rejected(self, request, **over):
        errors = support.verify(self.attempt, request, **over)
        self.assertTrue(errors, "tampering was accepted")
        self.assertNotIn(MARKER, "\n".join(errors))
        with self.assertRaises(ce.ContainerRequestError) as caught:
            ce.load_verified_result(self.attempt, **{**support.IDS, "request": request,
                                                     "images_dir": ce.IMAGES_DIR, **support.host_facts(), **over})
        self.assertNotIn(MARKER, str(caught.exception))
        with self.assertRaises(ce.ContainerRequestError):
            ce.to_worker_envelope(self.attempt, **{
                **support.IDS, "request": request, "images_dir": ce.IMAGES_DIR, **support.host_facts(),
                "input_fingerprint": "sha256:" + "0" * 64, "output_contract": "fixture-contract",
                "output_paths": [], "resume_command": None, **over})

    def reseal_file(self, result: dict, name: str, data: bytes):
        (self.log_dir / name).write_bytes(data)
        for entry in result["files"]:
            if entry["path"] == name:
                entry.update(sha256=ce._bytes_sha(data), bytes=len(data))


class VerifierTests(VerifierCase):
    def test_a_resealed_result_cannot_contradict_the_child_runners_own_record(self):
        # Found in verification: the verifier bound every file's hash but never read command.json,
        # so a failed run resealed as OK, a docker argv rewritten outside the boundary and forged
        # retained output (with matching counts and hashes) all verified.
        request, _, _ = self.produce(scripted=ScriptedDocker(client_exit=1))
        failed = self.result()
        self.assertEqual((failed["cause"], support.verify(self.attempt, request)),
                         ("CONTAINER_EXIT_NONZERO", []))
        self.write({**failed, "cause": None, "execution_status": "OK", "exit_code": 0}, rehash=True)
        self.assert_rejected(request)
        self.write({**failed, "exit_code": 7}, rehash=True)
        self.assert_rejected(request)
        self.write({**failed, "cause": "TIMEOUT", "exit_code": None}, rehash=True)
        self.assert_rejected(request)
        self.write(failed, rehash=False)
        self.assertEqual(support.verify(self.attempt, request), [])

        command_bytes = (self.log_dir / "command.json").read_bytes()
        command = json.loads(command_bytes)

        def widened(edit):
            value = json.loads(command_bytes)
            edit(value)
            return json.dumps(value).encode("utf-8")
        widenings = {
            "network": lambda c: c["argv"].__setitem__(c["argv"].index("--network") + 1, "host"),
            "privileged": lambda c: c["argv"].insert(2, "--privileged"),
            "other-argv": lambda c: c["argv"].__setitem__(-1, MARKER),
            "writable-target": lambda c: c["argv"].__setitem__(
                c["argv"].index("--mount") + 1,
                c["argv"][c["argv"].index("--mount") + 1].replace(",readonly", "")),
            "scratch-elsewhere": lambda c: c["argv"].__setitem__(
                len(c["argv"]) - 1 - c["argv"][::-1].index("--mount") + 1,
                "type=bind,source=/" + MARKER + ",target=/scratch"),
            "root-user": lambda c: c["argv"].__setitem__(c["argv"].index("--user") + 1, "0:0"),
            "longer-timeout": lambda c: c.__setitem__("timeout_seconds", c["timeout_seconds"] + 1),
            "larger-retention": lambda c: c["log_limits"].__setitem__("stdout", 1 << 30),
            "client-exit": lambda c: c.__setitem__("exit_code", 0),
            "not-an-object": lambda c: c.clear(),
        }
        for label, edit in widenings.items():
            with self.subTest(command=label):
                result = json.loads(json.dumps(failed))
                self.reseal_file(result, "command.json", widened(edit))
                self.write(result, rehash=True)
                self.assert_rejected(request)
        self.assertIn("--network", command["argv"])

        result = json.loads(json.dumps(failed))
        self.reseal_file(result, "command.json", command_bytes)
        self.reseal_file(result, "stdout.log", b"forged\n")
        result["streams"]["stdout"].update(observed_bytes=7, written_bytes=7, dropped_bytes=0)
        self.write(result, rehash=True)
        self.assert_rejected(request)

    def test_editing_only_one_result_field_is_rejected_with_and_without_a_rehash(self):
        request, _, _ = self.produce(scripted=ScriptedDocker(stdout=b"x" * 100000))
        golden = self.result()
        self.assertEqual(support.verify(self.attempt, request), [])
        other_sha = "sha256:" + "1" * 64
        edits = {
            "schema": "appsec-review/pinned-container-result/2.0", "adapter": ce.ADAPTER_ID + "x",
            "boundary": ce.BOUNDARY_ID + "x", "boundary_sha256": other_sha,
            "run_id": "other-run", "job_id": "other-job", "attempt_id": "other-attempt",
            "request_sha256": other_sha,
            "image_reference": "docker.io/library/other@sha256:" + "2" * 64,
            "image_record_sha256": other_sha, "permission_fingerprint_sha256": other_sha,
            "container_name": "appsec-" + "3" * 32,
            "execution_status": "FAILED", "cause": "TIMEOUT", "exit_code": 1,
            "started_at": "2026-09-21T00:00:00Z", "finished_at": "2026-09-19T00:00:00Z",
            "scratch_path": "elsewhere", "log_path": "logs/other",
            "streams": None, "files": golden["files"][:1], "container_removed": False,
            "result_sha256": other_sha,
        }
        self.assertEqual(set(edits), set(golden), "every top-level result field must have an edit")
        for field, value in edits.items():
            for rehash in (False, True):
                with self.subTest(field=field, rehash=rehash):
                    edited = deepcopy(golden)
                    edited[field] = value
                    self.write(edited, rehash and field != "result_sha256")
                    self.assert_rejected(request)
        nested = [
            lambda r: r["streams"]["stdout"].__setitem__("observed_bytes", 5),
            lambda r: r["streams"]["stdout"].__setitem__("written_bytes", 5),
            lambda r: r["streams"]["stdout"].__setitem__("dropped_bytes", 0),
            lambda r: r["streams"]["stdout"].__setitem__("truncated", False),
            lambda r: r["streams"]["stderr"].__setitem__("written_bytes", 1),
            lambda r: r["files"][0].__setitem__("sha256", other_sha),
            lambda r: r["files"][0].__setitem__("bytes", 1),
            lambda r: r["files"][0].__setitem__("path", "stdout.log"),
            lambda r: r["files"].reverse(),
            lambda r: r.__setitem__("note", MARKER),
            lambda r: r.__setitem__("cause", MARKER),
        ]
        for index, edit in enumerate(nested):
            with self.subTest(nested=index):
                edited = deepcopy(golden)
                edit(edited)
                self.write(edited, True)
                self.assert_rejected(request)
        self.write(deepcopy(golden), False)
        self.assertEqual(support.verify(self.attempt, request), [])

    def test_every_file_tampered_one_at_a_time_is_rejected_and_nothing_is_echoed(self):
        request, _, _ = self.produce()
        names = sorted(path.name for path in self.log_dir.iterdir())
        self.assertEqual(names, sorted((ce.RESULT_FILE, *ce.ATTEMPT_FILES)))
        for name in names:
            path = self.log_dir / name
            original = path.read_bytes()
            mutations = {
                "appended": original + MARKER.encode(), "prefixed": MARKER.encode() + original,
                "emptied": b"" if original else b"x", "one byte": bytes([original[0] ^ 1]) + original[1:] if original else b"\n",
            }
            for label, data in mutations.items():
                with self.subTest(file=name, mutation=label):
                    path.write_bytes(data)
                    self.assert_rejected(request)
            with self.subTest(file=name, mutation="deleted"):
                path.unlink()
                self.assert_rejected(request)
            if SYMLINKS:
                with self.subTest(file=name, mutation="replaced by a link to identical bytes"):
                    twin = self.root / ("twin-" + name)
                    twin.write_bytes(original)
                    path.symlink_to(twin)
                    self.assert_rejected(request)
                    path.unlink()
            path.write_bytes(original)
            self.assertEqual(support.verify(self.attempt, request), [])
        with self.subTest(mutation="extra file"):
            (self.log_dir / "extra.log").write_text(MARKER, encoding="utf-8")
            self.assert_rejected(request)
            (self.log_dir / "extra.log").unlink()
        with self.subTest(mutation="extra directory"):
            (self.log_dir / "sub").mkdir()
            self.assert_rejected(request)
            (self.log_dir / "sub").rmdir()
        with self.subTest(mutation="non-canonical but equal JSON"):
            (self.log_dir / ce.RESULT_FILE).write_text(json.dumps(self.result_dict()), encoding="utf-8")
            self.assert_rejected(request)

    def result_dict(self) -> dict:
        return json.loads((self.log_dir / ce.RESULT_FILE).read_text(encoding="utf-8"))

    def test_the_wrong_party_and_the_wrong_expected_request_are_rejected(self):
        request, _, _ = self.produce()
        for field in support.IDS:
            with self.subTest(wrong=field):
                self.assert_rejected(request, **{field: "someone-else"})
        other_limits = {**request, "limits": support.limits(pids=31)}
        other_argv = {**request, "argv": ["/bin/echo", "other"]}
        other_permission = {**request, "permission": support.permission(now="2026-09-20T12:00:01Z")}
        for label, expected in (("limits", other_limits), ("argv", other_argv), ("permission", other_permission)):
            with self.subTest(expected_request=label):
                self.assert_rejected(expected)
        with self.subTest(wrong="registry"):
            directory = self.root / "images"
            directory.mkdir()
            (directory / "fixture-harmless.json").write_text(json.dumps(
                {**support.fixture_record(), "purpose": "a different record for the same digest"}), encoding="utf-8")
            self.assert_rejected(request, images_dir=directory)
        with self.subTest(wrong="attempt root"):
            errors = ce.verify_container_result(self.root / "missing", **support.IDS, request=request,
                                                images_dir=ce.IMAGES_DIR, **support.host_facts())
            self.assertEqual(errors, ["the attempt root, the expected request and the host facts do not "
                                      "derive a docker run the adapter could have made"])
            self.log_dir.rename(self.attempt / "moved")
            self.assertEqual(support.verify(self.attempt, request), [
                "the log directory or its container-result.json is missing, linked or unreadable"])

    def test_impossible_outcome_shapes_are_rejected_even_when_rehashed(self):
        request, _, _ = self.produce()
        golden = self.result_dict()
        shapes = [
            {"cause": None, "execution_status": "OK", "exit_code": 1},
            {"cause": "CONTAINER_EXIT_NONZERO", "execution_status": "FAILED", "exit_code": 0},
            {"cause": "CONTAINER_EXIT_NONZERO", "execution_status": "OK", "exit_code": 2},
            {"cause": "TIMEOUT", "execution_status": "FAILED", "exit_code": 0},
            {"cause": "PERMISSION_DENIED", "execution_status": "BLOCKED", "exit_code": None},
            {"cause": "CLEANUP_FAILED", "execution_status": "FAILED", "exit_code": None},
            {"cause": None, "execution_status": "OK", "exit_code": 0, "container_removed": False},
            {"cause": None, "execution_status": "OK", "exit_code": 0, "streams": None},
        ]
        for shape in shapes:
            with self.subTest(shape=shape):
                self.write({**deepcopy(golden), **shape}, True)
                self.assert_rejected(request)

    def test_envelope_artifacts_are_hashed_from_disk_and_output_paths_are_single_spellings(self):
        request, _, _ = self.produce()
        (self.attempt / "scratch").mkdir(exist_ok=True)
        (self.attempt / "scratch" / "report.json").write_text("{}", encoding="utf-8")
        arguments = {**support.IDS, "request": request, "images_dir": ce.IMAGES_DIR, **support.host_facts(),
                     "input_fingerprint": "sha256:" + "0" * 64, "output_contract": "fixture-contract",
                     "resume_command": None}
        envelope = ce.to_worker_envelope(self.attempt, **arguments, output_paths=["scratch/report.json"])
        paths = [artifact["path"] for artifact in envelope["artifacts"]]
        self.assertEqual(paths, [f"logs/container/{n}" for n in list(ce.ATTEMPT_FILES)]
                         + ["logs/container/container-result.json", "scratch/report.json"])
        self.assertEqual(envelope["retry"], {"allowed": False, "resume_command": None})
        hostile = ["../outside", "/etc/passwd", "scratch/./report.json", "scratch//report.json",
                   "scratch/missing.json", "scratch", "logs/container/stdout.log", 7]
        if SYMLINKS:
            (self.attempt / "scratch" / "link.json").symlink_to(self.root / "target" / "source.c")
            hostile.append("scratch/link.json")
        for path in hostile:
            with self.subTest(path=path), self.assertRaises(ce.ContainerRequestError) as caught:
                ce.to_worker_envelope(self.attempt, **arguments, output_paths=[path])
            self.assertNotIn("outside", str(caught.exception))
        for name in arguments:
            with self.subTest(omitted=name), self.assertRaises(TypeError):
                ce.to_worker_envelope(self.attempt, output_paths=[],
                                      **{k: v for k, v in arguments.items() if k != name})



class VerifierMountParityTests(ScriptedCase):
    """PR 29 review [P1]: run_container applied the target-mount rule and the verification path did
    not, so verify_container_result -- and to_worker_envelope behind it -- certified a self-consistent
    attempt whose request mounted /etc, the host home, the attempt or the docker socket: states the
    adapter can never produce. The forgery is built the way a forger would build it: the mount rule
    is disabled ONLY while the attempt is materialized; the verifier and the envelope mapper then
    run unmodified. The suite missed it because every verifier test started from a request that
    run_container had already accepted."""

    def forge(self, mounts):
        request = support.request(None, ["/bin/echo", "hello"], target_mounts=mounts)

        def permissive(req, *, attempt_root, host_flavor, docker_host):
            return [(ce.translate_host_path(mount["host_path"], host_flavor), mount["container_path"])
                    for mount in req["target_mounts"]]
        first, second = ScriptedDocker().patches()
        with first, second, mock.patch.object(ce, "request_mount_sources", permissive):
            support.run(support.runtime(), self.attempt, request)
        return request

    def envelope_arguments(self, request):
        return {**support.IDS, "request": request, "images_dir": ce.IMAGES_DIR, **support.host_facts(),
                "input_fingerprint": "sha256:" + "0" * 64, "output_contract": "fixture-contract",
                "output_paths": [], "resume_command": None}

    def assert_uncertifiable(self, request):
        errors = support.verify(self.attempt, request)
        self.assertEqual(errors, ["the expected request mounts a host directory the adapter refuses to mount "
                                  "(missing, linked, sensitive, or the same directory twice): no run of it can exist"])
        with self.assertRaises(ce.ContainerRequestError):
            ce.load_verified_result(self.attempt, **{**support.IDS, "request": request,
                                                     "images_dir": ce.IMAGES_DIR, **support.host_facts()})
        with self.assertRaises(ce.ContainerRequestError):
            ce.to_worker_envelope(self.attempt, **self.envelope_arguments(request))

    @unittest.skipUnless(os.name == "posix", "/etc is a POSIX location; the parity test below is host-independent")
    def test_the_reviewers_case_etc_mounted_read_only_as_workspace(self):
        request = self.forge([{"host_path": "/etc", "container_path": "/workspace"}])
        self.assertTrue((self.log_dir / ce.RESULT_FILE).is_file())  # the forgery is complete and self-consistent
        self.assert_uncertifiable(request)

    def test_run_and_verify_refuse_exactly_the_same_mounts(self):
        """One rule, two callers. For each mount: run_container refuses it if and only if the
        verifier, the loader and the envelope mapper refuse a forged attempt that used it."""
        inside = self.attempt / "inner"
        inside.mkdir()
        second = self.root / "second"
        second.mkdir()
        cases = {
            "the legitimate target": [{"host_path": str(self.target), "container_path": "/workspace"}],
            "two distinct directories": [{"host_path": str(self.target), "container_path": "/workspace"},
                                         {"host_path": str(second), "container_path": "/inputs/second"}],
            "the attempt itself": [{"host_path": str(self.attempt), "container_path": "/workspace"}],
            "inside the attempt": [{"host_path": str(inside), "container_path": "/workspace"}],
            "an ancestor of the attempt": [{"host_path": str(self.root), "container_path": "/workspace"}],
            "the host home": [{"host_path": str(Path.home()), "container_path": "/workspace"}],
            "one directory twice": [{"host_path": str(self.target), "container_path": "/workspace"},
                                    {"host_path": str(self.target), "container_path": "/inputs/second"}],
            "a missing directory": [{"host_path": str(self.root / "absent"), "container_path": "/workspace"}],
        }
        if os.name == "posix":
            cases["/etc"] = [{"host_path": "/etc", "container_path": "/workspace"}]
            cases["/proc"] = [{"host_path": "/proc", "container_path": "/workspace"}]
        outcomes = {}
        for label, mounts in cases.items():
            with self.subTest(mount=label):
                for leftover in ("logs", "scratch"):
                    shutil.rmtree(self.attempt / leftover, ignore_errors=True)
                request = support.request(None, ["/bin/echo", "hello"], target_mounts=mounts)
                try:
                    first, second_patch = ScriptedDocker().patches()
                    with first, second_patch:
                        support.run(support.runtime(), self.attempt, request)
                    runs = True
                except ce.ContainerRequestError:
                    runs = False
                for leftover in ("logs", "scratch"):
                    shutil.rmtree(self.attempt / leftover, ignore_errors=True)
                forged = self.forge(mounts)
                verifies = support.verify(self.attempt, forged) == []
                self.assertEqual(runs, verifies, "execution and verification disagree about this mount")
                if runs:
                    ce.to_worker_envelope(self.attempt, **self.envelope_arguments(forged))
                else:
                    self.assert_uncertifiable(forged)
                outcomes[label] = runs
        self.assertTrue(outcomes["the legitimate target"] and outcomes["two distinct directories"])
        self.assertFalse(any(allowed for label, allowed in outcomes.items()
                             if label not in ("the legitimate target", "two distinct directories")))

    def test_a_mount_that_vanishes_after_the_run_fails_closed(self):
        request, _, _ = self.produce()
        self.assertEqual(support.verify(self.attempt, request), [])
        shutil.rmtree(self.target)
        self.assertTrue(support.verify(self.attempt, request))

    def test_the_host_facts_are_required_and_typed(self):
        request, _, _ = self.produce()
        with self.assertRaises(TypeError):
            support.verify(self.attempt, request, host_flavor="solaris")
        with self.assertRaises(TypeError):
            support.verify(self.attempt, request, docker_host=7)


# ---- PR 29 review, round 2 -----------------------------------------------------------------------

class ResealCase(VerifierCase):
    def reseal(self, edit_result=None):
        """The reviewer's resealer: re-hash every listed file, optionally edit, re-hash the result."""
        result = self.result()
        if edit_result:
            edit_result(result)
        for entry in result["files"]:
            data = (self.log_dir / entry["path"]).read_bytes()
            entry.update(sha256=ce._bytes_sha(data), bytes=len(data))
        self.write(result, rehash=True)

    def forge_command(self, edit, *, events_too: bool):
        command = json.loads((self.log_dir / "command.json").read_text(encoding="utf-8"))
        edit(command)
        (self.log_dir / "command.json").write_text(json.dumps(command), encoding="utf-8")
        if events_too:          # a forger who keeps events.jsonl consistent gets no further
            lines = (self.log_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
            rewritten = []
            for line in lines:
                item = json.loads(line)
                edit(item)
                rewritten.append(json.dumps(item, sort_keys=True))
            (self.log_dir / "events.jsonl").write_text("\n".join(rewritten) + "\n", encoding="utf-8")
        self.reseal()


class RecordFeedsNothingTests(ResealCase):
    """P1: the scratch source, the docker executable and the container user used to be lifted out
    of command.json and fed back into the 're-derived' argv, so the record agreed with itself."""

    def test_the_reviewers_five_forgeries_of_command_json_are_rejected_everywhere(self):
        def scratch(source):
            def edit(record):
                at = max(k for k, v in enumerate(record["argv"]) if v == "--mount")
                record["argv"][at + 1] = f"type=bind,source={source},target=/scratch"
            return edit

        def executable_and_user(record):
            record["argv"][0] = "/tmp/" + MARKER + "/docker"
            record["argv"][record["argv"].index("--user") + 1] = "1:0"
        forgeries = {
            "/etc/scratch": scratch("/etc/scratch"),
            "~/.ssh/scratch": scratch(str(Path.home() / ".ssh" / "scratch")),
            "docker.sock/scratch": scratch("/var/run/docker.sock/scratch"),
            "/scratch": scratch("/scratch"),
            "marker/scratch": scratch("/" + MARKER + "/scratch"),
            "docker executable and --user 1:0": executable_and_user,
        }
        for label, edit in forgeries.items():
            for events_too in (False, True):
                with self.subTest(forgery=label, events_too=events_too):
                    self.tearDown()
                    self.setUp()
                    request, _, _ = self.produce(request=support.request(None, ["/bin/true"]))
                    self.assertEqual(support.verify(self.attempt, request), [])
                    self.forge_command(edit, events_too=events_too)
                    self.assert_rejected(request)

    def test_the_callers_docker_executable_and_container_user_decide_not_the_record(self):
        request, _, _ = self.produce()
        self.assertEqual(support.verify(self.attempt, request), [])
        other = self.root / "other-docker"
        self.assert_rejected(request, docker_executable=other)
        self.assert_rejected(request, container_user="4242:4242")
        self.assert_rejected(request, docker_host="unix:///run/user/1/docker.sock")
        facts = support.host_facts()
        for name in ("host_flavor", "docker_host", "docker_executable", "container_user"):
            for function, extra in ((ce.verify_container_result, {}), (ce.load_verified_result, {}),
                                    (ce.to_worker_envelope, {
                                        "input_fingerprint": "sha256:" + "0" * 64, "output_contract": "c",
                                        "output_paths": [], "resume_command": None})):
                with self.subTest(omitted=name, function=function.__name__):
                    arguments = {**support.IDS, "request": request, "images_dir": ce.IMAGES_DIR,
                                 **facts, **extra}
                    del arguments[name]
                    with self.assertRaises(TypeError):
                        function(self.attempt, **arguments)
        for over in ({"docker_executable": str(facts["docker_executable"])},
                     {"docker_executable": Path("docker")}, {"container_user": "0:0"},
                     {"container_user": "1:0"}, {"container_user": "root"}, {"container_user": None}):
            with self.subTest(mistyped=str(over)):
                with self.assertRaises(TypeError):
                    support.verify(self.attempt, request, **over)

    def test_group_zero_is_never_a_legal_container_user(self):
        request = support.request(self.target, ["/bin/true"])
        self.rejected(request, "gid 0", runtime=support.runtime(container_user="1000:0"))
        with self.assertRaises(ce.ContainerRequestError):
            ce.build_docker_argv(**{**golden_arguments("posix"), "user": "1:0"})

    def test_a_different_spelling_of_the_attempt_root_does_not_verify(self):
        request, _, _ = self.produce()
        moved = self.root / "elsewhere"
        self.attempt.rename(moved)
        self.assertTrue(support.verify(moved, request))


class OutcomeRederivationTests(ResealCase):
    """P2: the outcome table ended in ``.get(cause, True)``; events.jsonl was hashed but never
    read; command.json bound a log's length only."""

    EXITED = {"Status": "exited", "OOMKilled": False}

    def runs(self):
        return {
            "exit 0": ScriptedDocker(),
            "exit 1": ScriptedDocker(client_exit=1),
            "exit 137": ScriptedDocker(client_exit=137, state={**self.EXITED, "ExitCode": 137}),
            "oom": ScriptedDocker(client_exit=137, state={**self.EXITED, "ExitCode": 137, "OOMKilled": True}),
            "client and container disagree": ScriptedDocker(client_exit=1, state={**self.EXITED, "ExitCode": 0}),
            "state unreadable": ScriptedDocker(client_exit=1, state=None),
            "start failed": ScriptedDocker(client_exit=127, state={"Status": "created", "ExitCode": 127,
                                                                   "OOMKilled": False}),
            "timed out": ScriptedDocker(client_exit=-9, metadata={"timed_out": True, "error": "TimeoutError: x"}),
            "cancelled": ScriptedDocker(client_exit=-9, metadata={"cancelled": True, "error": "InterruptedError: x"}),
            "log write failed": ScriptedDocker(metadata={"error": "diagnostic stream failure: OSError: disk"}),
        }

    def test_every_cause_against_every_client_record_only_the_derived_outcome_verifies(self):
        accepted = set()
        for label, scripted in self.runs().items():
            self.tearDown()
            self.setUp()
            request, _, genuine = self.produce(scripted=scripted)
            golden = self.result()
            truth = (genuine["cause"], genuine["exit_code"])
            self.assertEqual(support.verify(self.attempt, request), [], label)
            for cause in ce.STATUS_BY_CAUSE:
                for exit_code in (None, 0, 1, 127, 137):
                    with self.subTest(run=label, claimed=cause, exit_code=exit_code):
                        def edit(result):
                            result.update(cause=cause, execution_status=ce.STATUS_BY_CAUSE[cause],
                                          exit_code=exit_code,
                                          container_removed=cause != "CLEANUP_FAILED")
                        self.write(json.loads(json.dumps(golden)), rehash=False)
                        self.reseal(edit)
                        if (cause, exit_code) == truth:
                            self.assertEqual(support.verify(self.attempt, request), [])
                            accepted.add(cause)
                        else:
                            self.assert_rejected(request)
        self.assertEqual(accepted, {None, "CONTAINER_EXIT_NONZERO", "WORKER_LOST", "OOM_KILLED",
                                    "CONTAINER_START_FAILED", "TIMEOUT", "CANCELED", "LOG_WRITE_FAILED"})

    def test_the_reviewers_exit_one_run_cannot_be_reclassified_by_a_result_only_edit(self):
        request, _, result = self.produce(request=support.request(None, ["/bin/false"]),
                                          scripted=ScriptedDocker(client_exit=1))
        self.assertEqual((result["cause"], result["exit_code"]), ("CONTAINER_EXIT_NONZERO", 1))
        for cause, code in (("CANCELED", None), ("WORKER_LOST", 0), ("OOM_KILLED", 0), ("WORKER_LOST", None)):
            with self.subTest(cause=cause, exit_code=code):
                self.reseal(lambda r: r.update(cause=cause, execution_status=ce.STATUS_BY_CAUSE[cause],
                                               exit_code=code))
                self.assert_rejected(request)

    def test_a_same_length_forgery_of_a_retained_log_is_rejected(self):
        request, _, _ = self.produce(request=support.request(None, ["/bin/echo", "finding: none"]),
                                     scripted=ScriptedDocker(stdout=b"finding: none\n", stderr=b"warn: a\n"))
        for name, forged in (("stdout.log", b"finding: RCE!\n"), ("stderr.log", b"warn: b\n")):
            with self.subTest(file=name):
                path = self.log_dir / name
                original = path.read_bytes()
                self.assertEqual(len(original), len(forged))
                path.write_bytes(forged)
                self.reseal()
                self.assert_rejected(request)
                path.write_bytes(original)
                self.reseal()
                self.assertEqual(support.verify(self.attempt, request), [])

    def test_events_jsonl_is_read_and_cross_checked_not_just_hashed(self):
        request, _, _ = self.produce()
        path = self.log_dir / "events.jsonl"
        original = path.read_bytes()
        start, end = (json.loads(line) for line in original.decode("utf-8").splitlines())

        def lines(*items):
            return "".join(json.dumps(item, sort_keys=True) + "\n" for item in items).encode("utf-8")
        forgeries = {
            "garbage": b"not json at all\n", "emptied": b"", "start only": lines(start),
            "two ends": lines(end, end), "end before start": lines(end, start),
            "three events": lines(start, start, end), "not objects": b"[]\n[]\n",
            "unknown event": lines(start, {**end, "event": "FAILURE"}),
            "end disagrees with command.json": lines(start, {**end, "exit_code": 9}),
            "end carries an extra key": lines(start, {**end, MARKER: 1}),
            "start already knows the exit": lines({**start, "exit_code": 0}, end),
            "start ran another argv": lines({**start, "argv": [MARKER]}, end),
            "torn last line": original + b'{"event":',
            "no time": lines(start, {k: v for k, v in end.items() if k != "time"}),
        }
        for label, data in forgeries.items():
            with self.subTest(events=label):
                path.write_bytes(data)
                self.reseal()
                self.assert_rejected(request)
        path.write_bytes(lines(end))            # producible: the START write failed, END did not
        self.reseal()
        self.assertEqual(support.verify(self.attempt, request), [])

    def test_observation_json_is_closed_and_every_field_is_bound(self):
        request, _, _ = self.produce(scripted=ScriptedDocker(client_exit=1))
        path = self.log_dir / ce.OBSERVATION_FILE
        golden = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(golden["state"], {"exit_code": 1, "exited": True, "created": False, "oom_killed": False})
        edits = {
            "interrupted": {**golden, "interrupted": True},
            "state exit": {**golden, "state": {**golden["state"], "exit_code": 0}},
            "state oom": {**golden, "state": {**golden["state"], "oom_killed": True}},
            "state null": {**golden, "state": None},
            "not removed": {**golden, "removed": False},
            "stdout hash": {**golden, "stream_sha256": {**golden["stream_sha256"], "stdout": "sha256:" + "0" * 64}},
            "stdout hash null": {**golden, "stream_sha256": {**golden["stream_sha256"], "stdout": None}},
            "extra key": {**golden, MARKER: True},
            "missing key": {k: v for k, v in golden.items() if k != "removed"},
            "other schema": {**golden, "schema": ce.OBSERVATION_ID + "x"},
            "state extra key": {**golden, "state": {**golden["state"], MARKER: 1}},
            "bool as int": {**golden, "state": {**golden["state"], "exit_code": True}},
        }
        for label, value in edits.items():
            with self.subTest(observation=label):
                path.write_bytes(ce.canonical_request_bytes(value))
                self.reseal()
                self.assert_rejected(request)
        with self.subTest(observation="non-canonical but equal"):
            path.write_text(json.dumps(golden), encoding="utf-8")
            self.reseal()
            self.assert_rejected(request)
        with self.subTest(observation="deleted and unlisted"):
            path.unlink()
            self.reseal(lambda r: r.__setitem__("files", [e for e in r["files"]
                                                          if e["path"] != ce.OBSERVATION_FILE]))
            self.assert_rejected(request)

    def test_an_observation_that_cannot_be_written_is_a_log_write_failure_that_still_verifies(self):
        real = ce.atomic_bytes

        def failing(path, value):
            if Path(path).name == ce.OBSERVATION_FILE:
                raise OSError("disk full")
            return real(path, value)
        scripted = ScriptedDocker()
        first, second = scripted.patches()
        request = support.request(self.target, ["/bin/true"])
        with first, second, mock.patch.object(ce, "atomic_bytes", side_effect=failing):
            result = support.run(support.runtime(), self.attempt, request)
        self.assertEqual((result["cause"], result["execution_status"]), ("LOG_WRITE_FAILED", "FAILED"))
        self.assertEqual(support.verify(self.attempt, request), [])
        self.reseal(lambda r: r.update(cause=None, execution_status="OK", exit_code=0))
        self.assert_rejected(request)


class EveryCompletedRunVerifiesTests(ScriptedCase):
    """P2 invariant: every request run_container accepts and completes also verifies. The
    redactor's keywords in a path, and docker option spellings in the container's own argv, made
    genuine runs permanently unverifiable."""

    ARGVS = (["/bin/echo", "--mount", "x"], ["/bin/echo", "--user", "0:0"], ["/bin/echo", "--network", "host"],
             ["/bin/echo", "--mount", "type=bind,source=/etc,target=/scratch"],
             ["/bin/echo", "--password", "p"], ["/bin/echo", "api_key=1", "--token"], ["/bin/true"])
    SCRATCHES = ("scratch", "secret-scan/scratch", "token-audit", "work/api-key/password")
    ROOTS = ("attempt", "secrets-detection/attempt", "02-secrets-inventory/token/attempt")

    def test_keyword_bearing_paths_and_option_shaped_argv_all_verify(self):
        for root in self.ROOTS:
            for scratch in self.SCRATCHES:
                for argv in self.ARGVS:
                    with self.subTest(root=root, scratch=scratch, argv=argv):
                        self.tearDown()
                        self.setUp()
                        self.attempt = self.root.joinpath(*root.split("/"))
                        self.attempt.mkdir(parents=True, exist_ok=True)
                        request = support.request(self.target, argv, scratch_path=scratch,
                                                  log_path="logs/secret-token")
                        _, _, result = self.produce(request=request)
                        self.assertEqual(result["execution_status"], "OK")
                        self.assertEqual(support.verify(self.attempt, request), [])

    def test_a_redacted_record_still_cannot_be_verified_against_another_request(self):
        request = support.request(self.target, ["/bin/echo", "--mount", "x"], scratch_path="secret-scan/scratch")
        self.produce(request=request)
        self.assertTrue(support.verify(self.attempt, {**request, "argv": ["/bin/echo", "--mount", "y"]}))
        self.assertTrue(support.verify(self.attempt, request, container_user="4242:4242"))


class HostHomeTests(Sandbox):
    """P2: the mount rule's host home was $HOME alone -- an unstated environment input."""

    def mountable(self, path: Path) -> bool:
        request = {"target_mounts": [{"host_path": str(path), "container_path": "/workspace"}]}
        try:
            ce.request_mount_sources(request, attempt_root=self.attempt,
                                     host_flavor=support.runtime().host_flavor, docker_host=None)
        except ce.ContainerRequestError:
            return False
        return True

    def homes(self):
        account, environment = self.root / "account-home", self.root / "env-home"
        for home in (account, environment):
            (home / ".ssh").mkdir(parents=True)
            (home / ".docker").mkdir()
            (home / "projects").mkdir()
        return account, environment

    @unittest.skipIf(os.name == "nt", "the password database is POSIX only")
    def test_the_account_home_is_refused_wherever_the_environment_points_home(self):
        import pwd
        account, environment = self.homes()
        entry = mock.Mock(pw_dir=str(account))
        for variable in (str(environment), "/nonexistent", None):
            with self.subTest(HOME=variable), mock.patch.object(pwd, "getpwuid", return_value=entry), \
                    mock.patch.dict(os.environ):
                os.environ.pop("HOME", None)
                if variable is not None:
                    os.environ["HOME"] = variable
                for path in (account, account / ".ssh", account / ".docker", self.root):
                    self.assertFalse(self.mountable(path), path.name)
                self.assertTrue(self.mountable(account / "projects"))
                if variable == str(environment):     # the union: $HOME stays refused as well
                    for path in (environment, environment / ".ssh", environment / ".docker"):
                        self.assertFalse(self.mountable(path), path.name)
                    self.assertEqual(ce.host_homes(), (account, environment))

    @unittest.skipIf(os.name == "nt", "the password database is POSIX only")
    def test_the_reviewers_case_the_real_account_home_with_home_pointed_elsewhere(self):
        import pwd
        try:
            real = Path(pwd.getpwuid(os.getuid()).pw_dir)
        except KeyError:                     # a uid with no database entry has no such home
            self.assertIsInstance(ce.host_homes(), tuple)
            return
        with mock.patch.dict(os.environ, {"HOME": "/nonexistent"}):
            self.assertIn(real, ce.host_homes())
            for path in (real, real / ".ssh", real / ".docker", real / ".config"):
                if path.is_dir():
                    with self.subTest(path=path.name):
                        self.assertFalse(self.mountable(path))
                        self.rejected(support.request(path, ["/bin/true"]), "host home|credential directory")

    def test_without_a_password_database_the_environment_home_is_still_refused(self):
        _, environment = self.homes()
        with mock.patch.dict(sys.modules, {"pwd": None}), \
                mock.patch.object(ce.Path, "home", return_value=environment):
            self.assertEqual(ce.host_homes(), (environment,))
            self.assertFalse(self.mountable(environment))
            self.assertFalse(self.mountable(environment / ".ssh"))
            self.assertTrue(self.mountable(environment / "projects"))
        with mock.patch.dict(sys.modules, {"pwd": None}), \
                mock.patch.object(ce.Path, "home", side_effect=RuntimeError("no home")):
            self.assertEqual(ce.host_homes(), ())


# ---- adapter wiring and documentation ------------------------------------------------------------

class AdapterWiringTests(ScriptedCase):
    def test_pinned_container_adapter_runs_the_request_in_worker_inputs(self):
        adapter = PinnedContainerAdapter(support.runtime())
        self.assertEqual(adapter.kind, ce.WORKER_KIND)
        request = support.request(self.target, ["/bin/echo", "hello"])
        worker_request = WorkerRequest(support.RUN, support.JOB, support.ATTEMPT, self.attempt,
                                       {"container_request": request})
        first, second = ScriptedDocker().patches()
        with first, second:
            result = adapter.execute(worker_request)
        self.assertEqual(result["execution_status"], "OK")
        self.assertEqual(support.verify(self.attempt, request), [])

    def test_adapter_requires_a_runtime_and_a_container_request(self):
        with self.assertRaises(TypeError):
            PinnedContainerAdapter()
        with self.assertRaises(TypeError):
            PinnedContainerAdapter({"docker": "docker"})
        adapter = PinnedContainerAdapter(support.runtime())
        for inputs in ({}, {"request": {}}, []):
            with self.subTest(inputs=inputs), self.assertRaises(ce.ContainerRequestError):
                adapter.execute(WorkerRequest(support.RUN, support.JOB, support.ATTEMPT, self.attempt, inputs))
        wrong_party = WorkerRequest("another-run", support.JOB, support.ATTEMPT, self.attempt,
                                    {"container_request": support.request(self.target, ["/bin/true"])})
        with self.assertRaisesRegex(ce.ContainerRequestError, "run_id is not the run_id"):
            adapter.execute(wrong_party)

    def test_unimplemented_kinds_still_raise_before_work(self):
        worker_request = WorkerRequest(support.RUN, support.JOB, support.ATTEMPT, self.attempt, {})
        for kind in ("persona", "pool_coordinator", "join_controller"):
            with self.subTest(kind=kind), self.assertRaises(NotImplementedError):
                UnsupportedWorkerAdapter(kind).execute(worker_request)


class DocumentationTests(unittest.TestCase):
    DOC = ROOT.parent / "docs" / "adapters" / "pinned-container-adapter.md"
    SECTIONS = ["Status", "Wrapper identity", "Boundary 1.0", "Request", "Image registry", "Mounts and paths",
                "Permission gate and network", "Execution and outcomes", "Result and verification",
                "Worker-result envelope", "Windows-host and Linux-worker parity", "Fixture image",
                "Limitations", "Integration follow-ups"]

    def test_document_sections_are_an_allow_list(self):
        text = self.DOC.read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"^## (.+)$", text, flags=re.M), self.SECTIONS)
        self.assertEqual(re.findall(r"^# (.+)$", text, flags=re.M), ["Pinned-container argv adapter"])

    def test_document_names_every_boundary_flag_cause_limit_and_identity(self):
        text = self.DOC.read_text(encoding="utf-8")
        flags = [flag for flag in ce.BOUNDARY_FLAGS if flag.startswith("--")]
        for needle in (*flags, *[c for c in ce.STATUS_BY_CAUSE if c], *ce.LIMIT_BOUNDS, *ce.ENVIRONMENT_NAMES,
                       ce.ADAPTER_ID, ce.BOUNDARY_ID, ce.REQUEST_ID, ce.RESULT_ID, ce.IMAGE_RECORD_ID,
                       support.fixture_record()["digest"], "images/audit-native/run.sh",
                       "images/audit-buildenv-common/run.sh"):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)
        for line in text.splitlines():
            self.assertLessEqual(len(line), 240, "free-text line is unbounded")
            self.assertNotRegex(line, r"[\x00-\x08\x0b-\x1f]")


if __name__ == "__main__":
    unittest.main()
