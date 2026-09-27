import os
from pathlib import Path
import unittest
from unittest import mock

from images import image_build


class ImageBuildEnvironmentTests(unittest.TestCase):
    def test_environment_is_allowlisted_and_preserves_windows_plugin_discovery(self):
        host = {
            "PATH": r"C:\\Program Files\\Docker\\Docker\\resources\\bin",
            "SYSTEMROOT": r"C:\\Windows",
            "USERPROFILE": r"C:\\Users\\operator",
            "PROGRAMFILES": r"C:\\Program Files",
            "APPDATA": r"C:\\Users\\operator\\AppData\\Roaming",
            "SECRET_TOKEN": "must-not-pass",
        }
        with mock.patch.dict(os.environ, host, clear=True):
            child = image_build._environment()

        self.assertEqual(child["DOCKER_BUILDKIT"], "1")
        self.assertEqual(child["PROGRAMFILES"], host["PROGRAMFILES"])
        self.assertEqual(child["APPDATA"], host["APPDATA"])
        self.assertNotIn("SECRET_TOKEN", child)

    def test_build_command_disables_unstable_manifest_provenance(self):
        build = {"docker_context": None, "no_cache": False,
                 "build_args": {"Z": "last", "A": "first"},
                 "tag": "audit-test:local"}
        command = image_build._build_command(
            Path("docker"), build, Path("context"), Path("context/Dockerfile"))

        self.assertIn("--provenance=false", command)
        self.assertEqual(command[-4:], [str(Path("context/Dockerfile")), "-t",
                                        "audit-test:local", str(Path("context"))])
        self.assertLess(command.index("A=first"), command.index("Z=last"))


if __name__ == "__main__":
    unittest.main()
