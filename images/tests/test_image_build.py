import os
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


if __name__ == "__main__":
    unittest.main()
