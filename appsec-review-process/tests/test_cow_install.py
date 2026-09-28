import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cow_install as cow  # noqa: E402

LOG = """CMake Error at CMakeLists.txt:40 (find_package):
  Could not find a package configuration file provided by "Qt6" with any of
  the following names:

    Qt6Config.cmake
    qt6-config.cmake

  Add the installation prefix of "Qt6" to CMAKE_PREFIX_PATH
-- Checking for module 'sdl2'
--   No package 'sdl2' found
-- The following required packages were not found:

 - SDL2_mixer>=2.0
 - libzstd

src/a.c:3:10: fatal error: lua.h: No such file or directory
/bin/sh: 1: gettext: not found
Could NOT find KF6Archive
"""


class MissingFromLogsTests(unittest.TestCase):
    def test_each_kind_is_found_once_with_file_regexes(self):
        needs = {f"{n['kind']}:{n['name']}": n["regexes"] for n in cow.missing_from_logs(LOG)}
        self.assertIn("cmake-config:Qt6", needs)
        self.assertTrue(any("Qt6Config" in r for r in needs["cmake-config:Qt6"]))
        for module in ("sdl2", "SDL2_mixer", "libzstd"):
            self.assertIn(f"pkg-config:{module}", needs)
        self.assertIn("header:lua.h", needs)
        self.assertIn("program:gettext", needs)
        self.assertIn("cmake-module:KF6Archive", needs)

    def test_shells_and_build_tools_are_not_programs_to_install(self):
        needs = cow.missing_from_logs("/bin/sh: 1: sh: not found\nmake: not found\n")
        self.assertEqual([n for n in needs if n["kind"] == "program"], [])


class RankingTests(unittest.TestCase):
    def test_plan_then_stem_then_depth(self):
        calls = []

        def fake_query(resolver, script, *, log, timeout=600):
            calls.append(script)
            return ("@@ 0 0\nlibdmlc-dev: /usr/include/dmlc/lua.h\n"
                    "liblua5.2-dev: /usr/include/lua5.2/lua.h\nliblua5.3-dev: /usr/include/lua5.3/lua.h\n")
        original = cow._resolver_query
        cow._resolver_query = fake_query
        try:
            needs = [{"kind": "header", "name": "lua.h", "regexes": [r"/include/(?:.*/)?lua\.h$"]}]
            self.assertEqual(cow.packages_for("r", needs, log=Path("/dev/null"))["header:lua.h"], "liblua5.2-dev")
            self.assertEqual(cow.packages_for("r", needs, log=Path("/dev/null"), prefer={"liblua5.3-dev"})["header:lua.h"],
                             "liblua5.3-dev")
        finally:
            cow._resolver_query = original
        self.assertEqual(len(calls), 2)   # one container per lookup round, not per regex


if __name__ == "__main__":
    unittest.main()


class OfflineDownloads(unittest.TestCase):
    def test_download_failures_are_named(self):
        text = ("CMake Error at Libertinus-stamp/download-Libertinus.cmake:163 (message):\n  Each download failed!\n"
                "    error: downloading 'https://example.org/f.zip' failed\n"
                "          error: downloading 'https://example.org/f.zip' failed\n")
        self.assertEqual(cow.offline_downloads(text), ["https://example.org/f.zip"])
        self.assertEqual(cow.offline_downloads("all good"), [])

