"""Every tracked shell script with a shebang is executable in Git (2026-10-01: run.sh, tail-run-log.sh and
13 more were 100644, so calling them directly failed with Permission denied)."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest

REPO = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which("git") and (REPO / ".git").exists(), "needs a git checkout")
class ScriptModes(unittest.TestCase):
    def test_shebang_scripts_are_executable(self):
        listing = subprocess.run(["git", "-C", str(REPO), "ls-files", "-s", "--", "*.sh"],
                                 capture_output=True, text=True, check=True).stdout
        missing = []
        for line in listing.splitlines():
            mode, _, rest = line.partition(" ")
            path = rest.split("\t", 1)[1]
            with (REPO / path).open("rb") as handle:
                if handle.read(2) == b"#!" and mode != "100755":
                    missing.append(path)
        self.assertEqual(missing, [], "git update-index --chmod=+x " + " ".join(missing))


if __name__ == "__main__":
    unittest.main()
