from __future__ import annotations

from pathlib import Path
import subprocess
from urllib.parse import unquote

from scripts.docs_support import links

ROOT = Path(__file__).resolve().parents[1]


def test_current_documentation_local_links_resolve() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "-z", "--", "README.md", "docs", "containers", "deploy"],
        cwd=ROOT, capture_output=True, text=True, check=True, timeout=5,
    )
    files = [ROOT / path for path in sorted(tracked.stdout.split("\0")) if path.endswith(".md")]
    missing: list[str] = []
    for document in files:
        for target in links(document.read_text(encoding="utf-8")):
            if (not target or target.startswith(("#", "http://", "https://", "mailto:", "app://")) or
                    target.split("#", 1)[0].startswith("../../old/")):
                continue
            relative = unquote(target.split("#", 1)[0])
            if relative and not (document.parent / relative).resolve().exists():
                missing.append(f"{document.relative_to(ROOT).as_posix()}: {target}")
    assert missing == []
