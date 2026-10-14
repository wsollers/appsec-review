from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def test_current_documentation_local_links_resolve() -> None:
    roots = (ROOT / "README.md", ROOT / "docs", ROOT / "containers", ROOT / "deploy")
    files = [roots[0]]
    for directory in roots[1:]:
        files.extend(directory.rglob("*.md"))
    missing: list[str] = []
    for document in files:
        for match in LINK.finditer(document.read_text(encoding="utf-8")):
            target = match.group(1).strip("<>")
            if (not target or target.startswith(("#", "http://", "https://", "mailto:", "app://")) or
                    target.split("#", 1)[0].startswith("../../old/")):
                continue
            relative = unquote(target.split("#", 1)[0])
            if relative and not (document.parent / relative).resolve().exists():
                missing.append(f"{document.relative_to(ROOT).as_posix()}: {target}")
    assert missing == []
