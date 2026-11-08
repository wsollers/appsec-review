"""docs/TODO.md is the single TODO registry (AGENTS.md, "Deferred work and TODOs")."""
from __future__ import annotations

from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "docs/TODO.md"
ENTRY = re.compile(r"^### (T-\d{3}) — (.+)$", re.M)
INDEX_ROW = re.compile(r"^\| (T-\d{3}) \| \[(.+?)\]\(#([a-z0-9_-]+)\) \| ([a-z]+) \| (.+?) \|$", re.M)
AREAS = {"build", "topology", "images", "windows", "mobile", "scanners", "codeql", "graph", "native",
         "data", "history", "evidence", "review", "binary", "testing"}
STATE = re.compile(r"^(open|in-progress|blocked|done \(\d{4}-\d{2}-\d{2}, .+\))$")
FIELDS = ("State", "Area", "Why", "Scope", "Done when")


def _tracked_files() -> list[str]:
    result = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True)
    return result.stdout.splitlines()


def _anchor(entry_id: str, title: str) -> str:
    slug = re.sub(r"[^a-z0-9 _-]", "", f"{entry_id} — {title}".lower().replace("—", ""))
    return re.sub(r"\s+", "-", slug.strip())


def _sections() -> tuple[str, str]:
    text = REGISTRY.read_text(encoding="utf-8")
    active = text.index("\n## Active entries\n")
    legacy = text.index("\n## Legacy backlog\n")
    assert active < legacy
    return text[active:legacy], text[legacy:]


def test_the_registry_is_the_only_todo_file() -> None:
    offenders = [path for path in _tracked_files()
                 if re.search(r"(^|/)todo[^/]*\.md$", path, re.I) and path != "docs/TODO.md"]
    assert offenders == [], offenders


def test_ids_are_unique_sequential_and_indexed() -> None:
    text = REGISTRY.read_text(encoding="utf-8")
    index_start = text.index("\n## Index\n")
    body_start = text.index("\n## Active entries\n")
    entries = ENTRY.findall(text[body_start:])
    ids = [entry_id for entry_id, _ in entries]
    assert len(ids) == len(set(ids)), "duplicate TODO id"
    numbers = sorted(int(entry_id[2:]) for entry_id in ids)
    assert numbers == list(range(1, len(numbers) + 1)), "ids must be sequential from T-001 with no gaps"
    rows = INDEX_ROW.findall(text[index_start:body_start])
    indexed = {entry_id: (title, anchor, area, state) for entry_id, title, anchor, area, state in rows}
    assert set(indexed) == set(ids), "index rows and entries must name the same ids"
    for entry_id, title in entries:
        row_title, anchor, area, state = indexed[entry_id]
        assert row_title == title, f"{entry_id}: index title differs from entry title"
        assert anchor == _anchor(entry_id, title), f"{entry_id}: index anchor does not match the heading"
        assert area in AREAS, f"{entry_id}: unknown area {area!r}"
        assert STATE.match(state), f"{entry_id}: malformed state {state!r}"


def test_active_entries_carry_the_required_fields_in_order() -> None:
    active, _ = _sections()
    blocks = re.split(r"^### ", active, flags=re.M)[1:]
    assert blocks, "no active entries"
    for block in blocks:
        heading = block.splitlines()[0]
        entry_id = heading.split(" ")[0]
        positions = []
        for field in FIELDS:
            match = re.search(rf"^- \*\*{re.escape(field)}:\*\*(?: |$)", block, re.M)
            assert match, f"{entry_id}: missing field {field}"
            positions.append(match.start())
        assert positions == sorted(positions), f"{entry_id}: fields out of order"
        state = re.search(r"^- \*\*State:\*\* (.+)$", block, re.M).group(1)
        assert STATE.match(state), f"{entry_id}: malformed state {state!r}"
        area = re.search(r"^- \*\*Area:\*\* (.+)$", block, re.M).group(1)
        assert area in AREAS, f"{entry_id}: unknown area {area!r}"
        for relation in ("Blocked by", "Blocks"):
            match = re.search(rf"^- \*\*{relation}:\*\* (.+)$", block, re.M)
            if match:
                named = re.findall(r"T-\d{3}", match.group(1))
                assert named, f"{entry_id}: empty {relation} line"
                assert entry_id not in named, f"{entry_id}: {relation} names itself"


def test_relations_name_existing_ids() -> None:
    text = REGISTRY.read_text(encoding="utf-8")
    ids = {entry_id for entry_id, _ in ENTRY.findall(text)}
    referenced = set(re.findall(r"\*\*(?:Blocked by|Blocks):\*\* ([^\n]+)", text))
    for line in referenced:
        for named in re.findall(r"T-\d{3}", line):
            assert named in ids, f"relation names unknown id {named}"


def test_code_todo_comments_name_a_registry_id() -> None:
    text = REGISTRY.read_text(encoding="utf-8")
    ids = {entry_id for entry_id, _ in ENTRY.findall(text)}
    offenders = []
    for path in _tracked_files():
        if not path.startswith(("src/", "deploy/", "containers/")) or not path.endswith((".py", ".sh", ".ps1")):
            continue
        for number, line in enumerate((ROOT / path).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if re.search(r"\bTODO\b", line) and not any(entry_id in line for entry_id in ids):
                offenders.append(f"{path}:{number}: {line.strip()[:100]}")
    assert offenders == [], "TODO comments must name a docs/TODO.md id:\n" + "\n".join(offenders)
