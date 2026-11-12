"""Change-log files as a second, weaker history source.

A target is not always delivered with version-control history.  A maintained change log then says
which files changed and when, in the author's own words.  Everything here treats that text as
untrusted data: input is bounded in bytes, line length, entries and paths per entry; a file whose
format is not recognised yields no entries; and author names, e-mail addresses and message text
are consumed while parsing and never returned.  What leaves this module is structured facts only:
dates, entry identifiers, catalog paths, identifier-shaped symbol tokens and a closed-vocabulary
classification.

Change-log signals are never commit-derived and are never added to a Git-derived count.
"""

from __future__ import annotations

import calendar
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timezone
import re
from typing import Any

from .window import WINDOW_IDENTITY, window_start


IDENTITY = "appsec-review/history-changelog/1"
SCHEMA = "appsec-review/source-history-changelog/1"
SOURCE = "changelog"
FORMATS = ("git-log", "svn-log", "gnu-changelog", "keep-a-changelog")
AUTHORITY = ("change-log signals are author-stated and weaker than commit history: dates are claimed, file lists "
             "may be partial and nothing binds an entry to content; they prioritize review and are never "
             "vulnerability evidence")
SEMANTICS = ("change_count counts change-log entries inside the window that name the file; it is not a commit "
             "count and is never added to a Git-derived count")
BINDINGS = ("exact", "suffix", "repository_prefix")
MAX_MESSAGE_CHARS = 65_536
DETECTION_LINES = 200
MAX_SYMBOLS_PER_PATH = 32
MAX_FILE_SYMBOLS = 50
MAX_FILE_REFERENCES = 20
MAX_FILE_EVIDENCE = 5

Classifier = Callable[[str, str], Mapping[str, Any]]

_STEMS = ("changelog", "changes", "news", "history", "release-notes", "release_notes", "releasenotes")
_DOC_EXTENSIONS = frozenset({"md", "markdown", "txt", "rst", "adoc", "old"})
_SECTIONS = frozenset({"added", "changed", "deprecated", "removed", "fixed", "security"})
_MONTHS = {name: number for number, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
_WEEKDAYS = frozenset({"mon", "tue", "wed", "thu", "fri", "sat", "sun"})
_HEX = frozenset("0123456789abcdef")
_STATUS_LETTERS = frozenset("ACDMRTUXB")
# Both patterns are a single bounded character class: linear time on any input.
_PATH_TOKEN = re.compile(r"[A-Za-z0-9_.+~/-]{1,512}")
_SYMBOL = re.compile(r"[A-Za-z_~][A-Za-z0-9_:.~-]{0,127}")
_SKIP = object()


@dataclass(frozen=True, slots=True)
class ChangelogLimits:
    max_files: int
    max_file_bytes: int
    max_entries: int
    max_line_bytes: int
    max_paths_per_entry: int

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__slots__}


def is_changelog_name(path: str) -> bool:
    """Whether a catalog path's file name is a conventional change-log name.

    ``ChangeLog``, ``ChangeLog-1.0``, ``CHANGELOG.md``, ``CHANGES.txt``, ``NEWS-3.2`` and
    ``HISTORY.rst`` match; ``history.c`` and ``news.py`` do not.
    """
    name = path.rsplit("/", 1)[-1].lower()
    for stem in _STEMS:
        if name == stem:
            return True
        if name.startswith(stem) and name[len(stem)] in "-._":
            extension = name.rsplit(".", 1)[-1] if "." in name else ""
            return not extension.isalpha() or extension in _DOC_EXTENSIONS
    return False


def _digits(token: str) -> bool:
    """ASCII digits only: ``str.isdigit`` alone accepts characters such as ``²`` that ``int`` rejects."""
    return token.isascii() and token.isdigit()


def _iso_date(text: str) -> str | None:
    if len(text) != 10 or text[4] != "-" or text[7] != "-":
        return None
    try:
        value = date.fromisoformat(text)
    except ValueError:
        return None
    return text if 1970 <= value.year <= 2100 else None


def _stated_date(text: str) -> str | None:
    """The calendar date an author wrote, in ISO, ctime or RFC 2822 order; never converted between zones."""
    text = text.strip()
    iso = _iso_date(text[:10])
    if iso and (len(text) == 10 or text[10] in " T"):
        return iso
    year = month = day = None
    for token in text.replace(",", " ").split()[:8]:
        lower = token.lower()
        if month is None and lower.isalpha() and len(lower) <= 9 and lower[:3] in _MONTHS:
            month = _MONTHS[lower[:3]]
        elif _digits(token) and len(token) == 4 and year is None:
            year = int(token)
        elif _digits(token) and len(token) <= 2 and day is None:
            day = int(token)
    if year is None or month is None or day is None or not 1970 <= year <= 2100:
        return None
    try:
        return date(year, month, day).isoformat()
    except ValueError:
        return None


def _split_lines(data: bytes, max_line_bytes: int) -> tuple[list[str | None], int, int]:
    """Decode line by line; a line over the bound becomes ``None`` and is never interpreted."""
    raw = data.split(b"\n")
    if raw and raw[-1] == b"":
        raw.pop()
    lines: list[str | None] = []
    overlong = undecodable = 0
    for item in raw:
        if item.endswith(b"\r"):
            item = item[:-1]
        if len(item) > max_line_bytes:
            lines.append(None)
            overlong += 1
            continue
        try:
            lines.append(item.decode("utf-8"))
        except UnicodeDecodeError:
            lines.append(item.decode("utf-8", "replace"))
            undecodable += 1
    return lines, overlong, undecodable


def _git_header(line: str) -> str | None:
    if not line.startswith("commit "):
        return None
    token = line[7:].split(" ", 1)[0]
    return token if len(token) in (40, 64) and all(char in _HEX for char in token) else None


def _svn_header(line: str) -> tuple[str, str | None, int | None] | None:
    if not line.startswith("r") or " | " not in line:
        return None
    parts = line.split(" | ")
    if len(parts) != 4 or not _digits(parts[0][1:]) or len(parts[0]) > 12:
        return None
    count = parts[3].split(" ")
    lines = (int(count[0]) if len(count) == 2 and _digits(count[0]) and len(count[0]) <= 6
             and count[1] in ("line", "lines") else None)
    return parts[0], _iso_date(parts[2][:10]), lines


def _gnu_header(line: str) -> str | None:
    if not line or line[0] in " \t":
        return None
    iso = _iso_date(line[:10])
    if iso and len(line) > 10 and line[10] in " \t":
        return iso
    if line.split(" ", 1)[0].lower() in _WEEKDAYS:
        return _stated_date(line)
    return None


def _marker(line: str) -> str | None:
    """The format whose entry header this column-zero line is, if any."""
    if _git_header(line):
        return "git-log"
    if _svn_header(line):
        return "svn-log"
    if _gnu_header(line):
        return "gnu-changelog"
    if line.startswith("## "):
        return "keep-a-changelog"
    return None


def detect(lines: Sequence[str | None]) -> str | None:
    """The first entry header among the leading non-blank lines decides the format; none means unrecognised."""
    seen = 0
    for line in lines:
        if line is None or not line.strip():
            continue
        found = _marker(line)
        if found:
            return found
        seen += 1
        if seen >= DETECTION_LINES:
            break
    return None


def _unparsed(stats: dict[str, Any], line: str) -> None:
    stats["unparsed_lines"] += 1
    if _marker(line) not in (None, stats["format"]):
        stats["foreign_format_lines"] += 1


def _new(line: int, identity: str | None = None, stated: str | None = None) -> dict[str, Any]:
    return {"line": line, "id": identity, "date": stated, "paths": [], "text": [], "size": 0,
            "cut": False, "paths_cut": False}


def _say(entry: dict[str, Any], text: str) -> None:
    room = MAX_MESSAGE_CHARS - entry["size"]
    if room <= 0 or len(text) > room:
        entry["cut"] = True
    if room > 0:
        entry["text"].append(text[:room])
        entry["size"] += min(len(text), room) + 1


def _name(entry: dict[str, Any], path: str, limits: ChangelogLimits) -> list[str] | None:
    if len(entry["paths"]) >= limits.max_paths_per_entry:
        entry["paths_cut"] = True
        return None
    symbols: list[str] = []
    entry["paths"].append((path, symbols))
    return symbols


def _finish(entry: dict[str, Any], classify: Classifier, stats: dict[str, Any], position: int,
            section: str | None = None) -> dict[str, Any]:
    """Classify the entry's text and discard it; only the labels survive."""
    text = entry["text"]
    labels = dict(classify(text[0].strip() if text else "", "\n".join(text)))
    if section == "security":
        labels["fix"] = labels["security_fix"] = "changelog_section"
    elif section == "fixed" and labels.get("security_fix") is None:
        labels["fix"] = "changelog_section"
    stats["messages_truncated"] += int(entry["cut"])
    stats["entries_paths_truncated"] += int(entry["paths_cut"])
    stats["position"] = position
    return {"line": entry["line"], "id": entry["id"], "date": entry["date"],
            "paths": [(path, tuple(symbols)) for path, symbols in entry["paths"]],
            "fix": labels.get("fix"), "security_fix": labels.get("security_fix"),
            "security_references": list(labels.get("security_references", ())),
            "message_complete": not entry["cut"], "paths_truncated": entry["paths_cut"]}


def _rename_target(path: str) -> str:
    """The new name in Git's ``old => new`` and ``prefix/{old => new}/suffix`` notations."""
    if "{" in path and "}" in path and " => " in path:
        prefix, rest = path.split("{", 1)
        middle, suffix = rest.split("}", 1)
        if " => " in middle:
            return (prefix + middle.split(" => ", 1)[1] + suffix).replace("//", "/")
    if " => " in path:
        return path.split(" => ", 1)[1]
    return path


def _git_path(line: str) -> Any:
    """A path named by a ``--stat``, ``--numstat``, ``--name-status`` or ``--name-only`` row."""
    if line[0] == " ":
        body = line.strip()
        left, separator, _ = body.rpartition(" | ")
        if separator and left.strip():
            return _rename_target(left.strip())
        return _SKIP if _digits(body[:1]) and " changed" in body else None
    fields = line.split("\t")
    if len(fields) in (2, 3) and fields[0][:1] in _STATUS_LETTERS and (
            len(fields[0]) == 1 or (len(fields[0]) <= 4 and _digits(fields[0][1:]))) and fields[-1]:
        return fields[-1]
    if len(fields) == 3 and all(item == "-" or (_digits(item) and len(item) <= 9) for item in fields[:2]) \
            and fields[2]:
        return _rename_target(fields[2])
    return line if len(fields) == 1 and _PATH_TOKEN.fullmatch(line) else None


def _parse_git(lines: Sequence[str | None], stats: dict[str, Any], classify: Classifier,
               limits: ChangelogLimits) -> Iterator[dict[str, Any]]:
    entry: dict[str, Any] | None = None
    in_message = False
    for number, line in enumerate(lines, 1):
        if line is None or not line.strip():
            continue
        commit = _git_header(line)
        if commit:
            if entry is not None:
                yield _finish(entry, classify, stats, number - 1)
            entry, in_message = _new(number, commit), False
            continue
        if entry is None:
            _unparsed(stats, line)
            continue
        if line.startswith(("    ", "\t")):
            _say(entry, line.strip())
            in_message = True
            continue
        if not in_message and line[0] != " ":
            key, separator, value = line.partition(":")
            if separator and len(key) <= 32 and key.replace("-", "").isalpha():
                if key in ("Date", "AuthorDate") and entry["date"] is None:
                    entry["date"] = _stated_date(value)
                continue
        path = _git_path(line)
        if path is None:
            _unparsed(stats, line)
        elif path is not _SKIP:
            _name(entry, path, limits)
    if entry is not None:
        yield _finish(entry, classify, stats, len(lines))


def _separator(line: str) -> bool:
    return len(line) >= 20 and not line.strip("-")


def _parse_svn(lines: Sequence[str | None], stats: dict[str, Any], classify: Classifier,
               limits: ChangelogLimits) -> Iterator[dict[str, Any]]:
    """``svn log [-v]``.  The header's line count delimits the message, so message text cannot forge a header."""
    total, index = len(lines), 0
    while index < total:
        line = lines[index]
        if line is None or not line.strip() or _separator(line):
            index += 1
            continue
        header = _svn_header(line)
        if header is None:
            _unparsed(stats, line)
            index += 1
            continue
        entry = _new(index + 1, header[0], header[1])
        index += 1
        if index < total and lines[index] == "Changed paths:":
            index += 1
            while index < total and (lines[index] is None or lines[index].strip()):
                row = lines[index]
                index += 1
                if row is None:
                    continue
                body = row.strip()
                if len(body) > 2 and body[0] in "AMDR" and body[1] == " ":
                    path = body[2:].strip()
                    if path.endswith(")") and " (from " in path:
                        path = path.rsplit(" (from ", 1)[0]
                    _name(entry, path, limits)
                else:
                    _unparsed(stats, row)
        if index < total and lines[index] is not None and not lines[index].strip():
            index += 1
        if header[2] is not None:
            message = lines[index:index + header[2]]
            index += len(message)
            if len(message) < header[2]:
                # The header claims more message lines than the file holds: whatever it swallowed
                # may hide later entries, so those lines are reported, not trusted as one message.
                stats["unparsed_lines"] += len(message)
        else:
            start = index
            while index < total and not (lines[index] is not None and _separator(lines[index])):
                index += 1
            message = lines[start:index]
        for text in message:
            if text is not None and text.strip():
                _say(entry, text.strip())
        yield _finish(entry, classify, stats, index)


def _gnu_head(head: str) -> tuple[list[str], list[str]]:
    """File names before the first parenthesis and identifier-shaped symbols inside the parentheses."""
    names = [item.strip() for item in head.split("(", 1)[0].split(",")]
    if not all(_PATH_TOKEN.fullmatch(item) for item in names):
        names = []
    symbols: list[str] = []
    start = head.find("(")
    # One forward scan; only a closed group counts, so ``(Closes: ...`` names nothing.
    while start != -1 and len(symbols) < MAX_SYMBOLS_PER_PATH:
        end = head.find(")", start + 1)
        if end == -1:
            break
        symbols.extend(item.strip() for item in head[start + 1:end].split(",") if _SYMBOL.fullmatch(item.strip()))
        start = head.find("(", end + 1)
    return names, symbols[:MAX_SYMBOLS_PER_PATH]


def _parse_gnu(lines: Sequence[str | None], stats: dict[str, Any], classify: Classifier,
               limits: ChangelogLimits) -> Iterator[dict[str, Any]]:
    entry: dict[str, Any] | None = None
    current: list[list[str]] = []
    for number, line in enumerate(lines, 1):
        if line is None or not line.strip():
            continue
        if line[0] not in " \t":
            stated = _gnu_header(line)
            if stated is None:
                _unparsed(stats, line)
                continue
            if entry is not None:
                yield _finish(entry, classify, stats, number - 1)
            entry, current = _new(number, None, stated), []
            continue
        if entry is None:
            _unparsed(stats, line)
            continue
        body = line.strip()
        if body.startswith("* "):
            head, _, tail = body[2:].partition(":")
            names, symbols = _gnu_head(head)
            current = []
            for name in names:
                target = _name(entry, name, limits)
                if target is not None:
                    target.extend(symbols)
                    current.append(target)
            _say(entry, tail if names else body[2:])
        elif body.startswith("(") and current:
            head, _, tail = body.partition(":")
            _, symbols = _gnu_head(head)
            for target in current:
                target.extend(symbols[:MAX_SYMBOLS_PER_PATH - len(target)])
            _say(entry, tail)
        else:
            _say(entry, body)
    if entry is not None:
        yield _finish(entry, classify, stats, len(lines))


def _heading_date(line: str) -> str | None:
    for token in line.replace("(", " ").replace(")", " ").replace("[", " ").replace("]", " ").split()[:16]:
        stated = _iso_date(token)
        if stated:
            return stated
    return None


def _markdown_text(entry: dict[str, Any], text: str, limits: ChangelogLimits) -> None:
    _say(entry, text)
    for token in text.split("`")[1::2]:
        if _PATH_TOKEN.fullmatch(token) and ("/" in token or "." in token):
            _name(entry, token, limits)


def _parse_markdown(lines: Sequence[str | None], stats: dict[str, Any], classify: Classifier,
                    limits: ChangelogLimits) -> Iterator[dict[str, Any]]:
    """Keep a Changelog: ``## [version] - date`` headings, ``### Section`` headings and bullet items."""
    entry: dict[str, Any] | None = None
    stated: str | None = None
    section = entry_section = None
    for number, line in enumerate(lines, 1):
        if line is None or not line.strip():
            continue
        if entry is not None and line[0] in " \t":
            _markdown_text(entry, line.strip(), limits)
            continue
        if entry is not None:
            yield _finish(entry, classify, stats, number - 1, entry_section)
            entry = None
        if line.startswith("## "):
            stated, section = _heading_date(line), None
        elif line.startswith("### "):
            name = line[4:].strip().lower()
            section = name if name in _SECTIONS else None
        elif line.startswith("#"):
            continue
        elif line[:2] in ("- ", "* ", "+ "):
            entry, entry_section = _new(number, None, stated), section
            _markdown_text(entry, line[2:], limits)
        elif _marker(line) is not None:
            _unparsed(stats, line)
        else:
            stats["prose_lines"] += 1
    if entry is not None:
        yield _finish(entry, classify, stats, len(lines), entry_section)


_PARSERS = {"git-log": _parse_git, "svn-log": _parse_svn, "gnu-changelog": _parse_gnu,
            "keep-a-changelog": _parse_markdown}


def parse(data: bytes, limits: ChangelogLimits, classify: Classifier) -> dict[str, Any]:
    """Parse one change log.  ``format`` is ``None`` when no entry of a recognised format was read."""
    lines, overlong, undecodable = _split_lines(data, limits.max_line_bytes)
    detected = detect(lines)
    stats: dict[str, Any] = {"format": detected, "unparsed_lines": 0, "foreign_format_lines": 0,
                             "messages_truncated": 0, "entries_paths_truncated": 0, "prose_lines": 0,
                             "position": 0}
    entries: list[dict[str, Any]] = []
    beyond = 0
    if detected is not None:
        accepted = dict(stats)
        for entry in _PARSERS[detected](lines, stats, classify, limits):
            if len(entries) == limits.max_entries:
                # Everything after the last accepted entry is reported as one bound, not parsed.
                stats = accepted
                beyond = len(lines) - stats["position"]
                break
            entries.append(entry)
            accepted = dict(stats)
    dated = sum(1 for entry in entries if entry["date"])
    counts = {"line_count": len(lines), "entry_count": len(entries), "dated_entry_count": dated,
              "undated_entry_count": len(entries) - dated, "unparsed_lines": stats["unparsed_lines"],
              "foreign_format_lines": stats["foreign_format_lines"], "overlong_lines": overlong,
              "undecodable_lines": undecodable, "messages_truncated": stats["messages_truncated"],
              "entries_paths_truncated": stats["entries_paths_truncated"], "prose_lines": stats["prose_lines"],
              "lines_beyond_entry_bound": beyond}
    incomplete = (stats["unparsed_lines"] or beyond or overlong or stats["entries_paths_truncated"]
                  or stats["messages_truncated"])
    return {"format": detected if entries else None, "detected_format": detected,
            "status": "unrecognized" if not entries else "partial" if incomplete else "parsed",
            "entries": entries, "counts": counts}


def file_gaps(path: str, parsed: Mapping[str, Any], unparsed_bytes: int = 0) -> list[dict[str, Any]]:
    """Every way one file's parse fell short, as ``{gap, path, count, unit}`` records."""
    counts = parsed["counts"]
    gaps: list[tuple[str, int, str]] = []
    if unparsed_bytes:
        gaps.append(("changelog_bytes_truncated", unparsed_bytes, "bytes"))
    if parsed["status"] == "unrecognized":
        gaps.append(("changelog_format_unrecognized", counts["line_count"], "lines"))
    elif counts["foreign_format_lines"]:
        gaps.append(("changelog_mixed_format", counts["unparsed_lines"], "lines"))
    elif counts["unparsed_lines"]:
        gaps.append(("changelog_unparsed_lines", counts["unparsed_lines"], "lines"))
    if counts["lines_beyond_entry_bound"]:
        gaps.append(("changelog_entry_bound_reached", counts["lines_beyond_entry_bound"], "lines"))
    if counts["overlong_lines"]:
        gaps.append(("changelog_line_too_long", counts["overlong_lines"], "lines"))
    if counts["entries_paths_truncated"]:
        gaps.append(("changelog_entry_paths_truncated", counts["entries_paths_truncated"], "entries"))
    if counts["messages_truncated"]:
        gaps.append(("changelog_message_truncated", counts["messages_truncated"], "entries"))
    return [{"gap": gap, "path": path, "count": count, "unit": unit} for gap, count, unit in gaps]


class PathBinder:
    """Bind an author-typed path to an accepted catalog path, or say why not.

    ``exact``: the text is a catalog path (also tried under the source root).  ``suffix``: exactly
    one catalog path ends with ``/<text>``.  ``repository_prefix``: the text is a catalog path after
    removing a Subversion ``trunk/`` prefix; branch and tag paths never bind.  Several suffix matches are
    ``ambiguous``; nothing else is tried, so a name is never guessed.
    """

    def __init__(self, paths: Iterable[str], root: str = ".") -> None:
        self.paths = frozenset(paths)
        self.root = root
        self.by_name: dict[str, list[str]] = defaultdict(list)
        for path in sorted(self.paths):
            self.by_name[path.rsplit("/", 1)[-1]].append(path)
        self.cache: dict[str, tuple[str, str | None]] = {}

    def _rooted(self, text: str) -> tuple[str, ...]:
        return (text,) if self.root == "." else (f"{self.root}/{text}", text)

    def bind(self, raw: str) -> tuple[str, str | None]:
        if raw not in self.cache:
            self.cache[raw] = self._bind(raw)
        return self.cache[raw]

    def _bind(self, raw: str) -> tuple[str, str | None]:
        text = raw.strip()
        # ``git log --stat`` abbreviates long names to ``.../tail``: only a suffix match is sound.
        abbreviated = text.startswith(".../")
        text = (text[4:] if abbreviated else text).lstrip("/")
        while text.startswith("./"):
            text = text[2:]
        if (not text or len(text) > 1024 or "\0" in text
                or any(part in ("", ".", "..") for part in text.split("/"))):
            return "invalid", None
        if not abbreviated:
            for candidate in self._rooted(text):
                if candidate in self.paths:
                    return "exact", candidate
        matches = [path for path in self.by_name.get(text.rsplit("/", 1)[-1], ()) if path.endswith("/" + text)]
        if len(matches) == 1:
            return "suffix", matches[0]
        if matches:
            return "ambiguous", None
        if not abbreviated and text.startswith("trunk/"):
            # Branch and tag paths are other lines of development and are not counted for this file.
            tail = text[len("trunk/"):]
            if tail:
                for candidate in self._rooted(tail):
                    if candidate in self.paths:
                        return "repository_prefix", candidate
        return "unmatched", None


def _window_start(anchor: str, months: int) -> str:
    stamp = calendar.timegm(date.fromisoformat(anchor).timetuple())
    return datetime.fromtimestamp(window_start(stamp, months), timezone.utc).date().isoformat()


def summarize(parsed_files: Sequence[Mapping[str, Any]], *, catalog: Mapping[str, str], root: str,
              window_months: int, bulk_threshold: int) -> dict[str, Any]:
    """Bind every named path and derive per-entry records and per-file change-log signals.

    ``parsed_files`` is ``[{path, parsed}]`` in read order; ``catalog`` maps accepted paths to their
    SHA-256.  The window is ``window_months`` calendar months ending at the newest dated entry.
    """
    binder = PathBinder(catalog, root)
    mentions = dict.fromkeys((*BINDINGS, "ambiguous", "unmatched", "invalid"), 0)
    seen: set[tuple[str, str]] = set()
    entries: list[dict[str, Any]] = []
    duplicates = 0
    for item in parsed_files:
        parsed = item["parsed"]
        for entry in parsed["entries"]:
            if entry["id"] is not None:
                key = (parsed["format"], entry["id"])
                if key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
            bound: dict[str, set[str]] = {}
            bindings: dict[str, str] = {}
            unbound = 0
            for raw, symbols in entry["paths"]:
                kind, path = binder.bind(raw)
                mentions[kind] += 1
                if path is None:
                    unbound += 1
                    continue
                bound.setdefault(path, set()).update(symbols)
                bindings.setdefault(path, kind)
            entries.append({
                "changelog": item["path"], "line": entry["line"], "id": entry["id"], "date": entry["date"],
                "fix": entry["fix"], "security_fix": entry["security_fix"],
                "security_references": entry["security_references"],
                "message_complete": entry["message_complete"], "paths_truncated": entry["paths_truncated"],
                "paths": sorted(bound), "bindings": bindings,
                "binding_counts": {kind: sum(1 for value in bindings.values() if value == kind)
                                   for kind in BINDINGS},
                "symbols": {path: sorted(names)[:MAX_SYMBOLS_PER_PATH] for path, names in sorted(bound.items())
                            if names},
                "unbound_path_count": unbound, "bulk": len(entry["paths"]) > bulk_threshold})
    dates = [entry["date"] for entry in entries if entry["date"]]
    anchor = max(dates) if dates else None
    start = _window_start(anchor, window_months) if anchor else None
    files: dict[str, dict[str, Any]] = {}
    for entry in entries:
        entry["in_window"] = bool(start and entry["date"] and entry["date"] >= start)
        for path in entry["paths"]:
            record = files.setdefault(path, {
                "path": path, "sha256": catalog[path], "source": SOURCE, "change_count": 0,
                "lifetime_change_count": 0, "undated_change_count": 0, "bulk_change_count": 0,
                "fix_change_count": 0, "security_fix_change_count": 0, "lifetime_fix_change_count": 0,
                "lifetime_security_fix_change_count": 0, "first_change_date": None, "last_change_date": None,
                "bindings": dict.fromkeys(BINDINGS, 0), "security_references": set(), "symbols": set(),
                "evidence": []})
            record["bindings"][entry["bindings"][path]] += 1
            if entry["bulk"]:
                record["bulk_change_count"] += 1
                continue
            record["lifetime_change_count"] += 1
            record["lifetime_fix_change_count"] += int(bool(entry["fix"]))
            record["lifetime_security_fix_change_count"] += int(bool(entry["security_fix"]))
            if entry["in_window"]:
                record["change_count"] += 1
                record["fix_change_count"] += int(bool(entry["fix"]))
                record["security_fix_change_count"] += int(bool(entry["security_fix"]))
            if entry["date"] is None:
                record["undated_change_count"] += 1
            else:
                record["first_change_date"] = min(record["first_change_date"] or entry["date"], entry["date"])
                record["last_change_date"] = max(record["last_change_date"] or entry["date"], entry["date"])
            record["security_references"].update(entry["security_references"])
            record["symbols"].update(entry["symbols"].get(path, ()))
            record["evidence"].append({"changelog": entry["changelog"], "line": entry["line"],
                                       "date": entry["date"]})
    for entry in entries:
        # Per-path binding kinds are summed per entry and per file; the published record stays compact.
        del entry["bindings"]
    for record in files.values():
        record["security_references"] = sorted(record["security_references"])[:MAX_FILE_REFERENCES]
        record["symbols"] = sorted(record["symbols"])[:MAX_FILE_SYMBOLS]
        record["evidence"] = sorted(record["evidence"], key=lambda item: (
            item["date"] is None, tuple(-ord(char) for char in item["date"] or ""), item["changelog"],
            item["line"]))[:MAX_FILE_EVIDENCE]
        record["rank"] = None
    ranking = sorted((path for path, record in files.items() if record["lifetime_change_count"]),
                     key=lambda path: (-files[path]["change_count"], -files[path]["lifetime_change_count"],
                                       tuple(-ord(char) for char in files[path]["last_change_date"] or ""), path))
    for position, path in enumerate(ranking, 1):
        files[path]["rank"] = position
    totals = {
        "entry_count": len(entries), "dated_entry_count": len(dates),
        "undated_entry_count": len(entries) - len(dates), "duplicate_entry_count": duplicates,
        "in_window_entry_count": sum(1 for entry in entries if entry["in_window"]),
        "bulk_entry_count": sum(1 for entry in entries if entry["bulk"]),
        "fix_entry_count": sum(1 for entry in entries if entry["fix"]),
        "security_fix_entry_count": sum(1 for entry in entries if entry["security_fix"]),
        "in_window_fix_entry_count": sum(1 for entry in entries if entry["in_window"] and entry["fix"]),
        "in_window_security_fix_entry_count": sum(
            1 for entry in entries if entry["in_window"] and entry["security_fix"]),
        "entries_naming_files": sum(1 for entry in entries if entry["paths"]),
        "path_mentions": mentions, "bound_file_count": len(files), "ranked_file_count": len(ranking)}
    return {"window": {"identity": WINDOW_IDENTITY, "months": window_months, "anchor_date": anchor,
                       "start_date": start, "anchor": "newest dated change-log entry"},
            "entries": entries, "files": dict(sorted(files.items())), "ranking": ranking, "totals": totals}
