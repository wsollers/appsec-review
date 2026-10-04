"""Document intake for ``02-doc-intelligence-ingest`` (gap 7): which documents, what class, and their text.

Python decides the universe from paths alone (:func:`plan`): README*, SECURITY*, CHANGELOG*/HISTORY*/NEWS,
CONTRIBUTING*, man pages and documents under doc/design/spec-like paths, outside :data:`EXCLUSIONS`. Every
document-like path it does not take is listed with a reason. Each document gets one class
(:data:`DOC_CLASSES`) by path and name, never by a model.

Converters (target content is data; nothing in a document is executed or followed):

* text, markdown, rst, adoc: UTF-8, text line N is source line N.
* html: stdlib ``html.parser``. ``<script>``, ``<style>``, ``<template>`` and comments are dropped; headings
  become ``#`` lines, links ``text (url)``, table cells ``a | b``. Each text line keeps the source line
  where it started.
* roff (man pages): deterministic macro and escape stripping here, not ``groff``/``mandoc``. A man page is
  a text format, so it needs no container; stripping keeps one text line per source line (exact line
  provenance), and no roff interpreter (``.so``, ``.pso``, ``.sy`` requests) ever runs on hostile input.
* pdf: ``pdftotext -layout`` (poppler-utils), page provenance from its form feeds.
* docx: ``pandoc --sandbox -f docx -t gfm``; provenance is the converted text line.

PDF and DOCX run in the pinned ``audit-doc-convert`` image as B13 steps (:class:`ContainerConverter`):
network none, the checkout mounted read-only, one container per document and one version probe per tool.
Encrypted, corrupt, oversized and image-only documents are gaps with reasons. No OCR.
"""
from __future__ import annotations

from html.parser import HTMLParser
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
import threading
from datetime import datetime, timezone
from typing import Any
import zipfile

JOB = "02-doc-intelligence-ingest"
MANIFEST = "doc-text-manifest.json"
RECEIPT = "doc-convert-receipt.json"
TEXT_DIR = "doc-text"
MANIFEST_SCHEMA = "appsec-review/doc-text-manifest/1"
RECEIPT_SCHEMA = "appsec-review/doc-convert-receipt/1"
DOC_CLASSES = ("readme", "security_policy", "changelog", "design", "api", "manual", "other")
FORMATS = ("text", "markdown", "rst", "adoc", "html", "roff", "pdf", "docx")
BINARY_FORMATS = ("pdf", "docx")
SUFFIX_FORMATS = {".md": "markdown", ".markdown": "markdown", ".rst": "rst", ".adoc": "adoc", ".asciidoc": "adoc",
                  ".txt": "text", ".text": "text", ".html": "html", ".htm": "html", ".xhtml": "html",
                  ".pdf": "pdf", ".docx": "docx"}
UNSUPPORTED = {".doc", ".odt", ".rtf", ".ppt", ".pptx", ".odp", ".epub", ".xls", ".xlsx", ".ods", ".pages", ".chm"}
# A name rule (README*, SECURITY* ...) takes a file with these suffixes only as a document: security.c is code.
NON_DOC_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx",
                    ".jsx", ".java", ".kt", ".scala", ".go", ".rs", ".cs", ".rb", ".php", ".pl", ".pm", ".sh",
                    ".bash", ".ps1", ".lua", ".swift", ".m", ".mm", ".json", ".yaml", ".yml", ".toml", ".xml",
                    ".ini", ".cfg", ".conf", ".am", ".ac", ".m4", ".mk", ".cmake", ".png", ".jpg", ".jpeg", ".gif",
                    ".svg", ".ico", ".bmp", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".tar", ".7z", ".jar", ".class",
                    ".o", ".a", ".so", ".dll", ".exe", ".bin", ".css", ".scss", ".lock", ".sum", ".patch", ".diff"}
# Directory parts (case-insensitive) whose files are never intake documents, with the reason.
EXCLUSIONS = (
    ("vendored", ("vendor", "vendored", "third_party", "third-party", "thirdparty", "3rdparty", "external",
                  "extern", "node_modules", "bower_components", "deps")),
    ("generated", ("generated",)),
    ("build-system", ("cmakefiles", "autom4te.cache", "build-aux")),
    ("version-control", (".git", ".hg", ".svn")),
)
DOC_DIR_TOKENS = ("doc", "design", "architecture", "adr", "spec", "requirement", "product", "feature")
MAN_DIR_RE = re.compile(r"^man(?:[1-9n])?\Z")
MAN_NAME_RE = re.compile(r"^(?!.*\.so\.)(.*[^0-9.])\.(?:[1-9][a-z]{0,3}|man)(?:\.in)?\Z")
NAME_RULES = (("readme", re.compile(r"^readme(?:\Z|[-_.])")), ("security_policy", re.compile(r"^security(?:\Z|[-_.])")),
              ("changelog", re.compile(r"^(?:changelog|changes|history|news|release[-_]?notes)(?:\Z|[-_.])")),
              ("other", re.compile(r"^contributing(?:\Z|[-_.])")))
API_RE = re.compile(r"(?:^|[/_.\- ])(?:api|apis|openapi|swagger|endpoints?)(?:[/_.\- ]|\Z)")
DESIGN_RE = re.compile(r"design|architecture|(?:^|[/_.\- ])(?:adrs?|specs?|specification|requirements?|rfcs?)(?:[/_.\- ]|\Z)"
                       r"|threat[-_ ]?model")
# Security-relevant topics for headings and statements. Records are locators, never findings.
TOPICS = (
    ("auth", r"\b(?:auth\w*|log[ -]?ins?|logon|sign[ -]?in|passwords?|credentials?|sessions?|oauth\w*|saml|sso|mfa|2fa"
             r"|access[ -]control|rbac|permissions?)\b"),
    ("crypto", r"\b(?:crypt\w*|ciphers?|encrypt\w*|decrypt\w*|hmac|hash(?:es|ing)?|digests?|signatures?|signing|nonces?"
               r"|entropy|random(?:ness)?|c?s?prng|kdf|pbkdf2|bcrypt|scrypt|argon2|aes|rsa|ecdsa|ed25519|sha-?(?:1|256|512))\b"),
    ("tls", r"\b(?:tls|ssl|https|certificates?|x\.?509|mtls|ocsp|pinning)\b"),
    ("secrets", r"\b(?:secrets?|api[ _-]?keys?|tokens?|private[ _-]keys?|vault|keystore|keyring)\b"),
    ("reporting_policy", r"\b(?:vulnerabilit\w*|security (?:issues?|bugs?|advisor\w*|report\w*|contact|team|polic\w*)"
                         r"|disclos\w*|cve(?:-\d+-\d+)?|bug[ -]bounty|security@\S+|embargo\w*|supported versions?)\b"),
)
_TOPICS = tuple((name, re.compile(pattern, re.IGNORECASE)) for name, pattern in TOPICS)
SECURITY_HEADING = re.compile(r"\b(?:security|threats?|threat[- ]model|hardening|privacy)\b", re.IGNORECASE)
STATEMENT_WORDS = ("must", "should", "actor", "service", "incident", "deploy", "data", "auth")
ROFF_VERSION = "doc_convert-roff-strip-1"
HTML_VERSION = f"python-{sys.version_info.major}.{sys.version_info.minor}-html.parser"
IMAGE_ID = "audit-doc-convert"
PDFTOTEXT = "/usr/bin/pdftotext"
PANDOC = "/usr/bin/pandoc"
WORKSPACE = "/workspace"


# --------------------------------------------------------------------------- the universe (pure)

def topics(text: str) -> list[str]:
    return [name for name, pattern in _TOPICS if pattern.search(text)]


def doc_format(path: str) -> str | None:
    """The converter a path takes, or None when it is no document format this intake reads."""
    p = PurePosixPath(path); suffix = p.suffix.lower()
    if MAN_NAME_RE.match(p.name.lower()) and suffix not in SUFFIX_FORMATS:
        return "roff"
    return SUFFIX_FORMATS.get(suffix)


def _excluded(path: str) -> str | None:
    parts = {part.lower() for part in PurePosixPath(path).parts[:-1]}
    return next((name for name, dirs in EXCLUSIONS if parts & set(dirs)), None)


def _name_class(path: str) -> str | None:
    p = PurePosixPath(path); name = p.name.lower()
    if p.suffix.lower() in NON_DOC_SUFFIXES:
        return None
    return next((cls for cls, pattern in NAME_RULES if pattern.match(name)), None)


def _in_man_dir(path: str) -> bool:
    return any(MAN_DIR_RE.match(part.lower()) for part in PurePosixPath(path).parts[:-1])


def classify(path: str, fmt: str) -> str:
    """One of DOC_CLASSES from the path and name only; first rule wins."""
    named = _name_class(path)
    if named in ("readme", "security_policy", "changelog"):
        return named
    if fmt == "roff" or _in_man_dir(path):
        return "manual"
    low = path.lower()
    if API_RE.search(low):
        return "api"
    if DESIGN_RE.search(low):
        return "design"
    return "other"


def plan(source_files: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """(included [{path, doc_class, format}], skipped [{path, reason}]), both sorted by path.

    A path is a candidate document when a name rule matches it or it has a document format (including
    the unsupported office formats). Candidates the rules do not take are skipped with a reason.
    """
    included, skipped = [], []
    for path in sorted(source_files):
        if source_files[path].get("kind") != "file":
            continue
        suffix = PurePosixPath(path).suffix.lower()
        named = _name_class(path)
        fmt = doc_format(path)
        if fmt is None and named is not None and suffix not in UNSUPPORTED:
            fmt = "text"   # README, NEWS, ChangeLog, README.Debian ...
        if fmt is None and suffix not in UNSUPPORTED:
            continue
        excluded = _excluded(path)
        if excluded:
            skipped.append({"path": path, "reason": f"excluded-path:{excluded}"}); continue
        low = path.lower()
        in_scope = (named is not None or fmt == "roff" or _in_man_dir(path)
                    or any(token in low for token in DOC_DIR_TOKENS))
        if not in_scope:
            skipped.append({"path": path, "reason": "outside-document-scope"}); continue
        if fmt is None:
            skipped.append({"path": path, "reason": f"unsupported-format:{suffix}"}); continue
        if any(ord(char) < 0x20 or char == "\x7f" for char in path):
            skipped.append({"path": path, "reason": "unsafe-path"}); continue
        included.append({"path": path, "doc_class": classify(path, fmt), "format": fmt})
    return included, skipped


# --------------------------------------------------------------------------- text conversion (pure)

# A converted line: (text, source line or None, page or None, heading level 0..6)
Line = tuple[str, "int | None", "int | None", int]

_ATX = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*\Z")
_RST_UNDER = re.compile(r"^([=\-~^\"'`#*+.:_])\1{2,}\s*\Z")
_ADOC = re.compile(r"^(={1,6})\s+(\S.*)\Z")


def text_lines(text: str, fmt: str, *, page: int | None = None, source_lines: bool = True) -> list[Line]:
    """Lines of a text-like document with heading levels; markdown ATX/setext, rst underline, adoc ``=``."""
    raw = text.split("\n")
    if raw and raw[-1] == "":
        raw.pop()
    out: list[Line] = []
    for index, line in enumerate(raw):
        line = line.rstrip("\r")
        level = 0
        match = _ATX.match(line)
        following = raw[index + 1].rstrip("\r") if index + 1 < len(raw) else ""
        if fmt == "adoc":
            heading = _ADOC.match(line)
            level = len(heading.group(1)) if heading else 0
        elif fmt == "rst":
            level = 1 if line.strip() and _RST_UNDER.match(following) and len(following.strip()) >= len(line.strip()) \
                and not _RST_UNDER.match(line) else 0
        elif match:
            level = len(match.group(1))
        elif line.strip() and not line.lstrip().startswith(("-", "*", "+", ">", "|")) and re.match(r"^(=+|-+)\s*\Z", following) \
                and fmt in ("markdown", "text", "docx", "html"):
            level = 1 if following.strip().startswith("=") else 2
        out.append((line, (index + 1) if source_lines else None, page, level))
    return out


class _HTMLText(HTMLParser):
    BLOCK = {"p", "div", "br", "li", "tr", "section", "article", "header", "footer", "nav", "main", "aside", "pre",
             "table", "thead", "tbody", "ul", "ol", "dl", "dt", "dd", "blockquote", "hr", "title", "figcaption",
             "caption", "form", "address", "details", "summary"} | {f"h{n}" for n in range(1, 7)}
    DROP = {"script", "style", "template", "noscript", "object", "embed", "iframe", "svg", "math"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.lines: list[Line] = []
        self.current: list[str] = []
        self.start: int | None = None
        self.level = 0
        self.drop = 0
        self.pre = 0
        self.href: list[str | None] = []
        self.cells = 0

    def flush(self) -> None:
        text = "".join(self.current)
        text = text if self.pre else re.sub(r"[ \t\r\n\f\v]+", " ", text).strip()
        for index, part in enumerate(text.split("\n") if self.pre else [text]):
            if part.strip():
                prefix = ("#" * self.level + " ") if self.level else ""
                self.lines.append((prefix + part.rstrip(), (self.start or 1) + (index if self.pre else 0), None, self.level))
        self.current, self.start, self.cells = [], None, 0

    def _text(self, value: str) -> None:
        if self.drop or not value:
            return
        if self.start is None and value.strip():
            self.start = self.getpos()[0]
        if self.start is not None:
            self.current.append(value)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.DROP:
            self.drop += 1; return
        if self.drop:
            return
        if tag in self.BLOCK:
            self.flush()
        if tag in {f"h{n}" for n in range(1, 7)}:
            self.level = int(tag[1])
        elif tag == "pre":
            self.pre += 1
        elif tag in ("td", "th"):
            if self.cells:
                self._text(" | ")
            self.cells += 1
        elif tag == "li":
            self._text("- ")
        elif tag == "a":
            href = dict(attrs).get("href")
            self.href.append(href.strip() if href and not href.strip().lower().startswith(("javascript:", "data:")) else None)
        elif tag == "img":
            alt = dict(attrs).get("alt")
            if alt:
                self._text(f"[image: {alt}]")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.DROP:
            return
        self.handle_starttag(tag, attrs)
        if tag in self.BLOCK:
            self.flush()

    def handle_endtag(self, tag: str) -> None:
        if tag in self.DROP:
            self.drop = max(0, self.drop - 1); return
        if self.drop:
            return
        if tag == "a" and self.href:
            href = self.href.pop()
            if href:
                self._text(f" ({href})")
        if tag in self.BLOCK:
            self.flush()
        if tag in {f"h{n}" for n in range(1, 7)}:
            self.level = 0
        elif tag == "pre":
            self.pre = max(0, self.pre - 1)

    def handle_data(self, data: str) -> None:
        self._text(data)

    def handle_comment(self, data: str) -> None:   # comments never reach the text
        return

    def unknown_decl(self, data: str) -> None:
        return


def html_lines(text: str) -> list[Line]:
    parser = _HTMLText()
    parser.feed(text)
    parser.close()
    parser.flush()
    return parser.lines


_ROFF_SPECIAL = {"em": "--", "en": "-", "hy": "-", "bu": "*", "aq": "'", "dq": '"', "lq": '"', "rq": '"', "oq": "'",
                 "cq": "'", "co": "(c)", "rg": "(R)", "tm": "(TM)", "mu": "x", "<=": "<=", ">=": ">=", "->": "->",
                 "<-": "<-", "ti": "~", "ha": "^", "rs": "\\", "sl": "/", "ba": "|", "lB": "[", "rB": "]"}
_ROFF_ESCAPE = re.compile(r"\\(?:f(?:\[[^\]]*\]|\(..|.)|s[+-]?(?:\[[^\]]*\]|\(..|'[^']*'|\d{1,2})|[*n](?:\[[^\]]*\]|\(..|.)"
                          r"|[hvwoXlLbDSxNZRk](?:'[^']*'|\[[^\]]*\])?|\((..)|\[([^\]]*)\]|(.))")
_ROFF_FONT = {"B", "I", "R", "SM", "SB", "BI", "IB", "BR", "RB", "IR", "RI"}
_ROFF_SKIP = {"PP", "LP", "P", "br", "sp", "RS", "RE", "nf", "fi", "in", "ti", "ad", "na", "ne", "hy", "nh", "ft", "ps",
              "vs", "ll", "ta", "bp", "ce", "UE", "ME", "EX", "EE", "PD", "HP", "Pp", "Bl", "El", "Bd", "Ed", "Dd",
              "Os", "so", "mso", "pso", "sy", "nr", "rr", "rm", "rn", "ds", "as", "tr", "ie", "el", "if", "cc", "ec",
              "eo", "ev", "lf", "pl", "po", "ns", "rs", "wh", "ch", "it", "fc", "lc", "ss", "cs", "cu", "ul", "uf"}
# mdoc callable macros dropped from macro arguments (``.Nm hello Fl v`` is ``hello v``).
_MDOC_CALLABLE = {"Ad", "Ar", "Cd", "Cm", "Dv", "Er", "Ev", "Fa", "Fl", "Fn", "Fo", "Fc", "Ic", "Li", "Nm", "Op", "Oo",
                  "Oc", "Pa", "Sy", "Em", "Va", "Vt", "Xr", "Ql", "Dq", "Do", "Dc", "Sq", "So", "Sc", "Pq", "Po", "Pc",
                  "Bq", "Bo", "Bc", "Aq", "Ao", "Ac", "Qq", "Qo", "Qc", "Ns", "No", "Ux", "Bx", "At", "Ta", "Lk", "Mt"}


def _roff_text(value: str) -> str:
    value = value.split('\\"', 1)[0]

    def escape(match: re.Match) -> str:
        two, bracket, one = match.group(1), match.group(2), match.group(3)
        if two is not None or bracket is not None:
            return _ROFF_SPECIAL.get(two if two is not None else bracket, "")
        if one is None:
            return ""
        return {"-": "-", "e": "\\", "\\": "\\", " ": " ", "~": " ", "0": " ", "t": "\t", "'": "'", "`": "`",
                ".": "."}.get(one, "")
    return _ROFF_ESCAPE.sub(escape, value)


def _roff_args(value: str) -> list[str]:
    return [item[1:-1] if len(item) > 1 and item.startswith('"') and item.endswith('"') else item
            for item in re.findall(r'"[^"]*"|\S+', value)]


def roff_lines(text: str) -> list[Line]:
    """Man-page text with macros stripped; one output line per kept source line."""
    out: list[Line] = []
    skip_until: str | None = None
    table = 0      # 0 outside .TS; 1 in the format section; 2 in the data
    pending_heading = 0
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        if skip_until is not None:
            if line.strip() == skip_until:
                skip_until = None
            continue
        control = line[:1] in (".", "'")
        name, rest = "", ""
        if control:
            body = line[1:].lstrip()
            name, _, rest = body.partition(" ")
            name = name.strip(); rest = rest.strip()
            if name.startswith('\\"') or name == "":
                continue
            if name in ("de", "de1", "am", "ig"):
                skip_until = ".." if name != "ig" or not rest else "." + rest; continue
            if name == "TS":
                table = 1; continue
            if name == "TE":
                table = 0; continue
        if table == 1:
            if line.rstrip().endswith("."):
                table = 2
            continue
        level, value = 0, None
        if control:
            if name in ("TH", "Dt"):
                args = _roff_args(_roff_text(rest))
                value, level = (f"{args[0]}({args[1]})" if len(args) > 1 else " ".join(args)), 1
            elif name in ("SH", "Sh", "SS", "Ss"):
                level = 2 if name in ("SH", "Sh") else 3
                value = " ".join(_roff_args(_roff_text(rest)))
                if not value:
                    pending_heading = level; continue
            elif name in _ROFF_FONT:
                args = _roff_args(_roff_text(rest))
                value = ("".join(args) if len(name) == 2 and name not in ("SM", "SB") else " ".join(args))
            elif name in ("TP", "IP", "TQ", "It"):
                value = " ".join(item for item in _roff_args(_roff_text(rest)) if item not in _MDOC_CALLABLE)
                if name == "IP":
                    value = value.split(" ")[0] if value else ""
            elif name in ("UR", "MT"):
                value = _roff_text(rest).strip()
            elif name in _ROFF_SKIP:
                continue
            else:
                value = " ".join(item for item in _roff_args(_roff_text(rest)) if item not in _MDOC_CALLABLE)
        else:
            value = _roff_text(line)
            if table == 2:
                value = " | ".join(cell.strip() for cell in value.split("\t"))
            if pending_heading:
                level, pending_heading = pending_heading, 0
        value = (value or "").strip()
        if not value:
            continue
        out.append((("#" * level + " " + value) if level else value, number, None, level))
    return out


def pdf_lines(text: str) -> tuple[list[Line], int, int]:
    """(lines with their page, page count, non-whitespace characters) from ``pdftotext -layout`` output.

    pdftotext ends every page with a form feed, so page N is the text between the (N-1)th and Nth one.
    """
    pages = text.split("\f")
    if pages and pages[-1].strip() == "" and text.endswith("\f"):
        pages.pop()
    out: list[Line] = []
    for number, page in enumerate(pages, 1):
        for line, _src, _page, level in text_lines(page, "text", source_lines=False):
            out.append((line.rstrip(), None, number, 0))
    chars = sum(1 for char in text if not char.isspace())
    return out, len(pages), chars


def wrap(lines: list[Line], width: int) -> list[Line]:
    """Split lines longer than ``width``; each piece keeps the provenance of its line."""
    out: list[Line] = []
    for text, src, page, level in lines:
        if len(text) <= width:
            out.append((text, src, page, level)); continue
        out.extend((text[start:start + width], src, page, level) for start in range(0, len(text), width))
    return out


# --------------------------------------------------------------------------- provenance and records (pure)

def locator(fmt: str, line: Line, text_line: int, page_line: int) -> tuple[str, str]:
    """(locator, citation suffix) for one converted line."""
    _text, src, page, _level = line
    if page is not None:
        return f"page:{page}:line:{page_line}", f"#page={page}"
    if src is None:
        return f"text-line:{text_line}", f"#text-line={text_line}"
    if fmt in ("html", "roff"):
        return f"line:{src}:text-line:{text_line}", f":{src}"
    return f"line:{src}", f":{src}"


def records(path: str, doc_class: str, fmt: str, lines: list[Line]) -> list[dict[str, Any]]:
    """Locator records: one ``document``, then headings, security sections and statements."""
    first = next((text.lstrip("#").strip() for text, *_ in lines if text.strip()), "")
    base = {"doc_class": doc_class, "format": fmt}
    doc_topics = sorted(set(topics(path.replace("_", " "))) | ({"reporting_policy"} if doc_class == "security_policy" else set()))
    out = [{"kind": "document", "locator": "file", "text": f"{doc_class} {fmt} document {path}: {first}"[:500],
            "citation": path + (locator(fmt, lines[0], 1, 1)[1] if lines else ":1"), **base,
            **({"topics": doc_topics} if doc_topics else {})}]
    page_line: dict[int | None, int] = {}
    for number, line in enumerate(lines, 1):
        text, _src, page, level = line
        page_line[page] = page_line.get(page, 0) + 1
        value = text.strip().lstrip("#").strip() if level else text.strip()
        if not value:
            continue
        where, suffix = locator(fmt, line, number, page_line[page])
        found = topics(value)
        if level:
            kind = "security-section" if found or SECURITY_HEADING.search(value) else "document-heading"
        elif found or any(word in value.lower() for word in STATEMENT_WORDS):
            kind = "document-statement"
        else:
            continue
        out.append({"kind": kind, "locator": where, "text": value[:500], "citation": path + suffix, **base,
                    **({"topics": found} if found else {}), **({"heading_level": level} if level else {})})
    return out


def provenance(fmt: str, lines: list[Line]) -> dict[str, Any]:
    if fmt == "pdf":
        pages: dict[int, list[int]] = {}
        for number, (_text, _src, page, _level) in enumerate(lines, 1):
            pages.setdefault(page or 0, []).append(number)
        last = max(pages) if pages else 0
        return {"kind": "page", "pages": [[min(pages[p]), max(pages[p])] if p in pages else None
                                          for p in range(1, last + 1)]}
    if fmt == "docx":
        return {"kind": "converted-line"}
    return {"kind": "source-line", "lines": [src for _text, src, _page, _level in lines]}


# --------------------------------------------------------------------------- binary documents

def precheck(fmt: str, data: bytes, max_unpacked: int) -> str | None:
    """A gap kind for a PDF/DOCX that must not reach a converter, or None. Reads bytes; runs nothing."""
    if fmt == "pdf":
        if b"%PDF-" not in data[:1024]:
            return "corrupt-document"
        if re.search(rb"/Encrypt\s*(?:\d+\s+\d+\s+R|<<)", data):
            return "encrypted-document"
        return None
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        return "encrypted-document" if "EncryptedPackage".encode("utf-16-le") in data else "corrupt-document"
    if not data.startswith(b"PK\x03\x04"):
        return "corrupt-document"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:   # central directory only; nothing is extracted
            infos = archive.infolist()
    except (zipfile.BadZipFile, ValueError, OSError):
        return "corrupt-document"
    if not any(info.filename == "word/document.xml" for info in infos):
        return "corrupt-document"
    if any(info.flag_bits & 0x1 for info in infos):
        return "encrypted-document"
    if sum(info.file_size for info in infos) > max_unpacked:
        return "oversized-input"
    return None


def argv(fmt: str, path: str, output: str) -> list[str]:
    source = f"{WORKSPACE}/{path}"
    if fmt == "pdf":
        return [PDFTOTEXT, "-layout", "-enc", "UTF-8", "-eol", "unix", source, f"/scratch/{output}"]
    return [PANDOC, "--sandbox", "-f", "docx", "-t", "gfm", "--wrap=none", "-o", f"/scratch/{output}", source]


VERSION_ARGV = {"pdf": [PDFTOTEXT, "-v"], "docx": [PANDOC, "--version"]}
TOOL_NAMES = {"pdf": "pdftotext", "docx": "pandoc"}


def failure_gap(fmt: str, outcome: dict[str, Any]) -> str:
    """Gap kind for a converter run that did not produce text."""
    if fmt == "pdf" and b"password" in (outcome.get("stderr") or b"").lower():
        return "encrypted-document"
    cause = outcome.get("cause") or "no-output"
    return f"conversion-failed:{cause.lower()}" + (f"-exit-{outcome['exit_code']}" if outcome.get("exit_code") else "")


class ContainerConverter:
    """One B13 pinned-container step per binary document, or (``receipt`` given) their re-verification.

    ``run(step, argv, output)`` returns ``{status, cause, exit_code, stdout, stderr, output}``. In replay
    mode nothing is started: the stored trial is verified with ``container_execution.load_verified_result``
    against the result hash and output hash this attempt's receipt recorded.
    """

    def __init__(self, *, attempt: Path, run_id: str, job: str, target: str, converter: dict[str, Any],
                 source_snapshot_sha256: str, receipt: dict[str, Any] | None = None):
        self.attempt, self.run_id, self.job, self.target = Path(attempt), run_id, job, target
        self.image, self.limits = converter["image"], converter["container_limits"]
        self.source = source_snapshot_sha256
        self.replay = receipt is not None
        self.steps: dict[str, dict[str, Any]] = dict((receipt or {}).get("steps", {}))
        self.used: set[str] = set()

    def _host(self) -> dict[str, Any]:
        import container_execution as ce
        defaults = ce.host_defaults()
        if defaults["docker_executable"] is None:
            from execution_state import Blocked
            raise Blocked(f"{self.job}: Docker is unavailable for document conversion")
        return {"host_flavor": defaults["host_flavor"], "docker_host": None,
                "docker_executable": defaults["docker_executable"], "container_user": defaults["container_user"]}

    def request(self, step: str, command: list[str]) -> dict[str, Any]:
        import container_execution as ce
        import permission_capabilities as pc
        at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": self.job, "capabilities": []}
        context = {"run_id": self.run_id, "job_id": self.job, "source_snapshot_sha256": self.source, "now": at,
                   "registry_ceiling": []}
        decision = pc.evaluate(requirement, [], context)
        pc.require_granted(decision, requirement=requirement, grants=[], context=context)
        return {"schema": ce.REQUEST_ID, "run_id": self.run_id, "job_id": self.job, "attempt_id": step,
                "image": {"image_id": self.image["image_id"], "digest": self.image["digest"]}, "argv": command,
                "environment": [{"name": "LANG", "value": "C.UTF-8"}, {"name": "LC_ALL", "value": "C.UTF-8"},
                                {"name": "TZ", "value": "UTC"}, {"name": "SOURCE_DATE_EPOCH", "value": "0"}],
                "target_mounts": [{"host_path": self.target, "container_path": WORKSPACE}],
                "scratch_path": "scratch", "log_path": "logs", "network": {"mode": "none", "destinations": []},
                "permission": {"requirement": requirement, "grants": [], "decision": decision},
                "limits": self.limits}

    def run(self, step: str, command: list[str], output: str | None) -> dict[str, Any]:
        import container_execution as ce
        from execution_state import Blocked, file_hash, read_json
        trial = self.attempt / "doc-convert" / step
        host = self._host()
        if self.replay:
            stored = self.steps.get(step)
            if stored is None:
                raise Blocked(f"{self.job}: conversion step {step} is not in the receipt")
            request = read_json(trial / "logs" / ce.REQUEST_FILE)
            if request.get("argv") != command or request.get("image", {}).get("digest") != self.image["digest"] \
                    or request.get("target_mounts") != [{"host_path": self.target, "container_path": WORKSPACE}]:
                raise Blocked(f"{self.job}: conversion step {step} request changed")
            terminal = ce.load_verified_result(trial, run_id=self.run_id, job_id=self.job, attempt_id=step,
                request=request, images_dir=ce.IMAGES_DIR, expected_result_sha256=stored["result_sha256"], **host)
        else:
            trial.mkdir(parents=True)
            runtime = ce.ContainerRuntime(docker_executable=host["docker_executable"], docker_host=None,
                images_dir=ce.IMAGES_DIR, host_flavor=host["host_flavor"], container_user=host["container_user"],
                source_snapshot_sha256=self.source, registry_ceiling=[],
                clock=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), cancel=threading.Event())
            request = self.request(step, command)
            terminal = ce.run_container(runtime, run_id=self.run_id, job_id=self.job, attempt_id=step,
                                        attempt_root=trial, request=request)
            ce.load_verified_result(trial, run_id=self.run_id, job_id=self.job, attempt_id=step, request=request,
                images_dir=ce.IMAGES_DIR, expected_result_sha256=terminal["result_sha256"], **host)
            if terminal["execution_status"] == "BLOCKED":   # a host problem, not a document problem
                raise Blocked(f"{self.job}: document converter blocked ({terminal['cause']})")
        self.used.add(step)
        produced = trial / "scratch" / output if output else None
        data = produced.read_bytes() if produced is not None and produced.is_file() and not produced.is_symlink() else None
        output_sha = ("sha256:" + file_hash(produced)) if data is not None else None
        if self.replay:
            if output_sha != self.steps[step]["output_sha256"]:
                raise Blocked(f"{self.job}: conversion step {step} output changed")
        else:
            self.steps[step] = {"result_sha256": terminal["result_sha256"], "output_sha256": output_sha}

        def log(name: str) -> bytes:
            path = trial / "logs" / name
            return path.read_bytes() if path.is_file() and not path.is_symlink() else b""
        return {"status": terminal["execution_status"], "cause": terminal["cause"], "exit_code": terminal["exit_code"],
                "stdout": log("stdout.log"), "stderr": log("stderr.log"), "output": data}

    def receipt(self) -> dict[str, Any]:
        """Every step this attempt ran; a replay lists only the steps it verified, so a stray one shows."""
        return {"schema": RECEIPT_SCHEMA, "steps": {key: value for key, value in sorted(self.steps.items())
                                                    if not self.replay or key in self.used}}


def tool_version(converter: Any, fmt: str, cache: dict[str, str]) -> str:
    """The first line the pinned tool prints for its version probe (one probe per tool per attempt)."""
    if fmt not in cache:
        outcome = converter.run(f"dc-version-{TOOL_NAMES[fmt]}", VERSION_ARGV[fmt], None)
        text = (outcome["stdout"] or outcome["stderr"] or b"").decode("utf-8", errors="replace").strip()
        cache[fmt] = (text.splitlines()[0][:200] if text and outcome["status"] == "OK" else "unknown")
    return cache[fmt]


def step_id(fmt: str, path: str, sha256: str) -> str:
    from execution_state import digest
    return f"dc-{TOOL_NAMES[fmt]}-" + digest((path, sha256))[:24]


def doc_id(path: str) -> str:
    from execution_state import digest
    return "doc_" + digest(path)[:16]


def canonical(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


DERIVED_MANIFEST = "derived-text-manifest.json"


def derived_manifest(documents: list[dict[str, Any]]) -> dict[str, Any]:
    """The ``derived-text-manifest.json`` 02-evidence-index-derived chunks: per converted document its text
    artifact and sha256, source path and sha256, converter and version, and PDF page line ranges."""
    def pages(entry: dict[str, Any]) -> list[dict[str, int]] | None:
        if entry["provenance"]["kind"] != "page":
            return None
        return [{"page": number, "start_line": span[0], "end_line": span[1]}
                for number, span in enumerate(entry["provenance"]["pages"], 1) if span]
    return {"schema": "appsec-review/derived-text-manifest/1.0", "documents": [
        {"artifact_path": entry["text_path"], "sha256": entry["text_sha256"], "source_path": entry["path"],
         "source_sha256": entry["source_sha256"], "converter": entry["converter"]["name"],
         "converter_version": entry["converter"]["version"][:128], "pages": pages(entry)}
        for entry in sorted(documents, key=lambda item: item["path"])]}

