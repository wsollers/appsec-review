"""Deterministic C and C++ subject recognition over accepted source bytes (T-5013).

A subject is one complete function definition (or one named type definition for the session family)
with the entry and sink lines the reviewed recogniser families found inside it. Recognition is a
review question, never a verdict: it names where a worker must look and what it must establish.

The scanner needs no compiler or tree-sitter at inference time. Comments, string and character
literal contents and preprocessor lines are blanked (lengths and newlines preserved), brace blocks
are matched on the blanked text, and a block whose head ends in a parameter list is a function.
Accepted tree-sitter ``function_definition`` spans prioritise the same subjects in
``evidence.component_evidence``; the scanner is what makes a subject re-derivable from the excerpt
bytes alone, which citation re-resolution requires.

Known limits, recorded as limitations rather than hidden: macro bodies are not scanned, a function
produced by a macro has no name, K&R definitions and unbalanced braces end the scan of that file
with a named gap, and recognition is lexical (a call is a name followed by a parenthesis).
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Mapping, Sequence


LANGUAGE = "c-cpp"
RECOGNISER_VERSION = "c-cpp-source-subjects/1"
SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".ipp", ".inl"})
LANGUAGE_NAMES = frozenset({"c", "c++", "cpp", "cxx", "c/c++", "objective-c"})
_KEYWORDS = frozenset({
    "if", "else", "for", "while", "do", "switch", "return", "sizeof", "case", "default", "try", "catch",
    "alignof", "decltype", "typeid", "static_assert", "_Static_assert", "__attribute__", "throw", "new", "delete",
})
_QUALIFIERS = ("const", "volatile", "override", "final", "noexcept", "constexpr", "mutable", "&&", "&")
_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_NAME = re.compile(r"((?:" + _IDENT + r"\s*::\s*)*(?:operator\s*[^\s(]*|~?" + _IDENT + r")(?:\s*<[^<>(){};]*>)?)\s*$")
_CONTAINER = re.compile(r"^(?:inline\s+)?namespace(?:\s+[\w:]+)?(?:\s*=\s*[\w:]+)?$|^extern\s*\"[^\"]*\"$")
_TYPE = re.compile(
    r"^(?:(?:typedef|template\s*<[^{]*>)\s+)?(?:struct|class|union)\s+(?:alignas\s*\([^)]*\)\s+)?"
    r"(?P<name>" + _IDENT + r")(?:\s+final)?(?:\s*:\s*[^{]*)?$")
_ANONYMOUS_TYPE = re.compile(r"^(?:typedef\s+)?(?:struct|class|union)\s*$")

# Recogniser families: the reviewed procedures in ``obligations.py`` name these ids.
INPUT_ENTRY = "c_input_entry/1"
COMMAND_SINK = "c_command_sink/1"
FORMAT_SINK = "c_format_sink/1"
COPY_SINK = "c_copy_sink/1"
ALLOCATION_SIZE = "c_allocation_size/1"
MEMORY_RELEASE = "c_memory_release/1"
FILE_PATH = "c_file_path/1"
SESSION_STATE = "c_session_state/1"
LOG_SINK = "c_log_sink/1"
ERROR_PATH = "c_error_path/1"
FAMILIES = (INPUT_ENTRY, COMMAND_SINK, FORMAT_SINK, COPY_SINK, ALLOCATION_SIZE, MEMORY_RELEASE, FILE_PATH,
            SESSION_STATE, LOG_SINK, ERROR_PATH)
FAMILY_LABELS = {
    INPUT_ENTRY: "input entry", COMMAND_SINK: "command sink", FORMAT_SINK: "format sink",
    COPY_SINK: "copy sink", ALLOCATION_SIZE: "allocation size", MEMORY_RELEASE: "memory release",
    FILE_PATH: "file path", SESSION_STATE: "session state", LOG_SINK: "log sink", ERROR_PATH: "error path",
}

_ENTRY_CALLS = frozenset({
    "recv", "recvfrom", "recvmsg", "read", "pread", "readv", "fgets", "gets", "fread", "getline", "getdelim",
    "scanf", "fscanf", "sscanf", "getchar", "fgetc", "getc", "getenv", "secure_getenv", "accept", "accept4",
    "SSL_read", "zmq_recv",
})
_COMMAND_CALLS = frozenset({
    "popen", "system", "execl", "execlp", "execle", "execv", "execvp", "execvpe", "execve", "posix_spawn",
    "posix_spawnp", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW", "_popen", "_wsystem",
})
# Format-string argument position of each printf-family function.
_FORMAT_POSITION = {
    "printf": 0, "vprintf": 0, "wprintf": 0, "fprintf": 1, "vfprintf": 1, "fwprintf": 1, "dprintf": 1,
    "vdprintf": 1, "sprintf": 1, "vsprintf": 1, "snprintf": 2, "vsnprintf": 2, "swprintf": 2, "syslog": 1,
    "vsyslog": 1, "asprintf": 1, "vasprintf": 1, "err": 1, "errx": 1, "warn": 0, "warnx": 0,
    "printf_s": 0, "sprintf_s": 2, "snprintf_s": 2,
}
_COPY_CALLS = frozenset({
    "strcpy", "strcat", "stpcpy", "strncpy", "strncat", "sprintf", "vsprintf", "gets", "memcpy", "memmove",
    "bcopy", "wcscpy", "wcscat", "wmemcpy", "strcpy_s", "memcpy_s",
})
# Size argument position of each allocator.
_ALLOCATION_POSITION = {"malloc": 0, "calloc": 1, "realloc": 1, "reallocarray": 1, "alloca": 0,
                        "aligned_alloc": 1, "valloc": 0, "pvalloc": 0}
_RELEASE_CALLS = frozenset({"free", "cfree", "munmap", "fclose", "close", "pclose", "closedir"})
# Path argument position of each path-taking call.
_PATH_POSITION = {
    "fopen": 0, "freopen": 0, "open": 0, "open64": 0, "creat": 0, "realpath": 0, "stat": 0, "lstat": 0,
    "stat64": 0, "access": 0, "unlink": 0, "remove": 0, "rename": 0, "mkdir": 0, "rmdir": 0, "opendir": 0,
    "chmod": 0, "chown": 0, "readlink": 0, "link": 0, "symlink": 0, "truncate": 0, "chdir": 0, "mkfifo": 0,
    "mknod": 0, "utime": 0, "openat": 1, "fstatat": 1, "unlinkat": 1, "faccessat": 1, "mkdirat": 1,
    "renameat": 1, "readlinkat": 1, "ifstream": 0, "ofstream": 0, "fstream": 0, "wifstream": 0, "wofstream": 0,
}
_LOG_CALLS = frozenset({"syslog", "vsyslog", "openlog", "perror", "err", "errx", "warn", "warnx"})
_STDOUT_CALLS = frozenset({"printf", "vprintf", "puts", "fputs", "fprintf", "vfprintf", "putchar", "fwrite",
                           "fputc", "putc", "dprintf"})
_LOG_NAME = re.compile(r"(?i)(?:^|_)(?:log|audit|trace|debug|warn|err)[a-z0-9]*(?:_|$)")
_SESSION_NAME = re.compile(r"(?i)session|token|cookie")
_ERROR_RETURN = re.compile(r"\breturn\s+(?:-\s*1|-\s*[A-Z][A-Z0-9_]+|NULL|nullptr|false|EXIT_FAILURE)\s*;")
_ERROR_CALLS = frozenset({"exit", "_exit", "_Exit", "abort", "quick_exit", "perror", "strerror", "strerror_r"})
_CALL = re.compile(r"(?<![\w.>])(" + _IDENT + r"(?:\s*::\s*" + _IDENT + r")*)\s*\(")
_NEW_ARRAY = re.compile(r"\bnew\s+(?:\([^)]*\)\s*)?[\w:<>]+\s*\[([^\]]*)\]")
_DELETE = re.compile(r"\bdelete\b")
_STREAM_OPEN = re.compile(r"\b(?:std\s*::\s*)?w?[io]?fstream\s+" + _IDENT + r"\s*\(")
_STREAM_STDERR = re.compile(r"\b(?:std\s*::\s*)?(?:cerr|clog)\b")


@dataclass(frozen=True, slots=True)
class CFunction:
    """One complete definition: ``kind`` is ``function`` or ``type``; lines are 1-based, inclusive."""
    kind: str
    name: str
    first: int
    last: int
    start: int
    end: int
    families: Mapping[str, tuple[int, ...]] = field(default_factory=dict)
    entries: tuple[int, ...] = ()

    @property
    def recognized(self) -> bool:
        return bool(self.families)


@dataclass(frozen=True, slots=True)
class CScan:
    functions: tuple[CFunction, ...]
    gaps: tuple[str, ...]


def is_c_source(path: str, language: str | None) -> bool:
    suffix = path[path.rfind("."):].lower() if "." in path.rsplit("/", 1)[-1] else ""
    return suffix in SUFFIXES and (not language or language.lower() in LANGUAGE_NAMES)


def blank(text: str) -> str:
    """Replace comment, literal and preprocessor contents with spaces; keep every newline and offset."""
    out = list(text)
    i, n = 0, len(text)
    line_start = True
    while i < n:
        ch = text[i]
        if ch == "\n":
            line_start = True
            i += 1
            continue
        if line_start and ch == "#" and text[:i].rsplit("\n", 1)[-1].strip() == "":
            while i < n and text[i] != "\n":
                if text[i] == "\\" and i + 1 < n and text[i + 1] == "\n":
                    out[i] = " "
                    i += 2
                    continue
                out[i] = " "
                i += 1
            continue
        if not ch.isspace():
            line_start = False
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if text.startswith("/*", i):
            close = text.find("*/", i + 2)
            close = n if close < 0 else close + 2
            for j in range(i, close):
                if text[j] != "\n":
                    out[j] = " "
            i = close
            continue
        if ch in "\"'" and not (ch == "'" and _digit_separator(text, i)):
            quote = ch
            raw = text.startswith("R\"", i - 1) if i else False
            if raw:
                close_delim = text.find("(", i)
                delim = text[i + 1:close_delim] if 0 < close_delim - i < 20 else None
                if delim is not None:
                    terminator = ")" + delim + "\""
                    close = text.find(terminator, close_delim)
                    close = n if close < 0 else close + len(terminator)
                    for j in range(i + 1, close - 1):
                        if text[j] != "\n":
                            out[j] = " "
                    i = close
                    continue
            j = i + 1
            while j < n and text[j] != quote and text[j] != "\n":
                if text[j] == "\\":
                    j += 1
                j += 1
            for k in range(i + 1, min(j, n)):
                if text[k] != "\n":
                    out[k] = " "
            i = min(j + 1, n)
            continue
        i += 1
    return "".join(out)


def _digit_separator(text: str, i: int) -> bool:
    return i > 0 and text[i - 1].isdigit() and i + 1 < len(text) and text[i + 1].isalnum()


def _match_brace(blanked: str, start: int, end: int) -> int:
    depth = 0
    for i in range(start, end):
        if blanked[i] == "{":
            depth += 1
        elif blanked[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _function_name(head: str) -> str | None:
    """The declarator name of a head that ends in a parameter list plus qualifiers, or None."""
    stripped = head.rstrip()
    while True:
        changed = False
        for qualifier in _QUALIFIERS:
            if stripped.endswith(qualifier) and re.search(r"(?:^|[\s)>])" + re.escape(qualifier) + r"$", stripped):
                stripped = stripped[:-len(qualifier)].rstrip()
                changed = True
        arrow = re.search(r"->\s*[\w:<>*&\s]+$", stripped)
        if arrow is not None and ")" in stripped[:arrow.start()]:
            stripped = stripped[:arrow.start()].rstrip()
            changed = True
        if stripped.endswith(")"):
            open_index = _match_backwards(stripped, len(stripped) - 1)
            if open_index < 0:
                return None
            word = re.search(r"(\w+)\s*$", stripped[:open_index])
            if word is not None and word.group(1) in {"noexcept", "throw", "__attribute__", "alignas", "decltype",
                                                      "__declspec", "requires"}:
                stripped = stripped[:word.start(1)].rstrip()
                continue
            break
        if not changed:
            return None
    # A constructor initializer list ``Name(args) : base(x), member(y)`` follows the parameter list.
    colon = _initializer_colon(stripped)
    if colon >= 0 and stripped[:colon].rstrip().endswith(")"):
        stripped = stripped[:colon].rstrip()
    open_index = _match_backwards(stripped, len(stripped) - 1)
    if open_index < 0:
        return None
    before_params = stripped[:open_index]
    match = _NAME.search(before_params)
    if match is None:
        return None
    name = re.sub(r"\s+", "", match.group(1))
    bare = name.rsplit("::", 1)[-1].lstrip("~")
    if not bare or bare in _KEYWORDS or bare[0].isdigit():
        return None
    prefix = before_params[:match.start(1)].rstrip()
    if prefix.endswith(("=", "return", ",", "(", "&&", "||", "!", "?")) or (
            prefix.endswith(":") and not prefix.endswith("::")):
        return None
    return name


def _initializer_colon(text: str) -> int:
    depth = 0
    for i in range(len(text) - 1, -1, -1):
        ch = text[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth -= 1
        elif ch == ":" and depth == 0 and not (i > 0 and text[i - 1] == ":") and not text[i + 1:i + 2] == ":":
            return i
    return -1


def _match_backwards(text: str, close: int) -> int:
    depth = 0
    for i in range(close, -1, -1):
        if text[i] == ")":
            depth += 1
        elif text[i] == "(":
            depth -= 1
            if depth == 0:
                return i
    return -1


def scan(text: str) -> CScan:
    """Every complete function and named type definition of a C/C++ translation unit, in line order."""
    blanked = blank(text)
    functions: list[CFunction] = []
    gaps: list[str] = []
    _scan_region(text, blanked, 0, len(blanked), functions, gaps, nested=False)
    functions.sort(key=lambda item: (item.first, item.last, item.kind, item.name))
    return CScan(tuple(functions), tuple(dict.fromkeys(gaps)))


def _scan_region(text: str, blanked: str, start: int, end: int, out: list[CFunction], gaps: list[str],
                 *, nested: bool, owner: str = "") -> None:
    head_start = start
    i = start
    while i < end:
        ch = blanked[i]
        if ch == ";":
            head_start = i + 1
        elif ch == "}":
            head_start = i + 1
        elif ch == "{":
            close = _match_brace(blanked, i, end)
            if close < 0:
                gaps.append(f"unbalanced braces after line {_line_of(text, i)}; later definitions unscanned")
                return
            head = blanked[head_start:i]
            compact = re.sub(r"\s+", " ", head).strip()
            first_offset = head_start + (len(head) - len(head.lstrip()))
            first_line = _line_of(text, first_offset) if head.strip() else _line_of(text, i)
            last_line = _line_of(text, close)
            if _CONTAINER.match(compact):
                _scan_region(text, blanked, i + 1, close, out, gaps, nested=True)
            elif (type_match := _TYPE.match(compact)) is not None or _ANONYMOUS_TYPE.match(compact):
                name = type_match.group("name") if type_match else "<anonymous>"
                out.append(_type(text, blanked, name, first_line, last_line, first_offset, close + 1))
                _scan_region(text, blanked, i + 1, close, out, gaps, nested=True,
                             owner=f"{owner}{name}::" if name != "<anonymous>" else owner)
            else:
                name = _function_name(head)
                if name is not None:
                    if owner and "::" not in name:
                        name = owner + name
                    out.append(_function(text, blanked, name, first_line, last_line, first_offset, close + 1))
                elif compact and not nested and "=" not in compact and "enum" not in compact.split():
                    gaps.append(f"line {first_line}: unrecognised block head; 1 block omitted")
            i = close + 1
            head_start = i
            continue
        i += 1


def _arguments(blanked: str, open_index: int) -> list[str] | None:
    """Top-level comma-separated argument texts of the call whose ``(`` is at ``open_index``."""
    depth, current, values = 0, [], []
    for i in range(open_index, len(blanked)):
        ch = blanked[i]
        if ch in "([{":
            depth += 1
            if depth > 1:
                current.append(ch)
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                values.append("".join(current))
                return values
            current.append(ch)
        elif ch == "," and depth == 1:
            values.append("".join(current))
            current = []
        else:
            current.append(ch)
    return None


def _literal(argument: str) -> bool:
    value = argument.strip()
    return value.startswith(("\"", "L\"", "u8\"", "u\"", "U\"", "R\""))


def _constant_size(argument: str) -> bool:
    value = re.sub(r"\s+", "", argument)
    return bool(re.fullmatch(r"\(?(?:\([\w:*]+\))?\d+[uUlL]*\)?", value)
                or re.fullmatch(r"sizeof\(.*\)", value) or re.fullmatch(r"sizeof\s*\w+", value)
                or re.fullmatch(r"\d+[uUlL]*\*sizeof\(.*\)", value) or re.fullmatch(r"sizeof\(.*\)\*\d+[uUlL]*", value)
                or value in {"PATH_MAX", "BUFSIZ", "FILENAME_MAX", "NAME_MAX"})


def _function(text: str, blanked: str, name: str, first: int, last: int, start: int, end: int) -> CFunction:
    body = blanked[start:end]
    lines_offset = _line_of(text, start)
    families: dict[str, list[int]] = {}
    entries: list[int] = []
    bare = name.rsplit("::", 1)[-1]

    def mark(family: str, offset: int) -> None:
        line = lines_offset + body.count("\n", 0, offset)
        values = families.setdefault(family, [])
        if line not in values:
            values.append(line)

    logging_function = bool(_LOG_NAME.search(bare))
    session_function = bool(_SESSION_NAME.search(bare))
    for match in _CALL.finditer(body):
        callee = re.sub(r"\s+", "", match.group(1))
        short = callee.rsplit("::", 1)[-1]
        if short in _KEYWORDS and short not in {"new", "delete"}:
            continue
        arguments = _arguments(body, match.end() - 1)
        if arguments is None:
            continue
        offset = match.start(1)
        if short in _ENTRY_CALLS:
            mark(INPUT_ENTRY, offset)
            entries.append(lines_offset + body.count("\n", 0, offset))
        if short in _COMMAND_CALLS:
            mark(COMMAND_SINK, offset)
        position = _FORMAT_POSITION.get(short)
        if position is not None and len(arguments) > position and not _literal(arguments[position]):
            mark(FORMAT_SINK, offset)
        if short in _COPY_CALLS:
            mark(COPY_SINK, offset)
        position = _ALLOCATION_POSITION.get(short)
        if position is not None and len(arguments) > position and not _constant_size(arguments[position]):
            mark(ALLOCATION_SIZE, offset)
        if short in _RELEASE_CALLS and short in {"free", "cfree"}:
            mark(MEMORY_RELEASE, offset)
        position = _PATH_POSITION.get(short)
        if position is not None and len(arguments) > position and not _literal(arguments[position]):
            mark(FILE_PATH, offset)
        if short in _LOG_CALLS or (short in {"fprintf", "vfprintf", "fputs", "fputc", "fwrite", "putc"}
                                   and any("stderr" in argument for argument in arguments)):
            mark(LOG_SINK, offset)
        elif short in _STDOUT_CALLS and logging_function:
            mark(LOG_SINK, offset)
        elif short not in _STDOUT_CALLS and _LOG_NAME.search(short) and short != bare:
            mark(LOG_SINK, offset)
        if _SESSION_NAME.search(short) and short != bare:
            mark(SESSION_STATE, offset)
        if short in _ERROR_CALLS:
            mark(ERROR_PATH, offset)
    for match in _STREAM_OPEN.finditer(body):
        arguments = _arguments(body, match.end() - 1)
        if arguments and not _literal(arguments[0]):
            mark(FILE_PATH, match.start())
    for match in _NEW_ARRAY.finditer(body):
        if not _constant_size(match.group(1)):
            mark(ALLOCATION_SIZE, match.start())
    for match in _DELETE.finditer(body):
        mark(MEMORY_RELEASE, match.start())
    for match in re.finditer(r"\bargv\s*\[", body):
        mark(INPUT_ENTRY, match.start())
        entries.append(lines_offset + body.count("\n", 0, match.start()))
    for match in _STREAM_STDERR.finditer(body):
        mark(LOG_SINK, match.start())
    for match in _ERROR_RETURN.finditer(body):
        mark(ERROR_PATH, match.start())
    for match in re.finditer(r"\bthrow\b|\berrno\b", body):
        mark(ERROR_PATH, match.start())
    if session_function:
        mark(SESSION_STATE, 0)
    else:
        # A parameter or local of a session/token/cookie type is a use of that state.
        for match in re.finditer(r"\b(" + _IDENT + r")\s*\*?\s*&?\s*" + _IDENT + r"\s*[,;=)]", body):
            if _SESSION_NAME.search(match.group(1)) and match.group(1) not in {"return", "sizeof"}:
                mark(SESSION_STATE, match.start())
                break
    return CFunction("function", name, first, last, start, end,
                     {family: tuple(sorted(lines)) for family, lines in sorted(families.items())},
                     tuple(sorted(set(entries))))


def _type(text: str, blanked: str, name: str, first: int, last: int, start: int, end: int) -> CFunction:
    families = {SESSION_STATE: (first,)} if _SESSION_NAME.search(name) else {}
    return CFunction("type", name, first, last, start, end, families, ())


def normalized(text: str, item: CFunction) -> str:
    """Whitespace- and comment-insensitive text of one definition, for a position-independent identity."""
    return re.sub(r"\s+", " ", blank(text)[item.start:item.end]).strip()


def families_of(functions: Sequence[CFunction]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in functions:
        for family in item.families:
            counts[family] = counts.get(family, 0) + 1
    return dict(sorted(counts.items()))
