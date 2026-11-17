"""T-5013: the C/C++ scanner names complete definitions and the recogniser families inside them.

Positive and negative snippets per family; no model, no index, no file system. The scanner is what makes a
C/C++ subject re-derivable from the excerpt bytes alone, so these tests pin its exact spans and lines.
"""
from __future__ import annotations

import pytest

from appsec_review.owasp_workbench import c_subjects as c


SERVER = (
    "// Request handling for the smoke server.\n"                       # 1
    "#include <cstdio>\n"                                                 # 2
    "#include <sys/socket.h>\n"                                           # 3
    "\n"                                                                  # 4
    "namespace {\n"                                                       # 5
    "const char *const kRoot = \"/var/lib/smoke\";  // comment with { brace\n"  # 6
    "}  // namespace\n"                                                   # 7
    "\n"                                                                  # 8
    "struct Session {\n"                                                  # 9
    "  char name[32];\n"                                                  # 10
    "  char *scratch;\n"                                                  # 11
    "};\n"                                                                # 12
    "\n"                                                                  # 13
    "/* Writes one line to the log; the client supplies the line. */\n"   # 14
    "void log_message(const char *fmt) {\n"                               # 15
    "  printf(fmt);\n"                                                    # 16
    "  putchar('\\n');\n"                                                 # 17
    "}\n"                                                                 # 18
    "\n"                                                                  # 19
    "long serve_file(const char *name, char *out, size_t cap) {\n"        # 20
    "  char path[512];\n"                                                 # 21
    "  snprintf(path, sizeof(path), \"%s/%s\", kRoot, name);\n"           # 22
    "  FILE *file = fopen(path, \"rb\");\n"                               # 23
    "  if (file == nullptr) {\n"                                          # 24
    "    return -1;\n"                                                    # 25
    "  }\n"                                                               # 26
    "  size_t n = fread(out, 1, cap, file);\n"                            # 27
    "  fclose(file);\n"                                                   # 28
    "  return (long)n;\n"                                                 # 29
    "}\n"                                                                 # 30
    "\n"                                                                  # 31
    "int handle_request(char *line, int sock, Session *session) {\n"      # 32
    "  char cmd[640];\n"                                                  # 33
    "  snprintf(cmd, sizeof(cmd), \"/usr/libexec/report %s\", line);\n"   # 34
    "  FILE *pipe = popen(cmd, \"r\");\n"                                 # 35
    "  unsigned size = (unsigned)line[0] * (unsigned)line[1];\n"          # 36
    "  unsigned char *pixels = (unsigned char *)malloc(size);\n"          # 37
    "  memcpy(pixels, line + 2, size);\n"                                 # 38
    "  free(pixels);\n"                                                   # 39
    "  session->scratch[0] = '\\0';\n"                                    # 40
    "  log_message(line);\n"                                              # 41
    "  return 200;\n"                                                     # 42
    "}\n"                                                                 # 43
    "\n"                                                                  # 44
    "int serve_once(int sock) {\n"                                        # 45
    "  static char line[1024];\n"                                         # 46
    "  ssize_t n = recv(sock, line, sizeof(line) - 1, 0);\n"              # 47
    "  if (n <= 0) {\n"                                                   # 48
    "    return -1;\n"                                                    # 49
    "  }\n"                                                               # 50
    "  return handle_request(line, sock, nullptr);\n"                     # 51
    "}\n"                                                                 # 52
)


def by_name(text: str) -> dict[str, c.CFunction]:
    return {item.name: item for item in c.scan(text).functions}


def test_scan_names_complete_definitions_with_exact_line_spans() -> None:
    scan = c.scan(SERVER)
    assert scan.gaps == ()
    assert [(item.kind, item.name, item.first, item.last) for item in scan.functions] == [
        ("type", "Session", 9, 12), ("function", "log_message", 15, 18), ("function", "serve_file", 20, 30),
        ("function", "handle_request", 32, 43), ("function", "serve_once", 45, 52)]


def test_families_and_lines_match_the_recognised_calls() -> None:
    functions = by_name(SERVER)
    assert functions["Session"].families == {c.SESSION_STATE: (9,)}
    assert functions["log_message"].families == {c.FORMAT_SINK: (16,), c.LOG_SINK: (16, 17)}
    assert functions["serve_file"].families == {c.ERROR_PATH: (25,), c.FILE_PATH: (23,), c.INPUT_ENTRY: (27,)}
    assert functions["serve_file"].entries == (27,)
    assert functions["handle_request"].families == {
        c.ALLOCATION_SIZE: (37,), c.COMMAND_SINK: (35,), c.COPY_SINK: (38,), c.LOG_SINK: (41,),
        c.MEMORY_RELEASE: (39,), c.SESSION_STATE: (32,)}
    assert functions["serve_once"].families == {c.ERROR_PATH: (49,), c.INPUT_ENTRY: (47,)}


@pytest.mark.parametrize(("family", "positive", "negative"), [
    (c.INPUT_ENTRY, "int main(int argc, char **argv) {\n  return argv[1][0];\n}\n",
     "int f(int n) {\n  return n;\n}\n"),
    (c.INPUT_ENTRY, "int g(void) {\n  char *v = getenv(\"X\");\n  return v != 0;\n}\n",
     "int g(void) {\n  // getenv(\"X\") in a comment\n  const char *s = \"getenv(X)\";\n  return s[0];\n}\n"),
    (c.COMMAND_SINK, "void t(const char *a) {\n  system(a);\n}\n", "void t(const char *a) {\n  puts(a);\n}\n"),
    (c.FORMAT_SINK, "void l(const char *m) {\n  fprintf(stderr, m);\n}\n",
     "void l(const char *m) {\n  fprintf(stderr, \"%s\", m);\n}\n"),
    (c.FORMAT_SINK, "void l(char *b, const char *m) {\n  snprintf(b, 8, m);\n}\n",
     "void l(char *b, const char *m) {\n  snprintf(b, 8, \"%s\", m);\n}\n"),
    (c.COPY_SINK, "void p(char *s) {\n  char b[8];\n  strcpy(b, s);\n}\n",
     "void p(char *s) {\n  char b[8];\n  strlcpy(b, s, sizeof b);\n}\n"),
    (c.ALLOCATION_SIZE, "void *a(unsigned w, unsigned h) {\n  return malloc(w * h);\n}\n",
     "void *a(void) {\n  void *x = malloc(64);\n  return realloc(x, sizeof(int) * 4);\n}\n"),
    (c.ALLOCATION_SIZE, "int *a(int n) {\n  return new int[n];\n}\n", "int *a(void) {\n  return new int[4];\n}\n"),
    (c.MEMORY_RELEASE, "void r(void *p) {\n  free(p);\n}\n", "void r(void *p) {\n  (void)p;\n}\n"),
    (c.MEMORY_RELEASE, "void r(int *p) {\n  delete[] p;\n}\n", "void r(int *p) {\n  *p = 0;\n}\n"),
    (c.FILE_PATH, "int o(const char *n) {\n  return open(n, 0);\n}\n", "int o(void) {\n  return open(\"/etc/motd\", 0);\n}\n"),
    (c.FILE_PATH, "bool o(const std::string &n) {\n  std::ifstream in(n);\n  return in.good();\n}\n",
     "bool o() {\n  std::ifstream in(\"fixed.txt\");\n  return in.good();\n}\n"),
    (c.SESSION_STATE, "void session_reset(void) {\n}\n", "void frame_reset(void) {\n}\n"),
    (c.SESSION_STATE, "int use(Token *token) {\n  return token->id;\n}\n", "int use(Frame *frame) {\n  return frame->id;\n}\n"),
    (c.SESSION_STATE, "struct Cookie {\n  int id;\n};\n", "struct Frame {\n  int id;\n};\n"),
    (c.LOG_SINK, "void w(const char *m) {\n  syslog(LOG_INFO, \"%s\", m);\n}\n", "void w(const char *m) {\n  puts(m);\n}\n"),
    (c.LOG_SINK, "void audit_write(const char *m) {\n  puts(m);\n}\n", "void write_all(const char *m) {\n  puts(m);\n}\n"),
    (c.LOG_SINK, "void w(const char *m) {\n  std::cerr << m;\n}\n", "void w(const char *m) {\n  std::cout << m;\n}\n"),
    (c.ERROR_PATH, "int e(int x) {\n  if (x) {\n    return -1;\n  }\n  return 0;\n}\n", "int e(int x) {\n  return x + 1;\n}\n"),
    (c.ERROR_PATH, "void e(int x) {\n  if (x) {\n    abort();\n  }\n}\n", "void e(int x) {\n  (void)x;\n}\n"),
], ids=lambda value: value.split("/")[0] if isinstance(value, str) and value.endswith("/1") else None)
def test_each_family_has_a_positive_and_a_negative_snippet(family: str, positive: str, negative: str) -> None:
    [item] = c.scan(positive).functions
    assert family in item.families, item.families
    [other] = c.scan(negative).functions
    assert family not in other.families, other.families


def test_blanking_keeps_offsets_and_hides_literals_comments_and_preprocessor() -> None:
    text = "#define X \"{\"\n/* { */ int f() { const char *s = \"}\"; char c = '{'; return 0; } // }\n"
    blanked = c.blank(text)
    assert len(blanked) == len(text) and blanked.count("\n") == text.count("\n")
    assert blanked.count("{") == 1 and blanked.count("}") == 1
    [item] = c.scan(text).functions
    assert (item.name, item.first, item.last) == ("f", 2, 2)


def test_members_namespaces_and_qualifiers_are_scanned_and_named() -> None:
    text = (
        "namespace app {\n"
        "struct Handler {\n"
        "  virtual ~Handler() {}\n"
        "  virtual void handle(char *dst, const char *src) = 0;\n"
        "};\n"
        "struct CopyHandler : Handler {\n"
        "  CopyHandler() : Handler() {}\n"
        "  void handle(char *dst, const char *src) override { strcpy(dst, src); }\n"
        "  int size() const noexcept { return 0; }\n"
        "};\n"
        "}  // namespace app\n"
        "extern \"C\" {\n"
        "int c_entry(void) { return 0; }\n"
        "}\n"
        "template <typename T> T first(T *items) { return items[0]; }\n"
        "auto lambda = [](int x) { return x; };\n"
        "int table[] = {1, 2, 3};\n"
    )
    scan = c.scan(text)
    names = [(item.kind, item.name, item.first) for item in scan.functions]
    assert names == [
        ("type", "Handler", 2), ("function", "Handler::~Handler", 3), ("type", "CopyHandler", 6),
        ("function", "CopyHandler::CopyHandler", 7), ("function", "CopyHandler::handle", 8),
        ("function", "CopyHandler::size", 9), ("function", "c_entry", 13), ("function", "first", 15)]
    assert scan.gaps == ()
    assert c.COPY_SINK in by_name(text)["CopyHandler::handle"].families


def test_unbalanced_braces_and_unknown_block_heads_are_named_gaps_not_subjects() -> None:
    scan = c.scan("int f(void) {\n  return 0;\n")
    assert scan.functions == () and scan.gaps == ("unbalanced braces after line 1; later definitions unscanned",)
    scan = c.scan("PRE_HOOK {\n  int x;\n}\nint g(void) { return 1; }\n")
    assert [item.name for item in scan.functions] == ["g"]
    assert scan.gaps == ("line 1: unrecognised block head; 1 block omitted",)


def test_normalized_identity_ignores_layout_and_comments_but_not_tokens() -> None:
    [first] = c.scan("int f(int a) {\n  return a;  // one\n}\n").functions
    [second] = c.scan("\n\nint f(int a)\n{\n    return a; /* two */\n}\n").functions
    [third] = c.scan("int f(int a) {\n  return a + 1;\n}\n").functions
    one = c.normalized("int f(int a) {\n  return a;  // one\n}\n", first)
    two = c.normalized("\n\nint f(int a)\n{\n    return a; /* two */\n}\n", second)
    assert one == two != c.normalized("int f(int a) {\n  return a + 1;\n}\n", third)


@pytest.mark.parametrize(("path", "language", "expected"), [
    ("src/a.c", "C", True), ("src/a.cpp", "C++", True), ("src/a.h", "C/C++", True), ("src/a.cc", None, True),
    ("src/a.py", "Python", False), ("src/a.c", "Rust", False), ("src/a.js", "JavaScript", False), ("README", None, False),
])
def test_is_c_source_reads_suffix_and_declared_language(path: str, language: str | None, expected: bool) -> None:
    assert c.is_c_source(path, language) is expected
