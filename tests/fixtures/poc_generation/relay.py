"""What a ``poc_writer`` would produce for the cpp-multivuln ``packet.cpp:16`` overflow, and its bad variants.

``relay::parse_header`` copies ``out.length`` bytes (from the input's length field) into the 16-byte
``Header::name``. The guard on line 13 compares the buffer size with the length field, not with the
capacity of ``name``, so a 24-byte packet whose length field is 20 overflows the buffer (a stack write
past ``name``), and one whose length field is 8 does not. The good variant is the hand-written
reproducer used by the live compile test; each bad variant breaks exactly one validator.

The recorded ASTs under ``ast/`` were produced once from these sources by ``record_ast.py`` in the
local build image (``audit-buildenv-cpp:local``, clang 18.1.3) and are committed so the AST checks are
unit-tested without Docker.
"""
from __future__ import annotations

from typing import Any

SINK = "relay::parse_header"
TEST_NAME = "poc_parse_header_overlong_name"
CONTROL_NAME = "poc_parse_header_name_fits"
INCLUDES = ("relay/relay.hpp", "cstring")
PACKET_ARGV = (
    "/usr/bin/clang++", "-I/workspace/include", "-O2", "-g", "-DNDEBUG", "-std=c++17", "-Wall", "-Wextra", "-MD",
    "-MT", "CMakeFiles/relay.dir/src/packet.cpp.o", "-MF", "CMakeFiles/relay.dir/src/packet.cpp.o.d", "-o",
    "CMakeFiles/relay.dir/src/packet.cpp.o", "-c", "/workspace/src/packet.cpp")

GOOD_TEST = f"""void {TEST_NAME}() {{
  // A 4-byte header (kind 1, length field 20) followed by 20 name bytes; Header::name holds 16.
  std::uint8_t packet[24] = {{1, 0, 20, 0}};
  std::memset(packet + 4, 'A', 20);
  relay::Header header{{}};
  relay::parse_header(packet, sizeof packet, header);
}}"""
GOOD_CONTROL = f"""void {CONTROL_NAME}() {{
  // The same call with a length field of 8, which fits in Header::name.
  std::uint8_t packet[12] = {{1, 0, 8, 0}};
  std::memset(packet + 4, 'A', 8);
  relay::Header header{{}};
  relay::parse_header(packet, sizeof packet, header);
}}"""
TRIGGER = {"field": "header.length", "where": "bytes 2..3", "constraint": "greater than 16",
           "why": "G2 compares the size with the length field, not with the 16-byte capacity"}


def answer(test: str = GOOD_TEST, control: str = GOOD_CONTROL, *, includes: tuple[str, ...] = INCLUDES,
           test_name: str = TEST_NAME, control_name: str = CONTROL_NAME) -> dict[str, Any]:
    """The writer's compact answer (review-judge-and-poc.md section 5.2) for ``test`` and ``control``."""
    return {
        "action": "final",
        "result": {
            "claim": "c1",
            "test_function": {"name": test_name, "includes": list(includes), "source": test},
            "negative_control": {"name": control_name, "source": control},
            "setup": ["a 24-byte packet: 4-byte header with length field 20, then 20 name bytes",
                      "a Header out object"],
            "expected_observation": "a stack-buffer-overflow write to Header::name in memcpy under a sanitizer",
            "breakpoints": [{"function": SINK, "line": 16, "why": "the unbounded copy"}],
            "notes": "Add to the unit-test target; build with -fsanitize=address,undefined -g -O0 to observe the fault."}}


def variant(old: str, new: str) -> str:
    assert old in GOOD_TEST
    return GOOD_TEST.replace(old, new)


#: name -> (test source, control source, expected first violation rule or None)
VARIANTS: dict[str, tuple[str, str, str | None]] = {
    "good": (GOOD_TEST, GOOD_CONTROL, None),
    "main_defined": (GOOD_TEST + "\n\nint main() { return 0; }", GOOD_CONTROL, "entry_point"),
    "system_call": (variant("relay::Header header{};", 'relay::Header header{};\n  system("id");'), GOOD_CONTROL,
                    "call_not_allowlisted"),
    "ifstream": (variant("relay::Header header{};", 'relay::Header header{};\n  std::ifstream input("data");'),
                 GOOD_CONTROL, "type_not_allowed"),
    "getenv_call": (variant("relay::Header header{};", 'relay::Header header{};\n  (void)getenv("HOME");'),
                    GOOD_CONTROL, "call_not_allowlisted"),
    "inline_asm": (variant("relay::Header header{};", 'relay::Header header{};\n  __asm__("nop");'), GOOD_CONTROL,
                   "inline_asm"),
    "while_loop": (variant("relay::Header header{};", "relay::Header header{};\n  while (packet[0]) { break; }"),
                   GOOD_CONTROL, "unbounded_loop"),
    "huge_loop": (variant("relay::Header header{};",
                          "relay::Header header{};\n  for (int i = 0; i < 100000; ++i) { packet[0] = 1; }"),
                  GOOD_CONTROL, "unbounded_loop"),
    "recursion": (variant("relay::Header header{};", f"relay::Header header{{}};\n  {TEST_NAME}();"),
                  GOOD_CONTROL, "recursion"),
    "url_literal": (variant("relay::Header header{};",
                            'relay::Header header{};\n  const char *where = "http://attacker.example/x";\n  (void)where;'),
                    GOOD_CONTROL, "url_literal"),
    "secret_literal": (variant("relay::Header header{};",
                               'relay::Header header{};\n  const char *key = "api_key=hunter2";\n  (void)key;'),
                       GOOD_CONTROL, "secret_literal"),
    "path_literal": (variant("relay::Header header{};",
                             'relay::Header header{};\n  const char *where = "/etc/passwd";\n  (void)where;'),
                     GOOD_CONTROL, "path_literal"),
    "never_calls_sink": (variant("  relay::parse_header(packet, sizeof packet, header);\n", "  (void)header;\n"),
                         GOOD_CONTROL, "sink_not_called"),
    "trigger_absent": (GOOD_CONTROL.replace(CONTROL_NAME, TEST_NAME), GOOD_CONTROL, "trigger_absent"),
    "extra_declaration": ("static int counter = 0;\n" + GOOD_TEST, GOOD_CONTROL, "unexpected_declaration"),
    "project_call": (variant("relay::Header header{};", 'relay::Header header{};\n  (void)relay::probe_host("x");'),
                     GOOD_CONTROL, "call_not_allowlisted"),
    "unlisted_call": (variant("relay::Header header{};", "relay::Header header{};\n  (void)rand();"), GOOD_CONTROL,
                      "call_not_allowlisted"),
    "huge_array": (variant("std::uint8_t packet[24]", "std::uint8_t packet[1000000]"), GOOD_CONTROL, "array_size"),
    "huge_new": (variant("relay::Header header{};", "relay::Header header{};\n  auto *big = new int[100000];\n  delete[] big;"),
                 GOOD_CONTROL, "allocation_size"),
    "lambda": (variant("relay::Header header{};", "relay::Header header{};\n  auto f = [] {};\n  f();"), GOOD_CONTROL,
               "unsupported_construct"),
    "goto": (variant("relay::Header header{};", "relay::Header header{};\n  goto done;\n  done:;"), GOOD_CONTROL,
             "unbounded_loop"),
    "function_pointer": (variant("relay::Header header{};",
                                 "relay::Header header{};\n  auto fp = &relay::parse_header;\n  fp(packet, sizeof packet, header);"),
                         GOOD_CONTROL, "indirect_call"),
    "constructor_attribute": ("__attribute__((constructor)) " + GOOD_TEST, GOOD_CONTROL, "attribute"),
    "huge_vector": (variant("relay::Header header{};", "relay::Header header{};\n  std::vector<std::uint8_t> big(1000000);"),
                    GOOD_CONTROL, "allocation_size"),
    "string_fill": (GOOD_TEST.replace("  std::memset(packet + 4, 'A', 20);\n", "  std::string name(20, 'A');\n  std::memcpy(packet + 4, name.data(), 20);\n"),
                    GOOD_CONTROL, None),
    "syntax_error": (variant("relay::Header header{};", "relay::Header header{}"), GOOD_CONTROL, None),
}
