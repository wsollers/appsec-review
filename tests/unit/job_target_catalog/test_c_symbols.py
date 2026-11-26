from __future__ import annotations

from appsec_review.jobs.job_target_catalog.c_symbols import extract_c_family_symbols


def test_c_family_symbols_ignore_comments_locals_and_extract_functions_and_types():
    source = """\
/* Multi-line comment with prose:
 * struct must not be indexed, nor class can or struct for.
 */
// Single-line comment: struct nope { int x; };
struct internal_state;

typedef struct z_stream_s {
    int avail_in;
    struct internal_state *state;
} z_stream;

struct Session {
    int id;
    Session() : id(0) {}
};

#define CJSON_PUBLIC(type) type

CJSON_PUBLIC(struct Session *) session_open(const char *name) {
    struct frame f;
    if (name == 0) {
        return 0;
    }
    return 0;
}

int ZEXPORT deflateInit_(strm, level)
    z_stream *strm;
    int level;
{
    return level;
}
"""
    symbols = extract_c_family_symbols(source)
    extracted = [(s.name, s.kind, s.line) for s in symbols]
    assert extracted == [
        ("z_stream_s", "struct", 7),
        ("z_stream", "typedef", 10),
        ("Session", "struct", 12),
        ("Session", "function", 14),
        ("session_open", "function", 19),
        ("deflateInit_", "function", 27),
    ]


def test_c_family_symbols_unwrap_macro_declarators_and_post_brace_attributes():
    source = """\
typedef union { U16 u16; U32 u32; } __attribute__((packed)) unalign;
typedef struct { int x; } __declspec(align(16)) AlignedItem, *PAlignedItem;

int BZ_API(BZ2_bzCompressInit) (
    bz_stream *strm,
    int blockSize100k
)
{
    return blockSize100k;
}

const char * BZ_API(BZ2_bzlibVersion)(void)
{
    return "1.0.6";
}

int (paren_wrapped_fn)(int value)
{
    return value + 1;
}
"""
    symbols = extract_c_family_symbols(source)
    extracted = [(s.name, s.kind, s.line) for s in symbols]
    assert extracted == [
        ("unalign", "typedef", 1),
        ("AlignedItem", "typedef", 2),
        ("PAlignedItem", "typedef", 2),
        ("BZ2_bzCompressInit", "function", 4),
        ("BZ2_bzlibVersion", "function", 12),
        ("paren_wrapped_fn", "function", 17),
    ]


def test_c_symbols_formfeed_and_vertical_tab_preserve_exact_line_and_byte_offsets():
    raw_text = "/* page 1 */\f/* still line 1 */\n/* vtab */\vint exact_offset_fn(int x) { return x; }\n"
    raw_bytes = raw_text.encode("utf-8")
    hits = extract_c_family_symbols(raw_text)
    assert [(h.name, h.kind, h.line) for h in hits] == [("exact_offset_fn", "function", 2)]
    hit = hits[0]
    line_slice = raw_bytes[hit.line_start_byte:hit.line_end_byte].decode("utf-8")
    assert line_slice == "/* vtab */\vint exact_offset_fn(int x) { return x; }\n"


def test_c_symbols_define_macro_string_and_ifdef_else_dual_braces():
    source = """#define GLOB_PAT "/* not a block comment"
#define LINE_PAT "// not a line comment" \
    "/* multiline macro string"

#ifdef USE_FAST_PATH
int dual_branch_fn(int a) {
#else
int dual_branch_fn(int a) {
#endif
    return a + 1;
}

int survived_after_macro_and_ifdef(void) {
    return 42;
}
"""
    hits = extract_c_family_symbols(source)
    names = [(h.name, h.kind) for h in hits]
    assert ("survived_after_macro_and_ifdef", "function") in names


def test_c_symbols_modern_cpp_namespaces_literals_templates_operators_and_attributes():
    source = """inline namespace v1 {
export namespace api {

constexpr int kBudget = 1'000'000;
const char8_t *kRaw = u8R"delim(
struct FakeInsideRawString { int bad; };
int fake_raw_fn() { return 0; }
)delim";

struct [[nodiscard]] TaggedBox {
    int value;
    bool operator==(const TaggedBox &other) const { return value == other.value; }
    int operator()(int delta) const { return value + delta; }
};

std::function<void()> on_ready = nullptr;

template <typename T = int>
T templated_compute(T input) {
    return input;
}

std::ostream &operator<<(std::ostream &os, const TaggedBox &box) {
    return os;
}

} // namespace api
} // namespace v1
"""
    hits = extract_c_family_symbols(source)
    by_name_kind = [(h.name, h.kind) for h in hits]
    assert ("TaggedBox", "struct") in by_name_kind
    assert ("templated_compute", "function") in by_name_kind
    assert ("operator==", "function") in by_name_kind
    assert ("operator()", "function") in by_name_kind
    assert ("operator<<", "function") in by_name_kind
    assert ("FakeInsideRawString", "struct") not in by_name_kind
    assert ("fake_raw_fn", "function") not in by_name_kind
    assert ("on_ready", "function") not in by_name_kind


def test_symbol_index_exact_50000_cpp_boundary_complete(tmp_path, monkeypatch):
    from appsec_review.interchange import validate_unit_output
    from appsec_review.jobs.job_target_catalog import job as catalog_job
    from tests.unit.job_target_catalog.support import (
        INDEX_UNITS, PARTITION, capture_indexes, context, handler, partition, source,
    )

    assert catalog_job.MAX_CPP_SYMBOLS == 50_000
    builders_ok = capture_indexes(monkeypatch)
    unit_ok = context(tmp_path, INDEX_UNITS[1])
    unit_ok.job.config.job_id = "job_target_catalog"
    part_a = "".join(f"int a{i}(){{}}\n" for i in range(30_000)).encode("utf-8")
    part_b = "".join(f"int b{i}(){{}}\n" for i in range(20_000)).encode("utf-8")
    f_a = source(unit_ok, "src/part_a.cpp", part_a, "C++")
    f_b = source(unit_ok, "src/part_b.cpp", part_b, "C++")
    unit_ok.outputs[PARTITION] = partition([f_a, f_b])
    res_ok = handler(unit_ok.unit_id)(unit_ok)
    validate_unit_output(res_ok, unit_id=unit_ok.unit_id, strict_gaps=True)
    assert res_ok["item_count"] == 50_000
    assert res_ok["gaps"] == []
    assert builders_ok[0].coverage == [("declarations", "complete", None)]


def test_symbol_index_exact_50000_cpp_boundary_with_remaining_file_partial(tmp_path, monkeypatch):
    from appsec_review.interchange import GapCode, validate_unit_output
    from appsec_review.jobs.job_target_catalog import job as catalog_job
    from tests.unit.job_target_catalog.support import (
        INDEX_UNITS, PARTITION, capture_indexes, context, handler, partition, source,
    )

    assert catalog_job.MAX_CPP_SYMBOLS == 50_000
    builders_trunc = capture_indexes(monkeypatch)
    unit_trunc = context(tmp_path, INDEX_UNITS[1])
    unit_trunc.job.config.job_id = "job_target_catalog"
    full_50k = "".join(f"int c{i}(){{}}\n" for i in range(50_000)).encode("utf-8")
    f_full = source(unit_trunc, "src/full.cpp", full_50k, "C++")
    f_later = source(unit_trunc, "src/later.cpp", b"int missed_fn(){}\n", "C++")
    unit_trunc.outputs[PARTITION] = partition([f_full, f_later])
    res_trunc = handler(unit_trunc.unit_id)(unit_trunc)
    validate_unit_output(res_trunc, unit_id=unit_trunc.unit_id, strict_gaps=True)
    assert res_trunc["item_count"] == 50_000
    assert [g["code"] for g in res_trunc["gaps"]] == [GapCode.TRUNCATED.value]
    assert builders_trunc[0].coverage == [("declarations", "partial", res_trunc["gaps"][0]["gap_id"])]
