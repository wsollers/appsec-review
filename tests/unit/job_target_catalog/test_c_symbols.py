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
