"""Automake variables and conditionals in build discovery (T-091)."""
from __future__ import annotations

from appsec_review.jobs.build_points import autotools_build_points

ROOT_AM = """ACLOCAL_AMFLAGS = -I m4

if SRV_LIB
SSUBDIRS = ai server
else
SSUBDIRS =
endif

if MAKE_DATA
DSUBDIRS = data
else
DSUBDIRS =
endif

SUBDIRS = gen_headers $(DSUBDIRS) common $(SSUBDIRS) client $(EXTERNAL_DIR) .
"""

CLIENT_AM = """GUI_SUBDIRS =
if GUI_SDL2
GUI_SUBDIRS += gui-sdl2
endif
if GUI_GTK
if GTK4
GUI_SUBDIRS += gui-gtk-4.0
else
GUI_SUBDIRS += gui-gtk-3.22
endif
endif
ALL_DIRS = $(GUI_SUBDIRS) agents
SUBDIRS = $(ALL_DIRS)

bin_PROGRAMS =
if MODINST_CLI
bin_PROGRAMS += game-mp-cli
endif
if MODINST_GTK
bin_PROGRAMS += game-mp-gtk
endif
noinst_LTLIBRARIES = libcommon.la

da_sources = \\
\tcli.c \\
\tcli.h
libcommon_la_SOURCES = common.c $(shared_sources)
shared_sources = shared.c
if MODINST_CLI
game_mp_cli_SOURCES = $(da_sources)
endif
if MODINST_GTK
game_mp_gtk_SOURCES = gtk.c $(GENERATED)
endif
"""

INVENTORY = ("Makefile.am", "client/Makefile.am", "client/cli.c", "client/cli.h", "client/gtk.c",
             "client/common.c", "client/shared.c")


def _drives(text: str, path: str = "Makefile.am") -> dict:
    return autotools_build_points(".", {path: text}, INVENTORY)


def test_subdirs_reached_through_variables_and_conditionals_are_all_driven() -> None:
    result = _drives(ROOT_AM)
    assert [(drive["path"], drive["evidence"], drive.get("condition")) for drive in result["drives"]] == [
        ("gen_headers", "Makefile.am:15", None),
        ("data", "Makefile.am:10", "MAKE_DATA"),
        ("common", "Makefile.am:15", None),
        ("ai", "Makefile.am:4", "SRV_LIB"),
        ("server", "Makefile.am:4", "SRV_LIB"),
        ("client", "Makefile.am:15", None),
    ]
    # A variable with no assignment in the file is recorded, never guessed and never dropped silently.
    assert result["unresolved"] == [{
        "evidence": "Makefile.am:15", "kind": "unassigned_variable",
        "reason": "SUBDIRS references $(EXTERNAL_DIR), which has no assignment in this file"}]


def test_appended_and_nested_conditional_subdirs_carry_their_condition() -> None:
    result = _drives(CLIENT_AM, "client/Makefile.am")
    assert [(drive["path"], drive["evidence"], drive.get("condition")) for drive in result["drives"]] == [
        ("client/gui-sdl2", "client/Makefile.am:3", "GUI_SDL2"),
        ("client/gui-gtk-4.0", "client/Makefile.am:7", "GUI_GTK && GTK4"),
        ("client/gui-gtk-3.22", "client/Makefile.am:9", "GUI_GTK && !GTK4"),
        ("client/agents", "client/Makefile.am:12", None),
    ]


def test_appended_programs_are_all_kept_and_sources_follow_variables() -> None:
    result = _drives(CLIENT_AM, "client/Makefile.am")
    points = {point["name"]: point for point in result["build_points"]}
    assert set(points) == {"game-mp-cli", "game-mp-gtk", "libcommon.la"}
    assert points["game-mp-cli"] == {
        "name": "game-mp-cli", "kind": "program", "evidence": "client/Makefile.am:17",
        "condition": "MODINST_CLI", "sources": ["client/cli.c", "client/cli.h"], "include_dirs": []}
    assert points["game-mp-gtk"]["sources"] == ["client/gtk.c"]
    assert points["game-mp-gtk"]["condition"] == "MODINST_GTK"
    # A variable assigned after its use still resolves: make variables are read whole-file.
    assert points["libcommon.la"]["sources"] == ["client/common.c", "client/shared.c"]
    assert "condition" not in points["libcommon.la"]
    assert {"evidence": "client/Makefile.am:33", "kind": "unassigned_variable",
            "reason": "game_mp_gtk_SOURCES references $(GENERATED), which has no assignment in this file"} \
        in result["unresolved"]


def test_a_value_reached_both_conditionally_and_unconditionally_has_no_condition() -> None:
    text = "if A\nEXTRA = lib\nendif\nSUBDIRS = lib $(EXTRA) $(LOOP)\nLOOP = $(SUBDIRS) tools\n"
    result = _drives(text)
    assert [(drive["path"], drive.get("condition")) for drive in result["drives"]] == [("lib", None), ("tools", None)]
    # A reference cycle ends at the variable already being expanded and is recorded.
    assert [item["reason"] for item in result["unresolved"]] == [
        "SUBDIRS references $(SUBDIRS), which has no assignment in this file"]


def test_a_plain_makefile_am_reads_as_before() -> None:
    text = "SUBDIRS = src doc\nbin_PROGRAMS = x\nx_SOURCES = cli.c \\\n\tgtk.c\n"
    result = autotools_build_points(".", {"Makefile.am": text}, ("cli.c", "gtk.c"))
    assert result["drives"] == [{"path": "src", "via": "SUBDIRS", "evidence": "Makefile.am:1"},
                                {"path": "doc", "via": "SUBDIRS", "evidence": "Makefile.am:1"}]
    assert [point for point in result["build_points"] if point["kind"] == "program"] == [
        {"name": "x", "kind": "program", "evidence": "Makefile.am:2", "sources": ["cli.c", "gtk.c"],
         "include_dirs": []}]
    assert result["unresolved"] == []


AI_MODULE_AM = """aimoduledir = $(libdir)/game/ai
if AI_MOD_STATIC_CLASSIC
noinst_LTLIBRARIES = libclassicai.la
else
aimodule_LTLIBRARIES = fc_ai_classic.la
endif

libclassicai_la_SOURCES = classic.c
fc_ai_classic_la_SOURCES = classic.c
"""


def test_custom_prefix_primaries_are_build_points() -> None:
    # Automake product lists are ``<where>_<PRIMARY>`` for any install directory ``<where>dir``
    # (Automake manual, "Uniform Naming Scheme"); the prefix is not a fixed set.
    result = autotools_build_points(".", {"ai/classic/Makefile.am": AI_MODULE_AM}, ("ai/classic/Makefile.am", "ai/classic/classic.c"))
    points = [(p["name"], p["kind"], p.get("condition"), p["sources"]) for p in result["build_points"] if p["kind"] == "libtool_library"]
    assert points == [
        ("libclassicai.la", "libtool_library", "AI_MOD_STATIC_CLASSIC", ["ai/classic/classic.c"]),
        ("fc_ai_classic.la", "libtool_library", "!AI_MOD_STATIC_CLASSIC", ["ai/classic/classic.c"]),
    ]
    assert result["unresolved"] == []
