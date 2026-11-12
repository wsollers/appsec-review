"""Meson build points: what the build produces, not what it looks up (Freeciv walk, 2026-11-11)."""
from __future__ import annotations

from appsec_review.jobs.build_points import meson_build_points

MESON = """project('game', 'c')
c_compiler = meson.get_compiler('c')
z_dep = c_compiler.find_library('z', required: false)
charset_dep = c_compiler.find_library('charset', dirs: cross_lib_path,
                                      required: false)
if get_option('web')
  server_binary_name = 'game-web'
else
  server_binary_name = 'game-server'
endif
common_lib = library('game',
  'common/map.c',
  'common/unit.c',
  dependencies: z_dep
  )
server_lib = static_library('game_server', 'server/srv_main.c')
executable(server_binary_name,
  'server/civserver.c',
  link_with: [server_lib, common_lib],
  install: true
  )
executable('game-client', 'client/main.c', link_with: common_lib)
executable(unassigned_name, 'tools/tool.c')
"""
INVENTORY = ("common/map.c", "common/unit.c", "server/srv_main.c", "server/civserver.c", "client/main.c",
             "tools/tool.c", "meson.build")


def _points():
    return meson_build_points(".", {"meson.build": MESON}, INVENTORY)


def test_dependency_lookups_are_not_build_points() -> None:
    names = {point["name"]: point["kind"] for point in _points()["build_points"]}
    assert "z" not in names and "charset" not in names
    assert names == {"game": "library", "game_server": "static_library", "server_binary_name": "executable",
                     "game-client": "executable", "unassigned_name": "executable"}


def test_a_target_named_by_a_variable_is_a_build_point_with_its_sources_and_a_recorded_name() -> None:
    result = _points()
    by_name = {point["name"]: point for point in result["build_points"]}
    server = by_name["server_binary_name"]
    assert server["kind"] == "executable" and server["sources"] == ["server/civserver.c"]
    assert server["evidence"] == "meson.build:17"
    assert by_name["game"]["sources"] == ["common/map.c", "common/unit.c"]
    assert by_name["game-client"]["sources"] == ["client/main.c"]
    assert result["unresolved"] == [
        {"evidence": "meson.build:17", "kind": "variable_target_name",
         "reason": "target name is the variable server_binary_name (literal values in this file: "
                   "game-server, game-web)"},
        {"evidence": "meson.build:23", "kind": "variable_target_name",
         "reason": "target name is the variable unassigned_name (no literal value in this file)"}]
