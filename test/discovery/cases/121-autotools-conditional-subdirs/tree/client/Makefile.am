GUI_SUBDIRS =
if GUI_GTK
GUI_SUBDIRS += gui-gtk
endif
if GUI_SDL
GUI_SUBDIRS += gui-sdl
endif
SUBDIRS = $(GUI_SUBDIRS)

bin_PROGRAMS =
if CLI
bin_PROGRAMS += game-cli
endif
cli_sources = cli.c
game_cli_SOURCES = $(cli_sources)
