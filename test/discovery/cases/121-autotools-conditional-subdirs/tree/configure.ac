AC_INIT([game], [1.0])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
AM_CONDITIONAL([SERVER], [test "$enable_server" = yes])
AM_CONDITIONAL([MAKE_DATA], [test "$enable_data" = yes])
AM_CONDITIONAL([GUI_GTK], [test "$gui" = gtk])
AM_CONDITIONAL([GUI_SDL], [test "$gui" = sdl])
AM_CONDITIONAL([CLI], [test "$enable_cli" = yes])
AC_CONFIG_FILES([Makefile common/Makefile server/Makefile client/Makefile client/gui-gtk/Makefile client/gui-sdl/Makefile data/Makefile])
AC_OUTPUT
