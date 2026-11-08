SUBDIRS = src
all-local: third_party/zlite/build/libzlite.a
third_party/zlite/build/libzlite.a:
	cmake -S $(top_srcdir)/third_party/zlite -B $(top_builddir)/third_party/zlite/build && cmake --build $(top_builddir)/third_party/zlite/build
