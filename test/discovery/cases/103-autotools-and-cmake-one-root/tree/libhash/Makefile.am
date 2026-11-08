ACLOCAL_AMFLAGS = -I m4
lib_LIBRARIES = libhash.a
libhash_a_SOURCES = src/hash.c src/hash.h
bin_PROGRAMS = hashsum
hashsum_SOURCES = src/hashsum.c
hashsum_LDADD = libhash.a
