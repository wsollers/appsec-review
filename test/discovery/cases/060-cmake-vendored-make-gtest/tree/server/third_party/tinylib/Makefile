CC ?= cc
CFLAGS += -Iinclude

libtiny.a: src/tiny.c
	$(CC) $(CFLAGS) -c src/tiny.c -o tiny.o
	$(AR) rcs libtiny.a tiny.o

check: libtiny.a
	$(MAKE) -C test check

clean:
	rm -f tiny.o libtiny.a
