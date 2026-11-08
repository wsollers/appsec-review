CC ?= cc
CFLAGS ?= -O2 -Iinclude

all: libzlibish.a zpipe

libzlibish.a: src/inflate.c src/deflate.c
	$(CC) $(CFLAGS) -c src/inflate.c -o inflate.o
	$(CC) $(CFLAGS) -c src/deflate.c -o deflate.o
	$(AR) rcs $@ inflate.o deflate.o

zpipe: src/zpipe.c libzlibish.a
	$(CC) $(CFLAGS) src/zpipe.c libzlibish.a -o $@

clean:
	rm -f *.o libzlibish.a zpipe
