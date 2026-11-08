CC ?= gcc
CFLAGS ?= -O2 -Iinclude

all: libtinylib.a

libtinylib.a: tinylib.o
	ar rcs libtinylib.a tinylib.o

tinylib.o: src/tinylib.c include/tinylib.h
	$(CC) $(CFLAGS) -c src/tinylib.c -o tinylib.o

clean:
	rm -f tinylib.o libtinylib.a

.PHONY: all clean
