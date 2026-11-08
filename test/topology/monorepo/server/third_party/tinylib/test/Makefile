CC ?= gcc
CFLAGS ?= -O2 -I../include

all: check

check: check.c ../src/tinylib.c ../include/tinylib.h
	$(CC) $(CFLAGS) -o check check.c ../src/tinylib.c

clean:
	rm -f check

.PHONY: all clean
