CC ?= gcc
CFLAGS ?= -O2 -I../../common/include

all: packer

packer: main.c ../../common/src/util.c ../../common/include/util.h
	$(CC) $(CFLAGS) -o packer main.c ../../common/src/util.c

clean:
	rm -f packer

.PHONY: all clean
