include config.mk

all: packer libpack.a

libpack.a: pack.o
	$(AR) rcs $@ $^

packer: main.o libpack.a
	$(CC) $(CFLAGS) -o $@ main.o libpack.a

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o packer libpack.a

.PHONY: all clean
