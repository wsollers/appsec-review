PLATFORM ?= linux
include $(PLATFORM).mk

main.o: main.c tool.h
	$(CC) $(CFLAGS) -c main.c -o main.o

ifeq ($(OS),Windows_NT)
tool.exe: main.o os_win.c
	$(CC) $(CFLAGS) main.o os_win.c -o tool.exe $(LDLIBS)
else
tool: main.o os_posix.c
	$(CC) $(CFLAGS) main.o os_posix.c -o tool $(LDLIBS)
endif

clean:
	rm -f main.o tool tool.exe
