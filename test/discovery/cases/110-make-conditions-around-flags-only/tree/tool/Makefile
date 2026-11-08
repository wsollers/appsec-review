include common.mk

ifeq ($(OS),Windows_NT)
  CFLAGS += -DWIN32_LEAN_AND_MEAN
  EXEEXT = .exe
else
  CFLAGS += -D_GNU_SOURCE
  EXEEXT =
endif

all: tool$(EXEEXT)

tool$(EXEEXT): main.c util.c
	$(CC) $(CFLAGS) main.c util.c -o $@
	@echo "built for $(OS)Windows_NT-or-not"

clean:
	rm -f tool tool.exe

.PHONY: all clean
