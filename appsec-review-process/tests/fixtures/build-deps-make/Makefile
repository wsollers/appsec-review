# P36 fixture: a tiny make build with a configure-style generated header, a vendored tree and a system
# library. No bear on the host test path, so the build writes its own compile database.
CC ?= clang
CFLAGS = -O0 -Iinclude -I. -Ithird_party/minijson
OBJS = src/main.o third_party/minijson/minijson.o

all: bin/hello compile_commands.json

config.h:
	printf '#define APP_GREETING "hello"\n' > config.h

src/main.o: src/main.c config.h include/app.h third_party/minijson/minijson.h
	$(CC) $(CFLAGS) -c src/main.c -o src/main.o

third_party/minijson/minijson.o: third_party/minijson/minijson.c third_party/minijson/minijson.h
	$(CC) -Ithird_party/minijson -c third_party/minijson/minijson.c -o third_party/minijson/minijson.o

bin/hello: $(OBJS)
	mkdir -p bin
	$(CC) -o bin/hello $(OBJS) -lz -Wl,-rpath,/opt/fixture/lib

compile_commands.json:
	printf '[{"directory":"%s","file":"%s/src/main.c","arguments":["%s","-O0","-Iinclude","-I.","-Ithird_party/minijson","-c","src/main.c","-o","src/main.o"]},\n {"directory":"%s","file":"%s/third_party/minijson/minijson.c","arguments":["%s","-Ithird_party/minijson","-c","third_party/minijson/minijson.c","-o","third_party/minijson/minijson.o"]}]\n' \
	  "$(CURDIR)" "$(CURDIR)" "$(CC)" "$(CURDIR)" "$(CURDIR)" "$(CC)" > compile_commands.json
