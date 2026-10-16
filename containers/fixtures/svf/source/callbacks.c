/* Callback table dispatched through a struct field: the call in dispatch() is indirect. */
#include <string.h>

typedef int (*handler_fn)(char *buffer, const char *input);

static int copy_handler(char *buffer, const char *input) { strcpy(buffer, input); return 1; }
static int length_handler(char *buffer, const char *input) { (void)buffer; return (int)strlen(input); }
static int unused_handler(char *buffer, const char *input) { (void)buffer; (void)input; return 0; }

struct command { const char *name; handler_fn handler; };

static struct command commands[] = {
    {"copy", copy_handler},
    {"length", length_handler},
};

int dispatch(int index, char *buffer, const char *input) {
    return commands[index].handler(buffer, input);
}

int unrelated(void) { return unused_handler(0, 0); }
