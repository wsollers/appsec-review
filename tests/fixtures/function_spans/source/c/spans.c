#include <string.h>

static int counter = 0; /* ANCHOR:none */

struct item {
    int size;
};

static int helper(int value) { /* BEGIN:helper */
    int doubled = value * 2; /* ANCHOR:helper */
    if (doubled > 10) {
        return doubled;
    }
    return value; /* ANCHOR:helper */
} /* END:helper */

int parse_item(const char *input, struct item *out) /* BEGIN:parse_item */
{
    char buffer[16];
    const char *brace = "}"; /* a brace in a string literal */
    strcpy(buffer, input); /* ANCHOR:parse_item */
    out->size = helper((int)strlen(buffer)); /* ANCHOR:parse_item */
    counter += brace[0];
    return 0;
} /* END:parse_item */
