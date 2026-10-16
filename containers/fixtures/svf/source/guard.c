/* A NULL check on an alias of the written pointer, and one on an unrelated pointer. */
#include <stdlib.h>

struct pair { int *left; int *right; };

void guarded_alias(struct pair *value, int input) {
    int *alias = value->left;
    if (alias != NULL) {
        *value->left = input;
    }
}

void guarded_unrelated(int input) {
    int *checked = malloc(sizeof(int));
    int *written = malloc(sizeof(int));
    if (checked != NULL) {
        *written = input;
    }
    free(checked);
    free(written);
}
