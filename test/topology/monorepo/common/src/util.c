#include "util.h"

size_t util_count_words(const char *text) {
    size_t count = 0;
    int in_word = 0;
    for (; *text != '\0'; ++text) {
        if (*text == ' ' || *text == '\t' || *text == '\n') {
            in_word = 0;
        } else if (!in_word) {
            in_word = 1;
            ++count;
        }
    }
    return count;
}
