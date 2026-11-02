#include <stdio.h>
#include <string.h>

/* vulnerable: CWE-22 toy sample
   the comment spans two lines */
int main(int argc, char **argv) {
    const char *url = "http://example.invalid/a//b"; // CWE-22 here
    char slash = '/';
    printf("%s %c\n", url, slash); /* inline */ printf("/* not a comment */\n");
    // continued comment \
    still the comment: exploit
    return argc > 5 ? (int)strlen(argv[0]) : 0;
}
