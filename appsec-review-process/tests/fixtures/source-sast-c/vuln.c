/* Source-SAST fixture: one call per pattern family (never compiled or run). */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct node { int value; };

int copy_name(char *dst, const char *src) {
    strcpy(dst, src);
    strcat(dst, src);
    return 0;
}

void copy_bytes(char *dst, const char *src, size_t n) {
    memcpy(dst, src, n);
}

void format_arg(char *buffer, int argc, char **argv) {
    sprintf(buffer, argv[1]);
    printf(argv[1]);
}

void format_nonliteral(const char *fmt) {
    printf(fmt);
}

int run_command(const char *cmd) {
    return system(cmd);
}

void read_line(char *line) {
    gets(line);
    scanf("%s", line);
}

int parse(const char *text) {
    char *token = strtok((char *)text, ",");
    return atoi(token);
}

void lifetime(void) {
    struct node *item = malloc(sizeof *item);
    free(item);
    item->value = 1;
    free(item);
}

void clear_secret(char *secret, size_t n) {
    memset(secret, 0, n);
}

void random_bytes(char *out, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, out, n);
}
