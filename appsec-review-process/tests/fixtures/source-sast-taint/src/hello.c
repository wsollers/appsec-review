/* Taint-rule fixture (P13): each TAINT line is an intraprocedural source->sink flow an
 * appsec.c.taint.* rule must report; each SAFE line is a constant or sanitized flow it must not. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static void greet(const char *name) {
    char out[64];
    sprintf(out, "hello %s", name);        /* SAFE intraprocedural: name is a parameter, not a source */
    puts(out);
}

int main(int argc, char **argv) {
    char buf[128], line[256], cmd[512], net[64], id[32];
    const char *home = getenv("HOME");
    int count;

    printf(argv[1]);                       /* TAINT format-string: argv */
    strcpy(buf, argv[1]);                  /* TAINT unsafe-copy: argv */
    strcat(cmd, home);                     /* TAINT unsafe-copy: getenv */
    if (fgets(line, sizeof line, stdin) != NULL) {
        system(line);                      /* TAINT command-execution: fgets */
        fprintf(stderr, line);             /* TAINT format-string: fgets */
    }
    snprintf(cmd, sizeof cmd, "ls %s", getenv("PWD"));
    popen(cmd, "r");                       /* TAINT command-execution: getenv via snprintf */
    recv(0, net, sizeof net, 0);
    memcpy(buf, net, net[0]);              /* TAINT memory-copy length: recv */
    if (scanf("%d", &count) == 1)
        memcpy(buf, line, count);          /* TAINT memory-copy length: scanf */
    execl("/bin/sh", "sh", "-c", argv[2], (char *)NULL);  /* TAINT command-execution: argv */
    sprintf(id, "id -u %d", atoi(argv[3]));
    system(id);                            /* SAFE: atoi yields a number, not command text */
    printf("%s\n", argv[1]);               /* SAFE: literal format */
    system("/bin/true");                   /* SAFE: constant command */
    memcpy(buf, line, sizeof buf);         /* SAFE: constant length */
    greet(argv[1]);
    return 0;
}
