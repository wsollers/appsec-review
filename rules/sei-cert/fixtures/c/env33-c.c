/* SEI CERT ENV33-C focused fixture. Annotations bind to the next code line. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define RUN_SHELL(command) system(command)

int run_report(const char *name) {
  char command[256];
  snprintf(command, sizeof command, "report %s", name);
  // cert: positive appsec-review.sei-cert.c.env33-c.command-processor-call
  return system(command);
}

FILE *open_listing(const char *path) {
  // cert: variant appsec-review.sei-cert.c.env33-c.command-processor-call
  return popen(path, "r");
}

int macro_wrapped(const char *command) {
  // cert: known-false-negative appsec-review.sei-cert.c.env33-c.command-processor-call
  return RUN_SHELL(command);
}

int shell_exec(const char *script) {
  // cert: positive appsec-review.sei-cert.c.env33-c.exec-shell-command-string
  return execl("/bin/sh", "sh", "-c", script, (char *)0);
}

int shell_exec_path(const char *script) {
  // cert: variant appsec-review.sei-cert.c.env33-c.exec-shell-command-string
  return execlp("bash", "bash", "-c", script, (char *)0);
}

int has_command_processor(void) {
  // cert: exception:ENV33-C-EX1 appsec-review.sei-cert.c.env33-c.command-processor-call
  return system(NULL) != 0;
}

int has_command_processor_zero(void) {
  // cert: exception:ENV33-C-EX1 appsec-review.sei-cert.c.env33-c.command-processor-call
  return system(0) != 0;
}

int direct_exec(const char *path) {
  // cert: safe-alternative appsec-review.sei-cert.c.env33-c.exec-shell-command-string
  return execl("/usr/bin/report", "report", path, (char *)0);
}

int system_info(void) {
  // cert: near-miss appsec-review.sei-cert.c.env33-c.command-processor-call
  return sysconf(_SC_NPROCESSORS_ONLN) > 0;
}

int shell_without_command(void) {
  // cert: near-miss appsec-review.sei-cert.c.env33-c.exec-shell-command-string
  return execl("/bin/sh", "sh", "-n", "/etc/profile", (char *)0);
}

int declared_only(const char *);
int my_system(const char *command);
int wrapper(const char *command) {
  // cert: negative appsec-review.sei-cert.c.env33-c.command-processor-call
  return my_system(command);
}
