#define main caged_program_main
#include "../../caged.c"
#undef main
#include "fake_syscalls.h"
#include <assert.h>
#include <errno.h>

/* Redirects stdout, runs print_help() and copies the captured text. */
static void capture_help(char *buf, size_t size) {
  int pipefd[2];
  assert(pipe(pipefd) == 0);

  fflush(stdout);
  int saved = dup(STDOUT_FILENO);
  assert(saved >= 0);
  assert(dup2(pipefd[1], STDOUT_FILENO) >= 0);
  close(pipefd[1]);

  print_help();

  fflush(stdout);
  assert(dup2(saved, STDOUT_FILENO) >= 0);
  close(saved);

  ssize_t n = read(pipefd[0], buf, size - 1);
  if (n < 0) {
    n = 0;
  }
  buf[n] = '\0';
  close(pipefd[0]);
}

/* the help lists the usage line and every option group */
void test_print_help(void) {
  char buf[4096];
  capture_help(buf, sizeof buf);

  assert(strstr(buf, "usage: caged") != NULL);
  assert(strstr(buf, "--ro PATH") != NULL);
  assert(strstr(buf, "--rw PATH") != NULL);
  assert(strstr(buf, "--allow-connect-port") != NULL);
  assert(strstr(buf, "--allow-bind-port") != NULL);
  assert(strstr(buf, "--allow-connect-tcp") != NULL);
  assert(strstr(buf, "--allow-bind-tcp") != NULL);
  assert(strstr(buf, "--allow-scoped-signal") != NULL);
  assert(strstr(buf, "--allow-scoped-abstract-unix") != NULL);
  assert(strstr(buf, "--log-same-exec-off") != NULL);
  assert(strstr(buf, "--log-new-exec-on") != NULL);
  assert(strstr(buf, "--log-subdomains-off") != NULL);
  assert(strstr(buf, "--tsync") != NULL);
  assert(strstr(buf, "--help") != NULL);
  assert(strstr(buf, "CAGED_DISABLE_WARNINGS") != NULL);
}

/* --help sets the help flag and stops parsing successfully */
void test_parse_help_long(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--help", NULL};

  assert(parse_cmd_line(2, argv, &opts) == 0);
  assert(opts.help == 1);

  cmd_opts_free(&opts);
}

/* -h is an alias for --help */
void test_parse_help_short(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "-h", NULL};

  assert(parse_cmd_line(2, argv, &opts) == 0);
  assert(opts.help == 1);

  cmd_opts_free(&opts);
}

int main(void) {
  test_print_help();
  test_parse_help_long();
  test_parse_help_short();

  printf("OK\n");
  return 0;
}
