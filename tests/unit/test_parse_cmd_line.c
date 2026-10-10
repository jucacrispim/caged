#define main caged_program_main
#include "../../caged.c"
#undef main
#include "fake_syscalls.h"
#include <assert.h>

void test_ro_only_one_value(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--ro", "/usr", "--", "cat", NULL};

  assert(parse_cmd_line(5, argv, &opts) == 0);
  assert(opts.n_r == 1);
  assert(opts.n_rw == 0);
  assert(strcmp(opts.r_dir[0], "/usr") == 0);
  assert(strcmp(opts.cmd[0], "cat") == 0);
}

void test_rw_only_one_value(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--rw", "/tmp/x", "--", "sh", NULL};

  assert(parse_cmd_line(5, argv, &opts) == 0);
  assert(opts.n_r == 0);
  assert(opts.n_rw == 1);
  assert(strcmp(opts.rw_dir[0], "/tmp/x") == 0);
  assert(strcmp(opts.cmd[0], "sh") == 0);
}

void test_rw_ro_multiple_values(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--ro", "/a", "--rw", "/b",  "--ro",
                  "/c",    "--rw", "/d", "--",   "cmd", NULL};

  assert(parse_cmd_line(15, argv, &opts) == 0);
  assert(opts.n_r == 2);
  assert(opts.n_rw == 2);
  assert(strcmp(opts.r_dir[0], "/a") == 0);
  assert(strcmp(opts.r_dir[1], "/c") == 0);
  assert(strcmp(opts.rw_dir[0], "/b") == 0);
  assert(strcmp(opts.rw_dir[1], "/d") == 0);
  assert(strcmp(opts.cmd[0], "cmd") == 0);
}

void test_only_command_opt(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--", "/usr/bin/ls", "-la", NULL};

  assert(parse_cmd_line(5, argv, &opts) == 0);
  assert(opts.n_r == 0);
  assert(strcmp(opts.cmd[0], "/usr/bin/ls") == 0);
  assert(strcmp(opts.cmd[1], "-la") == 0);
}

void test_missing_params_error(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", NULL};

  assert(parse_cmd_line(1, argv, &opts) < 0);
}

void test_missing_ro_value_error(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--ro", NULL};

  assert(parse_cmd_line(2, argv, &opts) < 0);
}

void test_missing_rw_value_error(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--rw", NULL};

  assert(parse_cmd_line(2, argv, &opts) < 0);
}

void test_bad_param_error(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--bogus", NULL};

  assert(parse_cmd_line(2, argv, &opts) < 0);
}

void test_sem_missing_command_error(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--ro", "/usr", NULL};

  assert(parse_cmd_line(3, argv, &opts) < 0);
}

void test_separator_missing_command_error(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--", NULL};

  assert(parse_cmd_line(2, argv, &opts) < 0);
}

void test_ro_too_many(void) {
  struct cmd_opts opts = {0};
  char *argv[2 * (MAX_PATHS + 1) + 2];
  int i = 1;
  argv[0] = "caged";
  for (int k = 0; k < MAX_PATHS + 1; k++) {
    argv[i++] = "--ro";
    argv[i++] = "/x";
  }
  argv[i] = NULL;

  assert(parse_cmd_line(i, argv, &opts) < 0);
}

void test_rw_too_many(void) {
  struct cmd_opts opts = {0};
  char *argv[2 * (MAX_PATHS + 1) + 2];
  int i = 1;
  argv[0] = "caged";
  for (int k = 0; k < MAX_PATHS + 1; k++) {
    argv[i++] = "--rw";
    argv[i++] = "/x";
  }
  argv[i] = NULL;

  assert(parse_cmd_line(i, argv, &opts) < 0);
}

int main(void) {
  test_ro_only_one_value();
  test_rw_only_one_value();
  test_rw_ro_multiple_values();
  test_only_command_opt();
  test_missing_params_error();
  test_missing_ro_value_error();
  test_missing_rw_value_error();
  test_bad_param_error();
  test_sem_missing_command_error();
  test_separator_missing_command_error();
  test_ro_too_many();
  test_rw_too_many();

  printf("OK\n");
  return 0;
}
