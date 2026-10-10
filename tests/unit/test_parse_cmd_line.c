#define main caged_program_main
#include "../../caged.c"
#undef main
#include "fake_syscalls.h"
#include <assert.h>
#include <errno.h>

void test_ro_only_one_value(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--ro", "/usr", "--", "cat", NULL};

  assert(parse_cmd_line(5, argv, &opts) == 0);
  assert(opts.n_r == 1);
  assert(opts.n_rw == 0);
  assert(strcmp(opts.r_dir[0], "/usr") == 0);
  assert(strcmp(opts.cmd[0], "cat") == 0);

  cmd_opts_free(&opts);
}

void test_rw_only_one_value(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--rw", "/tmp/x", "--", "sh", NULL};

  assert(parse_cmd_line(5, argv, &opts) == 0);
  assert(opts.n_r == 0);
  assert(opts.n_rw == 1);
  assert(strcmp(opts.rw_dir[0], "/tmp/x") == 0);
  assert(strcmp(opts.cmd[0], "sh") == 0);

  cmd_opts_free(&opts);
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

  cmd_opts_free(&opts);
}

void test_only_command_opt(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--", "/usr/bin/ls", "-la", NULL};

  assert(parse_cmd_line(5, argv, &opts) == 0);
  assert(opts.n_r == 0);
  assert(strcmp(opts.cmd[0], "/usr/bin/ls") == 0);
  assert(strcmp(opts.cmd[1], "-la") == 0);

  cmd_opts_free(&opts);
}

void test_missing_params_error(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", NULL};

  assert(parse_cmd_line(1, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

void test_missing_ro_value_error(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--ro", NULL};

  assert(parse_cmd_line(2, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

void test_missing_rw_value_error(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--rw", NULL};

  assert(parse_cmd_line(2, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

void test_bad_param_error(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--bogus", NULL};

  assert(parse_cmd_line(2, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

void test_sem_missing_command_error(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--ro", "/usr", NULL};

  assert(parse_cmd_line(3, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

void test_separator_missing_command_error(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--", NULL};

  assert(parse_cmd_line(2, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

/* many --ro values: no fixed upper limit, order is preserved */
void test_many_ro_values(void) {
  struct cmd_opts opts = {0};
  char *argv[2 * 100 + 3];
  int i = 1;
  argv[0] = "caged";
  for (int k = 0; k < 100; k++) {
    argv[i++] = "--ro";
    argv[i++] = "/x";
  }
  argv[i++] = "--";
  argv[i++] = "true";
  argv[i] = NULL;

  assert(parse_cmd_line(i, argv, &opts) == 0);
  assert(opts.n_r == 100);
  assert(strcmp(opts.r_dir[0], "/x") == 0);
  assert(strcmp(opts.r_dir[99], "/x") == 0);
  assert(strcmp(opts.cmd[0], "true") == 0);

  cmd_opts_free(&opts);
}

/* many --rw values: no fixed upper limit, order is preserved */
void test_many_rw_values(void) {
  struct cmd_opts opts = {0};
  char *argv[2 * 100 + 3];
  int i = 1;
  argv[0] = "caged";
  for (int k = 0; k < 100; k++) {
    argv[i++] = "--rw";
    argv[i++] = "/y";
  }
  argv[i++] = "--";
  argv[i++] = "true";
  argv[i] = NULL;

  assert(parse_cmd_line(i, argv, &opts) == 0);
  assert(opts.n_rw == 100);
  assert(strcmp(opts.rw_dir[0], "/y") == 0);
  assert(strcmp(opts.rw_dir[99], "/y") == 0);
  assert(strcmp(opts.cmd[0], "true") == 0);

  cmd_opts_free(&opts);
}

/* allocation failure while growing the --ro list -> error */
void test_ro_out_of_memory(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--ro", "/usr", "--", "cat", NULL};

  reset_fake();
  fake.fail_realloc = 1;
  fake.realloc_err = ENOMEM;

  errno = 0;
  assert(parse_cmd_line(5, argv, &opts) < 0);
  assert(opts.n_r == 0);
  assert(errno == ENOMEM);

  cmd_opts_free(&opts);
}

/* allocation failure while growing the --rw list -> error */
void test_rw_out_of_memory(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--rw", "/tmp/x", "--", "sh", NULL};

  reset_fake();
  fake.fail_realloc = 1;
  fake.realloc_err = ENOMEM;

  errno = 0;
  assert(parse_cmd_line(5, argv, &opts) < 0);
  assert(opts.n_rw == 0);
  assert(errno == ENOMEM);

  cmd_opts_free(&opts);
}

/* --allow-scoped-signal releases the signal scope */
void test_allow_scoped_signal(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-scoped-signal", "--", "true", NULL};

  reset_fake();
  assert(parse_cmd_line(4, argv, &opts) == 0);
  assert(opts.released_scopes == LANDLOCK_SCOPE_SIGNAL);

  cmd_opts_free(&opts);
}

/* --allow-scoped-abstract-unix releases the abstract unix scope */
void test_allow_scoped_abstract_unix(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-scoped-abstract-unix", "--", "true", NULL};

  reset_fake();
  assert(parse_cmd_line(4, argv, &opts) == 0);
  assert(opts.released_scopes == LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET);

  cmd_opts_free(&opts);
}

/* both scope flags combine, mixed with the path options */
void test_allow_scoped_combined(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-scoped-abstract-unix", "--ro", "/usr",
                  "--allow-scoped-signal", "--", "true", NULL};

  reset_fake();
  assert(parse_cmd_line(7, argv, &opts) == 0);
  assert(opts.n_r == 1);
  assert(strcmp(opts.r_dir[0], "/usr") == 0);
  assert(opts.released_scopes ==
         (LANDLOCK_SCOPE_SIGNAL | LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET));

  cmd_opts_free(&opts);
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
  test_many_ro_values();
  test_many_rw_values();
  test_ro_out_of_memory();
  test_rw_out_of_memory();
  test_allow_scoped_signal();
  test_allow_scoped_abstract_unix();
  test_allow_scoped_combined();

  printf("OK\n");
  return 0;
}
