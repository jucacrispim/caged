/*
  Copyright 2026 Juca Crispim <juca@poraodojuca.dev>

  This file is part of caged.

  caged is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  caged is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with caged. If not, see <http://www.gnu.org/licenses/>.
*/

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

/* --allow-connect-tcp releases the whole connect access */
void test_allow_connect_tcp(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-connect-tcp", "--", "true", NULL};

  assert(parse_cmd_line(4, argv, &opts) == 0);
  assert(opts.released_net == LANDLOCK_ACCESS_NET_CONNECT_TCP);

  cmd_opts_free(&opts);
}

/* --allow-bind-tcp releases the whole bind access */
void test_allow_bind_tcp(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-bind-tcp", "--", "true", NULL};

  assert(parse_cmd_line(4, argv, &opts) == 0);
  assert(opts.released_net == LANDLOCK_ACCESS_NET_BIND_TCP);

  cmd_opts_free(&opts);
}

/* --allow-connect-port accumulates ports, order preserved */
void test_allow_connect_port(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged",           "--allow-connect-port", "443",
                  "--allow-connect-port", "80", "--", "true", NULL};

  assert(parse_cmd_line(9, argv, &opts) == 0);
  assert(opts.n_connect == 2);
  assert(opts.connect_ports[0] == 443);
  assert(opts.connect_ports[1] == 80);
  assert(opts.released_net == 0);

  cmd_opts_free(&opts);
}

/* --allow-bind-port accepts port 0 (ephemeral range) */
void test_allow_bind_port(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-bind-port", "0", "--", "true", NULL};

  assert(parse_cmd_line(5, argv, &opts) == 0);
  assert(opts.n_bind == 1);
  assert(opts.bind_ports[0] == 0);

  cmd_opts_free(&opts);
}

/* net flags mix with path options */
void test_allow_net_combined(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged",
                  "--allow-connect-port",
                  "443",
                  "--ro",
                  "/usr",
                  "--allow-bind-port",
                  "80",
                  "--",
                  "true",
                  NULL};

  assert(parse_cmd_line(10, argv, &opts) == 0);
  assert(opts.n_connect == 1);
  assert(opts.n_bind == 1);
  assert(opts.n_r == 1);
  assert(strcmp(opts.r_dir[0], "/usr") == 0);

  cmd_opts_free(&opts);
}

void test_allow_connect_port_missing_value(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-connect-port", NULL};

  assert(parse_cmd_line(2, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

void test_allow_bind_port_missing_value(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-bind-port", NULL};

  assert(parse_cmd_line(2, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

void test_allow_connect_port_invalid(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-connect-port", "abc", "--", "true", NULL};

  assert(parse_cmd_line(5, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

void test_allow_bind_port_invalid(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-bind-port", "70000", "--", "true", NULL};

  assert(parse_cmd_line(5, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

/* general flag then port flag for the same direction -> usage error */
void test_allow_connect_conflict(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged",     "--allow-connect-tcp", "--allow-connect-port",
                  "443", "--", "true", NULL};

  assert(parse_cmd_line(7, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

/* port flag then general flag for the same direction -> usage error */
void test_allow_connect_conflict_reverse(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged",     "--allow-connect-port", "443",
                  "--allow-connect-tcp", "--", "true", NULL};

  assert(parse_cmd_line(7, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

/* same conflict for bind */
void test_allow_bind_conflict(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged",     "--allow-bind-tcp", "--allow-bind-port",
                  "80", "--", "true", NULL};

  assert(parse_cmd_line(7, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

void test_allow_bind_conflict_reverse(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged",     "--allow-bind-port", "80",
                  "--allow-bind-tcp", "--", "true", NULL};

  assert(parse_cmd_line(7, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

/* allocation failure while growing the connect ports list -> error */
void test_connect_port_out_of_memory(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-connect-port", "443", "--", "true", NULL};

  reset_fake();
  fake.fail_realloc = 1;
  fake.realloc_err = ENOMEM;

  errno = 0;
  assert(parse_cmd_line(5, argv, &opts) < 0);
  assert(opts.n_connect == 0);
  assert(errno == ENOMEM);

  cmd_opts_free(&opts);
}

/* allocation failure while growing the bind ports list -> error */
void test_bind_port_out_of_memory(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-bind-port", "80", "--", "true", NULL};

  reset_fake();
  fake.fail_realloc = 1;
  fake.realloc_err = ENOMEM;

  errno = 0;
  assert(parse_cmd_line(5, argv, &opts) < 0);
  assert(opts.n_bind == 0);
  assert(errno == ENOMEM);

  cmd_opts_free(&opts);
}

/* --allow-unix-sockets releases the AF_UNIX ban */
void test_allow_unix_sockets(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-unix-sockets", "--", "true", NULL};

  assert(parse_cmd_line(4, argv, &opts) == 0);
  assert(opts.allow_unix_sockets == 1);
  assert(opts.allow_network_sockets == 0);

  cmd_opts_free(&opts);
}

/* --allow-network-sockets releases AF_INET, AF_INET6 and AF_NETLINK */
void test_allow_network_sockets(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-network-sockets", "--", "true", NULL};

  assert(parse_cmd_line(4, argv, &opts) == 0);
  assert(opts.allow_unix_sockets == 0);
  assert(opts.allow_network_sockets == 1);

  cmd_opts_free(&opts);
}

/* --max-procs sets the process limit */
void test_max_procs(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--max-procs", "64", "--", "true", NULL};

  assert(parse_cmd_line(5, argv, &opts) == 0);
  assert(opts.max_procs == 64);

  cmd_opts_free(&opts);
}

/* --max-procs without a value is a usage error */
void test_max_procs_missing_value(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--max-procs", NULL};

  assert(parse_cmd_line(2, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

/* a non-numeric value is a usage error */
void test_max_procs_invalid(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--max-procs", "abc", "--", "true", NULL};

  assert(parse_cmd_line(5, argv, &opts) < 0);
  assert(opts.max_procs == 0);

  cmd_opts_free(&opts);
}

/* zero is not a process limit */
void test_max_procs_zero(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--max-procs", "0", "--", "true", NULL};

  assert(parse_cmd_line(5, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

/* negative values are not a process limit */
void test_max_procs_negative(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--max-procs", "-1", "--", "true", NULL};

  assert(parse_cmd_line(5, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

/* trailing garbage after the digits is a usage error */
void test_max_procs_trailing_garbage(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--max-procs", "12abc", "--", "true", NULL};

  assert(parse_cmd_line(5, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

/* a value that overflows a long is a usage error */
void test_max_procs_overflow(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--max-procs", "99999999999999999999", "--", "true",
                  NULL};

  assert(parse_cmd_line(5, argv, &opts) < 0);

  cmd_opts_free(&opts);
}

/* --allow-sysv-ipc releases the SysV IPC ban */
void test_allow_sysv_ipc(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--allow-sysv-ipc", "--", "true", NULL};

  assert(parse_cmd_line(4, argv, &opts) == 0);
  assert(opts.allow_sysv_ipc == 1);
  assert(opts.allow_unix_sockets == 0);
  assert(opts.allow_network_sockets == 0);

  cmd_opts_free(&opts);
}

/* both socket flags combine with the path options, order preserved */
void test_allow_sockets_combined(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged",     "--allow-unix-sockets", "--ro",
                  "/usr",      "--allow-network-sockets", "--allow-connect-port",
                  "443",       "--", "true", NULL};

  assert(parse_cmd_line(9, argv, &opts) == 0);
  assert(opts.allow_unix_sockets == 1);
  assert(opts.allow_network_sockets == 1);
  assert(opts.n_r == 1);
  assert(strcmp(opts.r_dir[0], "/usr") == 0);
  assert(opts.n_connect == 1);
  assert(opts.connect_ports[0] == 443);

  cmd_opts_free(&opts);
}

/* the restrict-self flags are boolean and accumulate */
void test_restrict_flags(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged",
                  "--log-same-exec-off",
                  "--log-new-exec-on",
                  "--log-subdomains-off",
                  "--tsync",
                  "--",
                  "true",
                  NULL};

  assert(parse_cmd_line(8, argv, &opts) == 0);
  assert(opts.restrict_flags ==
         (LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF |
          LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON |
          LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF |
          LANDLOCK_RESTRICT_SELF_TSYNC));

  cmd_opts_free(&opts);
}

/* a restrict flag mixes with path options, order preserved */
void test_restrict_flags_with_ro(void) {
  struct cmd_opts opts = {0};
  char *argv[] = {"caged", "--ro", "/usr", "--tsync", "--", "true", NULL};

  reset_fake();
  assert(parse_cmd_line(6, argv, &opts) == 0);
  assert(opts.n_r == 1);
  assert(strcmp(opts.r_dir[0], "/usr") == 0);
  assert(opts.restrict_flags == LANDLOCK_RESTRICT_SELF_TSYNC);

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
  test_allow_connect_tcp();
  test_allow_bind_tcp();
  test_allow_connect_port();
  test_allow_bind_port();
  test_allow_net_combined();
  test_allow_connect_port_missing_value();
  test_allow_bind_port_missing_value();
  test_allow_connect_port_invalid();
  test_allow_bind_port_invalid();
  test_allow_connect_conflict();
  test_allow_connect_conflict_reverse();
  test_allow_bind_conflict();
  test_allow_bind_conflict_reverse();
  test_connect_port_out_of_memory();
  test_bind_port_out_of_memory();
  test_restrict_flags();
  test_restrict_flags_with_ro();
  test_allow_unix_sockets();
  test_allow_network_sockets();
  test_allow_sysv_ipc();
  test_allow_sockets_combined();
  test_max_procs();
  test_max_procs_missing_value();
  test_max_procs_invalid();
  test_max_procs_zero();
  test_max_procs_negative();
  test_max_procs_trailing_garbage();
  test_max_procs_overflow();

  printf("OK\n");
  return 0;
}
