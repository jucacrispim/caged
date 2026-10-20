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

void test_setup_ok(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.stat_ret = 0;
  fake.isdir_ret = 1;
  fake.add_rule_ret = 0;
  fake.prctl_ret = 0;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};
  push_path(&opts.r_dir, &opts.n_r, &opts.cap_r, "/usr");
  push_path(&opts.r_dir, &opts.n_r, &opts.cap_r, "/etc");
  push_path(&opts.rw_dir, &opts.n_rw, &opts.cap_rw, "/tmp/x");

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.create_calls_count == 1);
  assert(fake.add_calls_count == 3);
  assert(fake.restrict_calls_count == 1);
  /* scopes are restricted by default */
  assert(fake.last_scoped == SCOPED);
  /* net is handled (and thus denied) by default */
  assert(fake.last_handled_net == NET_HANDLED);
  /* no restrict-self flags are passed by default */
  assert(fake.last_restrict_flags == 0);

  cmd_opts_free(&opts);
}

/* releasing the whole connect access clears its bit from the handled mask */
void test_setup_released_net_general(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};
  opts.released_net = LANDLOCK_ACCESS_NET_CONNECT_TCP;

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.last_handled_net ==
         ((unsigned long)NET_HANDLED & ~LANDLOCK_ACCESS_NET_CONNECT_TCP));
}

/* --allow-*-port adds a rule per port */
void test_setup_net_port_rules(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.add_rule_ret = 0;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};
  push_port(&opts.connect_ports, &opts.n_connect, &opts.cap_connect, 443);
  push_port(&opts.bind_ports, &opts.n_bind, &opts.cap_bind, 80);

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.add_calls_count == 2);
  /* net stays governed when only individual ports are granted */
  assert(fake.last_handled_net == NET_HANDLED);
  /* last rule is the bind one */
  assert(fake.last_net_allowed_access == LANDLOCK_ACCESS_NET_BIND_TCP);
  assert(fake.last_net_port == 80);

  cmd_opts_free(&opts);
}

void test_setup_connect_rule_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.add_rule_ret = -1;
  fake.add_rule_err = EINVAL;

  struct cmd_opts opts = {0};
  push_port(&opts.connect_ports, &opts.n_connect, &opts.cap_connect, 443);

  assert(caged_setup(&opts) == CAGED_ERR_CONNECT_ACCESS);
  assert(fake.restrict_calls_count == 0);

  cmd_opts_free(&opts);
}

void test_setup_bind_rule_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.add_rule_ret = -1;
  fake.add_rule_err = EINVAL;

  struct cmd_opts opts = {0};
  push_port(&opts.bind_ports, &opts.n_bind, &opts.cap_bind, 80);

  assert(caged_setup(&opts) == CAGED_ERR_BIND_ACCESS);
  assert(fake.restrict_calls_count == 0);

  cmd_opts_free(&opts);
}

/* below ABI 4 net is unsupported, so nothing is handled */
void test_setup_net_unsupported_abi(void) {
  reset_fake();
  fake.abi = 3;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.last_handled_net == 0);
}

/* releasing a scope clears its bit from the default mask */
void test_setup_released_scope(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};
  opts.released_scopes = LANDLOCK_SCOPE_SIGNAL;

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.last_scoped == (SCOPED & ~LANDLOCK_SCOPE_SIGNAL));
}

/* below ABI 6 scopes are unsupported, so nothing is restricted */
void test_setup_scopes_unsupported_abi(void) {
  reset_fake();
  fake.abi = 5;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.last_scoped == 0);
}

/* restrict-self flags requested by the user are passed through when
   supported by the ABI */
void test_setup_restrict_flags(void) {
  reset_fake();
  fake.abi = 8;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};
  opts.restrict_flags =
      LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON | LANDLOCK_RESTRICT_SELF_TSYNC;

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.last_restrict_flags == (LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON |
                                      LANDLOCK_RESTRICT_SELF_TSYNC));
}

/* below ABI 7 the log flags are masked out (consistent with scopes) */
void test_setup_restrict_flags_unsupported_abi(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};
  opts.restrict_flags = RESTRICT_FLAGS;

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.last_restrict_flags == 0);
}

/* ABI 7 supports the log flags but TSYNC is masked out */
void test_setup_restrict_flags_abi_7(void) {
  reset_fake();
  fake.abi = 7;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};
  opts.restrict_flags = RESTRICT_FLAGS;

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.last_restrict_flags ==
         (RESTRICT_FLAGS & ~LANDLOCK_RESTRICT_SELF_TSYNC));
}

void test_setup_no_landlock(void) {
  reset_fake();
  fake.abi = -1;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_NO_LANDLOCK);
  assert(fake.create_calls_count == 0);
}

void test_setup_create_ruleset_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = -1;
  fake.create_ruleset_err = EPERM;

  struct cmd_opts opts = {0};

  errno = 0;
  assert(caged_setup(&opts) == CAGED_ERR_CREATE_RULESET);
  assert(errno == EPERM);
  assert(fake.add_calls_count == 0);
}

void test_setup_allow_ro_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.open_ret = -1;
  fake.open_err = ENOENT;

  struct cmd_opts opts = {0};
  push_path(&opts.r_dir, &opts.n_r, &opts.cap_r, "/nope");

  assert(caged_setup(&opts) == CAGED_ERR_READ_ACCESS);
  assert(fake.restrict_calls_count == 0);

  cmd_opts_free(&opts);
}

void test_setup_allow_rw_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.open_ret = -1;
  fake.open_err = ENOENT;

  struct cmd_opts opts = {0};
  push_path(&opts.rw_dir, &opts.n_rw, &opts.cap_rw, "/nope");

  assert(caged_setup(&opts) == CAGED_ERR_RW_ACCESS);
  assert(fake.restrict_calls_count == 0);

  cmd_opts_free(&opts);
}

void test_setup_restrict_prctl_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.prctl_ret = -1;
  fake.prctl_err = EPERM;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_RESTRICT_SELF);
}

void test_setup_restrict_syscall_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.prctl_ret = 0;
  fake.restrict_self_ret = -1;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_RESTRICT_SELF);
  assert(fake.restrict_calls_count == 1);
}

/*
  Number of seccomp rules added by deny_socket_families(): every family
  except the four allowed ones, plus the "above AF_MAX" catch-all.
*/
static int family_rules(void) {
  int n = 0;

  for (int f = 0; f < AF_MAX; f++) {
    if (f == AF_INET || f == AF_INET6 || f == AF_NETLINK || f == AF_UNIX) {
      continue;
    }
    n++;
  }
  return n + 1;
}

/* Number of rules added by deny_sysv_ipc(): one per SysV IPC syscall. */
static int sysv_rules(void) { return (int)SYSV_IPC_N; }

/* Number of rules added by deny_dangerous_syscalls(). */
static int deny_rules(void) { return (int)DENY_SYSCALLS_N; }

/* Common setup for a landlock run that reaches the seccomp step. */
static void setup_reaches_seccomp(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;
}

/* Make the Nth seccomp rule fail with -EINVAL. */
static void fail_seccomp_rule_at(int n) {
  fake.seccomp_rule_ret = -EINVAL;
  fake.seccomp_rule_fail_at = n;
}

/* Cores are disabled even when nothing is asked for, and RLIMIT_NPROC is
   left alone. Every inherited fd above stderr is closed at the end. */
void test_setup_rlimits_default(void) {
  setup_reaches_seccomp();

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.setrlimit_calls_count == 1);
  assert(fake.last_rlimit_resource == RLIMIT_CORE);
  assert(fake.last_rlimit_cur == 0);
  assert(fake.last_rlimit_max == 0);
  assert(fake.close_range_calls_count == 1);
  assert(fake.last_close_range_first == 3);
  assert(fake.last_close_range_last == ~0U);
  assert(fake.last_close_range_flags == 0);
  /* fds are closed only after the seccomp filter is installed */
  assert(fake.close_range_seen_loads == 1);
}

/* --max-procs sets RLIMIT_NPROC, with the hard limit equal to the soft one */
void test_setup_max_procs(void) {
  setup_reaches_seccomp();

  struct cmd_opts opts = {0};
  opts.max_procs = 64;

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.setrlimit_calls_count == 2);
  assert(fake.last_rlimit_resource == RLIMIT_NPROC);
  assert(fake.last_rlimit_cur == 64);
  assert(fake.last_rlimit_max == 64);
}

/* a failing RLIMIT_CORE aborts the setup before any ruleset exists */
void test_setup_rlimit_core_error(void) {
  setup_reaches_seccomp();
  fake.setrlimit_ret = -1;
  fake.setrlimit_err = EPERM;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_RLIMIT);
  assert(fake.create_calls_count == 0);
  assert(fake.close_range_calls_count == 0);
}

/* the RLIMIT_CORE call succeeds and RLIMIT_NPROC is the one that fails */
void test_setup_rlimit_nproc_error(void) {
  setup_reaches_seccomp();
  fake.setrlimit_ret = -1;
  fake.setrlimit_err = EPERM;
  fake.setrlimit_fail_at = 2;

  struct cmd_opts opts = {0};
  opts.max_procs = 64;

  assert(caged_setup(&opts) == CAGED_ERR_RLIMIT);
  assert(fake.setrlimit_calls_count == 2);
  assert(fake.create_calls_count == 0);
}

/* failing to close the inherited fds is an error, after the filter loaded */
void test_setup_close_fds_error(void) {
  setup_reaches_seccomp();
  fake.close_range_ret = -1;
  fake.close_range_err = EINVAL;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_CLOSE_FDS);
  assert(fake.seccomp_load_calls_count == 1);
}

/* By default the filter denies unix and network sockets: all rules run and
   the filter is loaded exactly once. */
void test_setup_seccomp_defaults(void) {
  setup_reaches_seccomp();

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.seccomp_rule_calls_count ==
         family_rules() + 7 + sysv_rules() + deny_rules());
  assert(fake.seccomp_load_calls_count == 1);
  assert(fake.seccomp_release_calls_count == 1);
  assert(fake.last_seccomp_action == SCMP_ACT_ERRNO(ENOSYS));
  assert(seccomp_detail == 0);
  assert(seccomp_failed_family == -1);
  assert(seccomp_failed_syscall == NULL);
}

/* --allow-unix-sockets skips the AF_UNIX rule */
void test_setup_seccomp_allow_unix(void) {
  setup_reaches_seccomp();

  struct cmd_opts opts = {0};
  opts.allow_unix_sockets = 1;

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.seccomp_rule_calls_count ==
         family_rules() + 6 + sysv_rules() + deny_rules());
  assert(fake.seccomp_load_calls_count == 1);
}

/* --allow-network-sockets skips the three network family rules */
void test_setup_seccomp_allow_network(void) {
  setup_reaches_seccomp();

  struct cmd_opts opts = {0};
  opts.allow_network_sockets = 1;

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.seccomp_rule_calls_count ==
         family_rules() + 4 + sysv_rules() + deny_rules());
  assert(fake.seccomp_load_calls_count == 1);
}

/* both flags together skip four rules */
void test_setup_seccomp_allow_both(void) {
  setup_reaches_seccomp();

  struct cmd_opts opts = {0};
  opts.allow_unix_sockets = 1;
  opts.allow_network_sockets = 1;

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.seccomp_rule_calls_count ==
         family_rules() + 3 + sysv_rules() + deny_rules());
}

/* --allow-sysv-ipc skips the whole SysV IPC table */
void test_setup_seccomp_allow_sysv_ipc(void) {
  setup_reaches_seccomp();

  struct cmd_opts opts = {0};
  opts.allow_sysv_ipc = 1;

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.seccomp_rule_calls_count == family_rules() + 7 + deny_rules());
  /* the dangerous table is unconditional, so it still resolves its names */
  assert(fake.seccomp_resolve_calls_count == deny_rules());
  assert(fake.seccomp_load_calls_count == 1);
}

/* a SysV rule fails: the code says so and the filter is not loaded */
void test_setup_seccomp_sysv_ipc_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(family_rules() + 8);

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_SYSVIPC);
  assert(seccomp_detail == -EINVAL);
  assert(seccomp_failed_family == -1);
  assert(fake.seccomp_load_calls_count == 0);
  assert(fake.seccomp_release_calls_count == 1);
}

/* the last SysV rule fails: the loop runs the whole table before giving up */
void test_setup_seccomp_sysv_ipc_last_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(family_rules() + 7 + sysv_rules());

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_SYSVIPC);
  assert(fake.seccomp_resolve_calls_count == sysv_rules());
  assert(fake.seccomp_load_calls_count == 0);
}

/* a syscall name libseccomp cannot resolve fails closed */
void test_setup_seccomp_sysv_ipc_resolve_error(void) {
  setup_reaches_seccomp();
  fake.seccomp_resolve_fail_at = 3;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_SYSVIPC);
  assert(seccomp_detail == -ENOSYS);
  assert(fake.seccomp_rule_calls_count == family_rules() + 7 + 2);
  assert(fake.seccomp_load_calls_count == 0);
}

/* the first dangerous syscall rule fails: the code says so and names it */
void test_setup_seccomp_syscalls_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(family_rules() + 7 + sysv_rules() + 1);

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_SYSCALLS);
  assert(seccomp_detail == -EINVAL);
  assert(strcmp(seccomp_failed_syscall, DENY_SYSCALLS[0]) == 0);
  assert(fake.seccomp_load_calls_count == 0);
  assert(fake.seccomp_release_calls_count == 1);
}

/* the last dangerous rule fails: the whole table is walked first */
void test_setup_seccomp_syscalls_last_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(family_rules() + 7 + sysv_rules() + deny_rules());

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_SYSCALLS);
  assert(strcmp(seccomp_failed_syscall, DENY_SYSCALLS[deny_rules() - 1]) == 0);
  assert(fake.seccomp_resolve_calls_count == sysv_rules() + deny_rules());
  assert(fake.seccomp_load_calls_count == 0);
}

/* a dangerous name libseccomp cannot resolve fails closed and is reported */
void test_setup_seccomp_syscalls_resolve_error(void) {
  setup_reaches_seccomp();
  fake.seccomp_resolve_fail_at = sysv_rules() + 2;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_SYSCALLS);
  assert(seccomp_detail == -ENOSYS);
  assert(strcmp(seccomp_failed_syscall, DENY_SYSCALLS[1]) == 0);
  assert(fake.seccomp_rule_calls_count ==
         family_rules() + 7 + sysv_rules() + 1);
  assert(fake.seccomp_load_calls_count == 0);
}

void test_setup_seccomp_init_error(void) {
  setup_reaches_seccomp();
  fake.seccomp_init_null = 1;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_INIT);
  assert(fake.seccomp_rule_calls_count == 0);
  assert(fake.seccomp_load_calls_count == 0);
}

/* a family rule fails: the code says so and reports which family */
void test_setup_seccomp_families_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(1);

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_FAMILIES);
  assert(seccomp_detail == -EINVAL);
  assert(seccomp_failed_family == 0);
  assert(fake.seccomp_release_calls_count == 1);
  assert(fake.seccomp_load_calls_count == 0);
}

/* the "above AF_MAX" rule fails: no family is to blame */
void test_setup_seccomp_above_af_max_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(family_rules());

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_FAMILIES);
  assert(seccomp_detail == -EINVAL);
  assert(seccomp_failed_family == -1);
}

void test_setup_seccomp_inet_raw_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(family_rules() + 1);

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_INET_RAW);
  assert(seccomp_detail == -EINVAL);
  assert(seccomp_failed_family == -1);
  assert(fake.seccomp_load_calls_count == 0);
}

/* the second raw rule (AF_INET6) fails */
void test_setup_seccomp_inet6_raw_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(family_rules() + 2);

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_INET_RAW);
  assert(seccomp_detail == -EINVAL);
  assert(fake.seccomp_load_calls_count == 0);
}

void test_setup_seccomp_netlink_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(family_rules() + 3);

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_NETLINK);
  assert(seccomp_failed_family == -1);
}

void test_setup_seccomp_unix_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(family_rules() + 4);

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_UNIX);
}

void test_setup_seccomp_network_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(family_rules() + 5);

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_NETWORK);
}

/* the second and third network rules (AF_INET6, AF_NETLINK) fail */
void test_setup_seccomp_network_inet6_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(family_rules() + 6);

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_NETWORK);
  assert(seccomp_detail == -EINVAL);
  assert(fake.seccomp_load_calls_count == 0);
}

void test_setup_seccomp_network_netlink_error(void) {
  setup_reaches_seccomp();
  fail_seccomp_rule_at(family_rules() + 7);

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_NETWORK);
  assert(fake.seccomp_load_calls_count == 0);
}

/* the filter is built but cannot be installed */
void test_setup_seccomp_load_error(void) {
  setup_reaches_seccomp();
  fake.seccomp_load_ret = -EPERM;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_SECCOMP_LOAD);
  assert(fake.seccomp_load_calls_count == 1);
  assert(fake.seccomp_release_calls_count == 1);
}

/* test if every  return code have a message */
void test_strreturn(void) {
  enum caged_return codes[] = {
      CAGED_OK,
      CAGED_ERR_NO_LANDLOCK,
      CAGED_ERR_CREATE_RULESET,
      CAGED_ERR_READ_ACCESS,
      CAGED_ERR_RW_ACCESS,
      CAGED_ERR_CONNECT_ACCESS,
      CAGED_ERR_BIND_ACCESS,
      CAGED_ERR_RESTRICT_SELF,
      CAGED_ERR_RLIMIT,
      CAGED_ERR_CLOSE_FDS,
      CAGED_ERR_SECCOMP_INIT,
      CAGED_ERR_SECCOMP_FAMILIES,
      CAGED_ERR_SECCOMP_INET_RAW,
      CAGED_ERR_SECCOMP_NETLINK,
      CAGED_ERR_SECCOMP_UNIX,
      CAGED_ERR_SECCOMP_NETWORK,
      CAGED_ERR_SECCOMP_SYSVIPC,
      CAGED_ERR_SECCOMP_SYSCALLS,
      CAGED_ERR_SECCOMP_LOAD,
  };
  for (size_t i = 0; i < sizeof codes / sizeof codes[0]; i++) {
    const char *msg = caged_strreturn(codes[i]);
    assert(msg != NULL);
    assert(msg[0] != '\0');
  }
}

void test_strreturn_unknown_error(void) {
  assert(strcmp(caged_strreturn((enum caged_return)999), "unknown error") == 0);
}

/* ABI used by the setup run whose stderr is being captured. */
static long g_setup_abi;

static void run_setup_quiet(void) {
  reset_fake();
  fake.abi = g_setup_abi;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};
  caged_setup(&opts);
}

/* Runs caged_setup with stderr redirected and copies the captured text. */
static void capture_setup_warnings(long abi, char *buf, size_t size) {
  int pipefd[2];
  assert(pipe(pipefd) == 0);

  fflush(stderr);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0);
  assert(dup2(pipefd[1], STDERR_FILENO) >= 0);
  close(pipefd[1]);

  g_setup_abi = abi;
  run_setup_quiet();

  fflush(stderr);
  assert(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);

  ssize_t n = read(pipefd[0], buf, size - 1);
  if (n < 0) {
    n = 0;
  }
  buf[n] = '\0';
  close(pipefd[0]);
}

/* a kernel new enough for everything prints no warning at all */
void test_warn_none_when_all_supported(void) {
  char buf[1024];
  capture_setup_warnings(9, buf, sizeof buf);
  assert(buf[0] == '\0');
}

/* only the features the ABI lacks are listed */
void test_warn_partial(void) {
  char buf[2048];
  capture_setup_warnings(6, buf, sizeof buf);

  assert(strstr(buf, "does not support some features") != NULL);
  assert(strstr(buf, "restrict-self log flags (needs ABI 7)") != NULL);
  assert(strstr(buf, "restrict-self TSYNC (needs ABI 8)") != NULL);
  assert(strstr(buf, "UNIX socket name resolution (needs ABI 9)") != NULL);
  /* features already supported by ABI 6 are not warned about */
  assert(strstr(buf, "network access control") == NULL);
  assert(strstr(buf, "ioctl on device files") == NULL);
  assert(strstr(buf, "IPC scopes") == NULL);
}

/* an old ABI lists every feature */
void test_warn_all_when_none_supported(void) {
  char buf[4096];
  capture_setup_warnings(1, buf, sizeof buf);

  assert(strstr(buf, "network access control (needs ABI 4)") != NULL);
  assert(strstr(buf, "ioctl on device files (needs ABI 5)") != NULL);
  assert(strstr(buf, "IPC scopes (needs ABI 6)") != NULL);
  assert(strstr(buf, "restrict-self log flags (needs ABI 7)") != NULL);
  assert(strstr(buf, "restrict-self TSYNC (needs ABI 8)") != NULL);
  assert(strstr(buf, "UNIX socket name resolution (needs ABI 9)") != NULL);
}

/* CAGED_DISABLE_WARNINGS=1 silences the warnings */
void test_warn_disabled_by_env(void) {
  char buf[1024];
  assert(setenv("CAGED_DISABLE_WARNINGS", "1", 1) == 0);
  capture_setup_warnings(6, buf, sizeof buf);
  assert(buf[0] == '\0');
  assert(unsetenv("CAGED_DISABLE_WARNINGS") == 0);
}

/* any value other than "1" leaves the warnings enabled */
void test_warn_env_other_value_keeps_warnings(void) {
  char buf[1024];
  assert(setenv("CAGED_DISABLE_WARNINGS", "0", 1) == 0);
  capture_setup_warnings(6, buf, sizeof buf);
  assert(strstr(buf, "does not support some features") != NULL);
  assert(unsetenv("CAGED_DISABLE_WARNINGS") == 0);
}

int main(void) {
  test_setup_ok();
  test_setup_released_net_general();
  test_setup_net_port_rules();
  test_setup_connect_rule_error();
  test_setup_bind_rule_error();
  test_setup_net_unsupported_abi();
  test_setup_released_scope();
  test_setup_scopes_unsupported_abi();
  test_setup_restrict_flags();
  test_setup_restrict_flags_unsupported_abi();
  test_setup_restrict_flags_abi_7();
  test_setup_no_landlock();
  test_setup_create_ruleset_error();
  test_setup_allow_ro_error();
  test_setup_allow_rw_error();
  test_setup_restrict_prctl_error();
  test_setup_restrict_syscall_error();
  test_setup_rlimits_default();
  test_setup_max_procs();
  test_setup_rlimit_core_error();
  test_setup_rlimit_nproc_error();
  test_setup_close_fds_error();
  test_setup_seccomp_defaults();
  test_setup_seccomp_allow_unix();
  test_setup_seccomp_allow_network();
  test_setup_seccomp_allow_both();
  test_setup_seccomp_allow_sysv_ipc();
  test_setup_seccomp_init_error();
  test_setup_seccomp_families_error();
  test_setup_seccomp_above_af_max_error();
  test_setup_seccomp_inet_raw_error();
  test_setup_seccomp_inet6_raw_error();
  test_setup_seccomp_netlink_error();
  test_setup_seccomp_unix_error();
  test_setup_seccomp_network_error();
  test_setup_seccomp_network_inet6_error();
  test_setup_seccomp_network_netlink_error();
  test_setup_seccomp_sysv_ipc_error();
  test_setup_seccomp_sysv_ipc_last_error();
  test_setup_seccomp_sysv_ipc_resolve_error();
  test_setup_seccomp_syscalls_error();
  test_setup_seccomp_syscalls_last_error();
  test_setup_seccomp_syscalls_resolve_error();
  test_setup_seccomp_load_error();
  test_strreturn();
  test_strreturn_unknown_error();
  test_warn_none_when_all_supported();
  test_warn_partial();
  test_warn_all_when_none_supported();
  test_warn_disabled_by_env();
  test_warn_env_other_value_keeps_warnings();

  printf("OK\n");
  return 0;
}
