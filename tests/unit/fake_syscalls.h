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

#ifndef FAKE_SYSCALL_H
#define FAKE_SYSCALL_H
#include <stddef.h>
#include <stdint.h>

struct open_call {
  const char *path;
  int flags;
  int ret_fd;
};

/* struct used in tests. It carries return values and spies
 for the mocked tests
*/
struct fake_context {
  long abi;
  long create_ruleset_ret;
  int create_ruleset_err;
  long add_rule_ret;
  long restrict_self_ret;
  int open_ret;
  int open_err;
  int stat_ret;
  int stat_err;
  int isdir_ret;
  int add_rule_err;
  int prctl_ret;
  int prctl_err;
  int fail_realloc;
  int realloc_err;

  int setrlimit_ret;
  int setrlimit_err;
  /* Fail only the Nth setrlimit() call. 0 fails on the first one
     when setrlimit_ret is negative. Used to reach the RLIMIT_NPROC call. */
  int setrlimit_fail_at;
  int close_range_ret;
  int close_range_err;

  int seccomp_init_null;
  int seccomp_rule_ret;
  /* Fail only the Nth rule call). 0 makes every call fail when
     seccomp_rule_ret is negative.  Used to reach each deny_* step. */
  int seccomp_rule_fail_at;
  int seccomp_load_ret;
  /* Fail the Nth seccomp_syscall_resolve_name(). 0 resolves all. */
  int seccomp_resolve_fail_at;

  /* spies */
  struct open_call last_open;
  int open_calls_count;
  int close_calls_count;
  long last_allowed_access;
  int last_parent_fd;
  unsigned long last_scoped;
  unsigned long last_handled_net;
  long last_net_allowed_access;
  long last_net_port;
  unsigned long last_restrict_flags;
  int create_calls_count;
  int add_calls_count;
  int restrict_calls_count;
  int ruleset_close_calls_count;

  /* seccomp spies */
  int seccomp_rule_calls_count;
  int seccomp_load_calls_count;
  int seccomp_release_calls_count;
  int last_seccomp_syscall;
  uint32_t last_seccomp_action;
  unsigned int last_seccomp_arg_cnt;
  int seccomp_resolve_calls_count;

  /* resource and fd spies */
  int setrlimit_calls_count;
  int last_rlimit_resource;
  unsigned long last_rlimit_cur;
  unsigned long last_rlimit_max;
  int close_range_calls_count;
  unsigned int last_close_range_first;
  unsigned int last_close_range_last;
  int last_close_range_flags;
  /* seccomp_load() count at the moment close_range() ran */
  int close_range_seen_loads;
};

extern struct fake_context fake;

void reset_fake(void);

#endif
