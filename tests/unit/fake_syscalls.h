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
#include <seccomp.h>

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
  int fail_strndup;
  int strndup_err;

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
  /* seccomp_attr_set() return value (negative errno) */
  int seccomp_attr_ret;

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
  int seccomp_attr_calls_count;
  enum scmp_filter_attr last_seccomp_attr;
  uint32_t last_seccomp_attr_value;

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

  /* user/network namespace setup (--loopback-only) */
  int unshare_ret;
  int unshare_err;
  /* Fail only the Nth unshare() call (1 = user namespace, 2 = network
     namespace). 0 fails every call when unshare_ret is negative. */
  int unshare_fail_at;
  int socket_fd;
  int socket_err;
  int ioctl_ret;
  int ioctl_err;
  /* Fail only the Nth ioctl() call (1 = SIOCGIFFLAGS, 2 = SIOCSIFFLAGS). */
  int ioctl_fail_at;
  /* flags SIOCGIFFLAGS reports back */
  short ioctl_flags;
  int capset_ret;
  int capset_err;
  int capbset_drop_ret;
  int capbset_drop_err;
  int ambient_ret;
  int ambient_err;
  int proc_open_fd;
  int proc_open_fail;
  /* Fail only the Nth /proc/self open (1 = setgroups, 2 = uid_map,
     3 = gid_map). 0 fails every call when proc_open_fail is set. */
  int proc_open_fail_at;
  int proc_open_err;
  /* Negative fails the write; 0 writes everything; positive writes that many
     bytes, which is how a short write is simulated. */
  int write_ret;
  int write_err;

  /* namespace spies */
  int unshare_calls_count;
  unsigned long last_unshare_flags;
  int socket_calls_count;
  int last_socket_family;
  int last_socket_type;
  int socket_close_calls_count;
  int ioctl_calls_count;
  unsigned long last_ioctl_request;
  short last_ioctl_flags;
  int capset_calls_count;
  unsigned long last_capset_version;
  unsigned long last_capset_permitted;
  unsigned long last_capset_effective;
  int capbset_drop_calls_count;
  int last_capbset_cap;
  int ambient_calls_count;
  int last_ambient_option;
  int proc_open_calls_count;
  const char *last_proc_path;
  int proc_close_calls_count;
  int write_calls_count;
  char last_write[64];
  /* every /proc entry opened and every line written, in order */
  const char *proc_paths[8];
  char proc_writes[8][64];
};

extern struct fake_context fake;

void reset_fake(void);

#endif
