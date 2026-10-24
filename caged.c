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

/*
  The sandbox itself: ABI gating, the Landlock ruleset and its rules, the
  seccomp filter and the resource limits. This file is meant to be linkable as
  a library; nothing here parses argv or prints anything for the user. The
  command-line front end lives in cli.c and main.c.
*/

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/netlink.h>
#include <seccomp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "caged.h"

/* I need to define this here because it's not defined in any
 header I can include.*/
#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xf
#endif

/* fs access handled by the latest api */
#define FS_HANDLED                                                             \
  (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |                \
   LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |                \
   LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |            \
   LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |                \
   LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |                \
   LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |              \
   LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |                    \
   LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV |                \
   LANDLOCK_ACCESS_FS_RESOLVE_UNIX)

#define PERMS_READ                                                             \
  (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |                \
   LANDLOCK_ACCESS_FS_EXECUTE)

#define PERMS_READ_WRITE                                                       \
  (PERMS_READ | LANDLOCK_ACCESS_FS_WRITE_FILE |                                \
   LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |            \
   LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |                 \
   LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_RESOLVE_UNIX)

/* fs access only relevant for directories */
#define PERMS_DIRS_ONLY                                                        \
  (LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |               \
   LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR |              \
   LANDLOCK_ACCESS_FS_MAKE_REG)

/* scopes restricted by default (added in Landlock ABI 6) */
#define SCOPED (LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL)

/* net access handled by the latest api (added in Landlock ABI 4) */
#define NET_HANDLED                                                            \
  (LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP)

/* restrict-self flags supported by the latest api: the log flags were added
   in ABI 7 and TSYNC in ABI 8 */
#define RESTRICT_FLAGS                                                         \
  (LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF |                                  \
   LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON |                                    \
   LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF | LANDLOCK_RESTRICT_SELF_TSYNC)

/*
  The sandbox diagnostics declared in caged.h. They are file-global here so
  the caller can report what went wrong after caged_setup returns.
*/
int seccomp_detail;
int seccomp_failed_family = -1;
const char *seccomp_failed_syscall;

/*
  The Landlock ABI version on the host. It is kept so we can report what
  the kernel offers against what --require-abi asked for.
*/
long abi_found = -1;

/* Set by caged_setup from CAGED_DISABLE_WARNINGS, before environ is replaced */
int caged_warnings_disabled;

/*
  System V IPC syscalls are blocked. They will return ENOSYS
*/
static const char *SYSV_IPC_SYSCALLS[] = {
    "msgget",     "msgsnd", "msgrcv", "msgctl", "semget", "semop",
    "semtimedop", "semctl", "shmget", "shmat",  "shmdt",  "shmctl",
};

/*
  Syscalls that act on other processes or use shared memory are blocked
*/
static const char *DENY_SYSCALLS[] = {
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "pidfd_getfd",
    "process_madvise",
    "kcmp",
    "keyctl",
    "add_key",
    "request_key",
    "io_uring_setup",
    "bpf",
    "perf_event_open",
    "userfaultfd",
};

#define SYSV_IPC_N (sizeof SYSV_IPC_SYSCALLS / sizeof SYSV_IPC_SYSCALLS[0])
#define DENY_SYSCALLS_N (sizeof DENY_SYSCALLS / sizeof DENY_SYSCALLS[0])

/*
  Environment variables that will be inherited by default.
*/
static const char *BASE_ENV[] = {
    "PATH",
    "HOME",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_MESSAGES",
    "LC_PAPER",
    "LC_NAME",
    "LC_ADDRESS",
    "LC_TELEPHONE",
    "LC_MEASUREMENT",
    "LC_IDENTIFICATION",
};

#define BASE_ENV_N (sizeof BASE_ENV / sizeof BASE_ENV[0])

void cmd_opts_free(struct cmd_opts *opts) {
  free((void *)opts->r_dir);
  free((void *)opts->rw_dir);
  free(opts->connect_ports);
  free(opts->bind_ports);
  free(opts->env);
  opts->r_dir = NULL;
  opts->rw_dir = NULL;
  opts->connect_ports = NULL;
  opts->bind_ports = NULL;
  opts->env = NULL;
  opts->n_r = 0;
  opts->n_rw = 0;
  opts->n_connect = 0;
  opts->n_bind = 0;
  opts->n_env = 0;
  opts->cap_r = 0;
  opts->cap_rw = 0;
  opts->cap_connect = 0;
  opts->cap_bind = 0;
  opts->cap_env = 0;
}

/*
  Appends `entry` to a dynamic list of environment strings, growing the
  backing array (doubling its capacity) when it is full. Returns 0 on
  success, -1 on allocation failure.
*/
static int push_env_entry(char ***list, int *n, int *cap, const char *entry) {
  if (*n == *cap) {
    int new_cap = *cap ? *cap * 2 : 4;
    char **grown = realloc(*list, (size_t)new_cap * sizeof **list);
    if (grown == NULL) {
      return -1;
    }
    *list = grown;
    *cap = new_cap;
  }
  (*list)[(*n)++] = (char *)entry;
  return 0;
}

/* Length of the NAME part of a NAME=VALUE entry. */
static size_t env_name_len(const char *entry) {
  const char *eq = strchr(entry, '=');
  return eq == NULL ? strlen(entry) : (size_t)(eq - entry);
}

/* True when `entry`'s name is exactly the `name_len` bytes of `name`. */
static int env_same_name(const char *entry, const char *name, size_t name_len) {
  return env_name_len(entry) == name_len && strncmp(entry, name, name_len) == 0;
}

/* True when `entry` is one of the variables inherited by default. */
static int env_is_base(const char *entry) {
  for (size_t k = 0; k < BASE_ENV_N; k++) {
    if (env_same_name(entry, BASE_ENV[k], strlen(BASE_ENV[k]))) {
      return 1;
    }
  }
  return 0;
}

/* True when `entry` is overridden by one of the opts' env entries. */
static int env_overridden(const char *entry, const struct cmd_opts *opts) {
  for (int k = 0; k < opts->n_env; k++) {
    if (env_same_name(entry, opts->env[k], env_name_len(opts->env[k]))) {
      return 1;
    }
  }
  return 0;
}

/*
  Builds the environment variables. The default base, or
  everything inherited with keep_env and the env values.
  Returns a NULL-terminated array, or NULL on allocation failure.
*/
static char **build_env(const struct cmd_opts *opts) {
  char **env = NULL;
  int n = 0;
  int cap = 0;
  int failed = 0;

  if (environ != NULL) {
    for (char **e = environ; *e != NULL; e++) {
      if (!opts->keep_env && !env_is_base(*e)) {
        continue;
      }
      if (env_overridden(*e, opts)) {
        continue;
      }
      failed |= push_env_entry(&env, &n, &cap, *e) < 0;
    }
  }
  for (int k = 0; k < opts->n_env; k++) {
    failed |= push_env_entry(&env, &n, &cap, opts->env[k]) < 0;
  }
  failed |= push_env_entry(&env, &n, &cap, NULL) < 0;
  if (failed) {
    free(env);
    return NULL;
  }
  return env;
}

/*
  Replaces the process environment with the given entries. Anything not in
  `env` is dropped from environ, so every child of this process starts with
  the allowed variables only.
*/
static void replace_environ(char **env) {
  clearenv();
  for (int k = 0; env[k] != NULL; k++) {
    const char *eq = strchr(env[k], '=');
    if (eq == NULL) {
      setenv(env[k], "", 1);
      continue;
    }
    char *name = strndup(env[k], (size_t)(eq - env[k]));
    if (name != NULL) {
      setenv(name, eq + 1, 1);
      free(name);
    }
  }
}

/*
  Creates a new landlock ruleset.
  By default it denies permission for all the handled acesses.
  The handled accesses are held by the *attr pointer
*/
static int create_ruleset(const struct landlock_ruleset_attr *attr) {
  return syscall(SYS_landlock_create_ruleset, attr,
                 sizeof(struct landlock_ruleset_attr), 0);
}

/* Adds an exception (grants access) on the ruleset for the given acesses.
   The accesses for the grants are held by the *pb pointer
 */
static int add_rule(int ruleset_fd,
                    const struct landlock_path_beneath_attr *pb) {
  return syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                 pb, 0);
}

/* Locks the current process and its children to the rules added up to point */
static int restrict_self(int ruleset_fd, unsigned long flags) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    return -1;
  }
  return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}

/* Sets soft and the hard limits. */
static int set_limit(int resource, rlim_t value) {
  struct rlimit rl = {.rlim_cur = value, .rlim_max = value};
  return setrlimit(resource, &rl);
}

/*
  Applies the resource limits. Core is always 0.
*/
static int apply_rlimits(long max_procs) {
  if (set_limit(RLIMIT_CORE, 0) < 0) {
    return -1;
  }
  if (max_procs > 0 && set_limit(RLIMIT_NPROC, (rlim_t)max_procs) < 0) {
    return -1;
  }
  return 0;
}

/*
  Closes every file descriptor inherited above stderr.
*/
static int close_inherited_fds(void) { return close_range(3, ~0U, 0); }

static long check_abi() {
  return syscall(SYS_landlock_create_ruleset, NULL, 0,
                 LANDLOCK_CREATE_RULESET_VERSION);
}

/*
  True when the kernel's Landlock ABI meets the --require-abi floor. A floor
  of 0 means "no requirement": caged then only warns about the features the
  ABI lacks, which is the fail-open behaviour.
*/
static int abi_satisfies(long abi, long require) {
  return require <= 0 || abi >= require;
}

/*
  Returns the handled fs accesses supported by the abi version available on
  the host
*/
static int get_handled_access_fs(long abi) {
  int handled = FS_HANDLED;
  if (abi < 2) {
    handled &= ~LANDLOCK_ACCESS_FS_REFER;
  }
  if (abi < 3) {
    handled &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
  }
  if (abi < 5) {
    handled &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
  }
  if (abi < 9) {
    handled &= ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
  }
  return handled;
}

static int get_perms_read_write(long abi) {
  int perms = PERMS_READ_WRITE;
  if (abi < 3) {
    perms &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
  }
  if (abi < 9) {
    perms &= ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
  }
  return perms;
}

/*
  Returns the scopes restricted by default and supported by the abi version
  available on the host. Scopes were added in ABI 6.
*/
static unsigned long get_supported_scopes(long abi) {
  unsigned long scopes = SCOPED;
  if (abi < 6) {
    scopes = 0;
  }
  return scopes;
}

/*
  Returns the net accesses supported by the abi version available on the host.
  Net accesses were added in ABI 4.
*/
static int get_handled_access_net(long abi) {
  int handled = NET_HANDLED;
  if (abi < 4) {
    handled = 0;
  }
  return handled;
}

/*
  Returns the restrict-self flags supported by the abi version available on
  the host. The log flags were added in ABI 7 and TSYNC in ABI 8.
*/
static unsigned long get_supported_restrict_flags(long abi) {
  unsigned long flags = RESTRICT_FLAGS;
  if (abi < 7) {
    flags &= ~(LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF |
               LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON |
               LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF);
  }
  if (abi < 8) {
    flags &= ~LANDLOCK_RESTRICT_SELF_TSYNC;
  }
  return flags;
}

/* Grant some kind of access for a given path */
static int allow_access(int ruleset_fd, const char *path,
                        struct landlock_path_beneath_attr *pb) {
  int r;
  int parent_fd;
  struct stat st;

  parent_fd = open(path, O_PATH | O_CLOEXEC);
  if (parent_fd < 0) {
    return -1;
  }

  if (fstat(parent_fd, &st) < 0) {
    close(parent_fd);
    return -1;
  }
  if (!S_ISDIR(st.st_mode)) {
    pb->allowed_access &= ~PERMS_DIRS_ONLY;
  }
  pb->parent_fd = parent_fd;
  r = add_rule(ruleset_fd, pb);
  close(pb->parent_fd);
  return r;
}

/* Grant read access for a given path */
static int allow_read_access(int ruleset_fd, const char *path) {
  struct landlock_path_beneath_attr pb = {.allowed_access = PERMS_READ};

  return allow_access(ruleset_fd, path, &pb);
}

/* Grant read and write access for a give path */
static int allow_read_write_access(int ruleset_fd, const char *path, long abi) {
  int perms = get_perms_read_write(abi);
  struct landlock_path_beneath_attr pb = {.allowed_access = perms};
  return allow_access(ruleset_fd, path, &pb);
}

/* Adds a net rule granting the given access for a single port. */
static int add_net_rule(int ruleset_fd, unsigned long allowed_access,
                        unsigned short port) {
  struct landlock_net_port_attr attr = {
      .allowed_access = allowed_access,
      .port = port,
  };
  return syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_NET_PORT,
                 &attr, 0);
}

/* Grant the ability to connect to the given port. */
static int allow_net_connect_access(int ruleset_fd, unsigned short port) {
  return add_net_rule(ruleset_fd, LANDLOCK_ACCESS_NET_CONNECT_TCP, port);
}

/* Grant the ability to bind the given port. */
static int allow_net_bind_access(int ruleset_fd, unsigned short port) {
  return add_net_rule(ruleset_fd, LANDLOCK_ACCESS_NET_BIND_TCP, port);
}

/*
  Blocks the use of all socket families except for AF_INET, AF_INET6,
  AF_NETLINK and AF_UNIX. These have individual rules for each one.
*/
static int deny_socket_families(scmp_filter_ctx ctx) {
  int r;

  for (int f = 0; f < AF_MAX; f++) {
    if (f == AF_INET || f == AF_INET6 || f == AF_NETLINK || f == AF_UNIX) {
      continue;
    }
    r = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 1,
                               SCMP_A0(SCMP_CMP_EQ, f));
    if (r < 0) {
      seccomp_detail = r;
      seccomp_failed_family = f;
      return -1;
    }
  }
  /* Families numbered above this build's AF_MAX are also blocked */
  r = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 1,
                             SCMP_A0(SCMP_CMP_GE, AF_MAX));
  if (r < 0) {
    seccomp_detail = r;
    return -1;
  }
  return 0;
}

/* Blocks the use of AF_INET and AF_INET6 SOCK_RAW as this could be used to
   manually craft packets that could bypass the landlock rules.
*/
static int deny_inet_raw(scmp_filter_ctx ctx) {
  int r;

  r = seccomp_rule_add_exact(
      ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 2,
      SCMP_A0(SCMP_CMP_EQ, AF_INET),
      SCMP_A1(SCMP_CMP_MASKED_EQ, SOCK_TYPE_MASK, SOCK_RAW));
  if (r < 0) {
    seccomp_detail = r;
    return -1;
  }
  r = seccomp_rule_add_exact(
      ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 2,
      SCMP_A0(SCMP_CMP_EQ, AF_INET6),
      SCMP_A1(SCMP_CMP_MASKED_EQ, SOCK_TYPE_MASK, SOCK_RAW));
  if (r < 0) {
    seccomp_detail = r;
    return -1;
  }
  return 0;
}

/* Blocks the use of AF_NETLINK NETLINK_USERSOCK as this protocol is
   used to IPC.
*/
static int deny_netlink_usersock(scmp_filter_ctx ctx) {
  int r;

  r = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 2,
                             SCMP_A0(SCMP_CMP_EQ, AF_NETLINK),
                             SCMP_A2(SCMP_CMP_EQ, NETLINK_USERSOCK));
  if (r < 0) {
    seccomp_detail = r;
    return -1;
  }
  return 0;
}

/* Blocks the use of AF_UNIX. Used for IPC */
static int deny_unix_sockets(scmp_filter_ctx ctx) {
  int r;

  r = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 1,
                             SCMP_A0(SCMP_CMP_EQ, AF_UNIX));
  if (r < 0) {
    seccomp_detail = r;
    return -1;
  }
  return 0;
}

/* Blocks the use of AF_INET, AF_INET6 and AF_NETLINK */
static int deny_network_sockets(scmp_filter_ctx ctx) {
  int r;

  r = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 1,
                             SCMP_A0(SCMP_CMP_EQ, AF_INET));
  if (r < 0) {
    seccomp_detail = r;
    return -1;
  }
  r = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 1,
                             SCMP_A0(SCMP_CMP_EQ, AF_INET6));
  if (r < 0) {
    seccomp_detail = r;
    return -1;
  }
  r = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 1,
                             SCMP_A0(SCMP_CMP_EQ, AF_NETLINK));
  if (r < 0) {
    seccomp_detail = r;
    return -1;
  }
  return 0;
}

/*
  Denies each named syscall with ENOSYS. A name libseccomp cannot resolve
  returns an error.
*/
static int deny_syscall_list(scmp_filter_ctx ctx, const char *const *names,
                             size_t n) {
  for (size_t k = 0; k < n; k++) {
    int nr = seccomp_syscall_resolve_name(names[k]);
    if (nr == __NR_SCMP_ERROR) {
      seccomp_detail = -ENOSYS;
      seccomp_failed_syscall = names[k];
      return -1;
    }
    int r = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(ENOSYS), nr, 0);
    if (r < 0) {
      seccomp_detail = r;
      seccomp_failed_syscall = names[k];
      return -1;
    }
  }
  return 0;
}

/* Blocks the system V ipc calls */
static int deny_sysv_ipc(scmp_filter_ctx ctx) {
  return deny_syscall_list(ctx, SYSV_IPC_SYSCALLS, SYSV_IPC_N);
}

/* Blocks the syscalls that escape the sandbox or attack the kernel */
static int deny_dangerous_syscalls(scmp_filter_ctx ctx) {
  return deny_syscall_list(ctx, DENY_SYSCALLS, DENY_SYSCALLS_N);
}

/*
  Builds and loads the seccomp filter.

  `tsync` mirrors the Landlock restrict-self flag of the same name: the filter
  is then applied to every thread of the thread group, not only to the calling
  one. Without it a thread that already exists (a sibling) keeps running
  unfiltered; a process forked from another branch is out of reach either way.
  Calling seccomp_load with the flag set can return the tid of a thread that
  failed to synchronize instead of -1, so the load is checked against 0.
*/
static enum caged_return apply_seccomp(int allow_unix_sockets,
                                       int allow_network_sockets,
                                       int allow_sysv_ipc, int tsync) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

  seccomp_detail = 0;
  seccomp_failed_family = -1;
  seccomp_failed_syscall = NULL;
  if (ctx == NULL) {
    return CAGED_ERR_SECCOMP_INIT;
  }
  int r = 0;
  if (tsync) {
    r = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1);
    if (r < 0) {
      seccomp_detail = r;
      seccomp_release(ctx);
      return CAGED_ERR_SECCOMP_TSYNC;
    }
  }
  if (deny_socket_families(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_FAMILIES;
  }
  if (deny_inet_raw(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_INET_RAW;
  }
  if (deny_netlink_usersock(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_NETLINK;
  }
  if (!allow_unix_sockets && deny_unix_sockets(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_UNIX;
  }
  if (!allow_network_sockets && deny_network_sockets(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_NETWORK;
  }
  if (!allow_sysv_ipc && deny_sysv_ipc(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_SYSVIPC;
  }
  if (deny_dangerous_syscalls(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_SYSCALLS;
  }
  if (seccomp_load(ctx) != 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_LOAD;
  }
  seccomp_release(ctx);
  return CAGED_OK;
}

const char *caged_strreturn(enum caged_return r) {
  switch (r) {
  case CAGED_OK:
    return "ok";
  case CAGED_ERR_NO_LANDLOCK:
    return "Landlock not supported";
  case CAGED_ERR_ABI_TOO_OLD:
    return "Landlock ABI too old";
  case CAGED_ERR_CREATE_RULESET:
    return "error creating ruleset";
  case CAGED_ERR_READ_ACCESS:
    return "error allowing read access";
  case CAGED_ERR_RW_ACCESS:
    return "error allowing read_write access";
  case CAGED_ERR_CONNECT_ACCESS:
    return "error allowing connect access";
  case CAGED_ERR_BIND_ACCESS:
    return "error allowing bind access";
  case CAGED_ERR_RESTRICT_SELF:
    return "error restricting self";
  case CAGED_ERR_RLIMIT:
    return "error setting resource limits";
  case CAGED_ERR_CLOSE_FDS:
    return "error closing inherited file descriptors";
  case CAGED_ERR_SECCOMP_INIT:
    return "error creating seccomp filter";
  case CAGED_ERR_SECCOMP_FAMILIES:
    return "error denying socket families";
  case CAGED_ERR_SECCOMP_INET_RAW:
    return "error denying raw sockets";
  case CAGED_ERR_SECCOMP_NETLINK:
    return "error denying netlink usersock";
  case CAGED_ERR_SECCOMP_UNIX:
    return "error denying unix sockets";
  case CAGED_ERR_SECCOMP_NETWORK:
    return "error denying network sockets";
  case CAGED_ERR_SECCOMP_SYSVIPC:
    return "error denying sysv ipc";
  case CAGED_ERR_SECCOMP_SYSCALLS:
    return "error denying dangerous syscalls";
  case CAGED_ERR_SECCOMP_LOAD:
    return "error loading seccomp filter";
  case CAGED_ERR_SECCOMP_TSYNC:
    return "error setting seccomp thread sync";
  case CAGED_ERR_ENV:
    return "error building the environment";
  }
  return "unknown error";
}

/*
  Creates the sandbox. If return != CAGED_OK the process must be terminated
  with an error.

  Use caged_strreturn for a sane message.
*/
enum caged_return caged_setup(const struct cmd_opts *opts, char ***env) {
  if (env != NULL) {
    *env = NULL;
  }
  if (apply_rlimits(opts->max_procs) < 0) {
    return CAGED_ERR_RLIMIT;
  }
  long abi = check_abi();
  abi_found = abi;
  if (abi < 1) {
    return CAGED_ERR_NO_LANDLOCK;
  }
  if (!abi_satisfies(abi, opts->require_abi)) {
    errno = ENOTSUP;
    return CAGED_ERR_ABI_TOO_OLD;
  }
  int handled = get_handled_access_fs(abi);
  int handled_net = get_handled_access_net(abi);
  struct landlock_ruleset_attr r_perm = {
      .handled_access_fs = handled,
      .handled_access_net = (unsigned long)handled_net & ~opts->released_net,
      .scoped = get_supported_scopes(abi) & ~opts->released_scopes,
  };
  int ruleset = create_ruleset(&r_perm);
  if (ruleset < 0) {
    return CAGED_ERR_CREATE_RULESET;
  }
  for (int k = 0; k < opts->n_r; k++) {
    if (allow_read_access(ruleset, opts->r_dir[k]) < 0) {
      return CAGED_ERR_READ_ACCESS;
    }
  }
  for (int k = 0; k < opts->n_rw; k++) {
    if (allow_read_write_access(ruleset, opts->rw_dir[k], abi) < 0) {
      return CAGED_ERR_RW_ACCESS;
    }
  }
  for (int k = 0; k < opts->n_connect; k++) {
    if (allow_net_connect_access(ruleset, opts->connect_ports[k]) < 0) {
      return CAGED_ERR_CONNECT_ACCESS;
    }
  }
  for (int k = 0; k < opts->n_bind; k++) {
    if (allow_net_bind_access(ruleset, opts->bind_ports[k]) < 0) {
      return CAGED_ERR_BIND_ACCESS;
    }
  }
  if (restrict_self(ruleset, opts->restrict_flags &
                                 get_supported_restrict_flags(abi)) < 0) {
    return CAGED_ERR_RESTRICT_SELF;
  }
  close(ruleset);
  enum caged_return r =
      apply_seccomp(opts->allow_unix_sockets, opts->allow_network_sockets,
                    opts->allow_sysv_ipc,
                    (opts->restrict_flags & LANDLOCK_RESTRICT_SELF_TSYNC) != 0);
  if (r != CAGED_OK) {
    return r;
  }
  if (close_inherited_fds() < 0) {
    return CAGED_ERR_CLOSE_FDS;
  }
  /* The environment is the last step so the allowed entries are computed
     from the inherited environ, which replace_environ() then drops. The
     warning switch is read first because it is not part of the base set. */
  const char *disable = getenv("CAGED_DISABLE_WARNINGS");
  caged_warnings_disabled = disable != NULL && strcmp(disable, "1") == 0;
  char **new_env = build_env(opts);
  if (new_env == NULL) {
    return CAGED_ERR_ENV;
  }
  replace_environ(new_env);
  if (env != NULL) {
    *env = new_env;
  } else {
    free(new_env);
  }
  return CAGED_OK;
}
