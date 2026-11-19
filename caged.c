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
  The setup itself and the parts of it that do not belong to a single
  subsystem: the resource limits, the inherited descriptors and the return
  codes. The layers it drives are in landlock.c, seccomp.c, namespaces.c and
  env.c.
*/

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "caged_internal.h"

/* Set by caged_setup from CAGED_DISABLE_WARNINGS, before environ is replaced */
int caged_warnings_disabled;

void caged_opts_free(struct caged_opts *opts) {
  free((void *)opts->r_dir);
  free((void *)opts->rw_dir);
  free(opts->connect_ports);
  free(opts->bind_ports);
  free(opts->env);
  free(opts->mount_ro);
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
  /* private_tmp_src points into the caller's argv: nothing to free. */
  opts->private_tmp_src = NULL;
  opts->cap_r = 0;
  opts->cap_rw = 0;
  opts->cap_connect = 0;
  opts->cap_bind = 0;
  opts->cap_env = 0;
}

/* Sets soft and the hard limits. */
int caged_set_limit(int resource, rlim_t value) {
  struct rlimit rl = {.rlim_cur = value, .rlim_max = value};
  return setrlimit(resource, &rl);
}

/*
  Applies the resource limits. Core is always 0.
*/
int caged_apply_rlimits(long max_procs) {
  if (caged_set_limit(RLIMIT_CORE, 0) < 0) {
    return -1;
  }
  if (max_procs > 0 && caged_set_limit(RLIMIT_NPROC, (rlim_t)max_procs) < 0) {
    return -1;
  }
  return 0;
}

/*
  Closes every file descriptor inherited above stderr, except report_fd.
*/
int caged_close_inherited_fds(int report_fd) {
  if (report_fd < 3) {
    return close_range(3, ~0U, 0);
  }
  if (report_fd > 3 &&
      close_range(3, (unsigned int)report_fd - 1, 0) < 0) {
    return -1;
  }
  return close_range((unsigned int)report_fd + 1, ~0U, 0);
}

/*
  True when the kernel's Landlock ABI meets the --require-abi floor.
*/
int caged_abi_satisfies(long abi, long require) {
  return require <= 0 || abi >= require;
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
  case CAGED_ERR_SECCOMP_CLONE_NS:
    return "error denying namespace clones";
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
  case CAGED_ERR_REPORT_FD:
    return "error setting the report descriptor";
  case CAGED_ERR_USERNS_UNAVAILABLE:
    return "error creating the user namespace";
  case CAGED_ERR_USERNS_MAP:
    return "error writing the user namespace id maps";
  case CAGED_ERR_NETNS:
    return "error setting up the loopback network namespace";
  case CAGED_ERR_CAPABILITIES:
    return "error dropping capabilities";
  case CAGED_ERR_MOUNT:
    return "error setting up a private mount";
  }
  return "unknown error";
}

/*
  Creates the sandbox. If return != CAGED_OK the process must be terminated
  with an error.

  Use caged_strreturn for a sane message.
*/
enum caged_return caged_setup(const struct caged_opts *opts, char ***env) {
  if (env != NULL) {
    *env = NULL;
  }
  /*
    The report descriptor is claimed first: it has to be usable when the
    setup fails, and FD_CLOEXEC has to be in place before the sweep below
    keeps it open, so the command it execs never inherits it. A bad
    descriptor is an error like any other: silently writing nothing would let
    the caller mistake a broken sandbox for the command's own exit status.
  */
  if (opts->report_fd >= 3 && fcntl(opts->report_fd, F_SETFD, FD_CLOEXEC) < 0) {
    return CAGED_ERR_REPORT_FD;
  }
  if (caged_apply_rlimits(opts->max_procs) < 0) {
    return CAGED_ERR_RLIMIT;
  }
  /*
    The namespaces must come before landlock and seccomp: they need the
    unshare, the mount and the /proc writes those layers deny, and the
    filesystem policy has to be built against the /tmp and /dev/shm the
    command will actually see.
  */
  if (opts->loopback_only || opts->private_tmp || opts->private_shm ||
      opts->n_mount_ro > 0) {
    enum caged_return ns = caged_setup_namespaces(
        opts->private_tmp, opts->private_tmp_src, opts->private_shm,
        opts->loopback_only, opts->mount_ro, opts->n_mount_ro);
    if (ns != CAGED_OK) {
      return ns;
    }
  }
  long abi = caged_check_abi();
  abi_found = abi;
  if (abi < 1) {
    return CAGED_ERR_NO_LANDLOCK;
  }
  if (!caged_abi_satisfies(abi, opts->require_abi)) {
    errno = ENOTSUP;
    return CAGED_ERR_ABI_TOO_OLD;
  }
  unsigned long long handled = caged_get_handled_access_fs(abi);
  unsigned long long handled_net = caged_get_handled_access_net(abi);
  struct landlock_ruleset_attr r_perm = {
      .handled_access_fs = handled,
      .handled_access_net = handled_net & ~opts->released_net,
      .scoped = caged_get_handled_scopes(abi) & ~opts->released_scopes,
  };
  /* caged_create_ruleset reports the raw syscall result */
  long ruleset_ret = caged_create_ruleset(&r_perm);
  if (ruleset_ret < 0) {
    return CAGED_ERR_CREATE_RULESET;
  }
  int ruleset = (int)ruleset_ret;
  for (int k = 0; k < opts->n_r; k++) {
    if (caged_allow_read_access(ruleset, opts->r_dir[k]) < 0) {
      return CAGED_ERR_READ_ACCESS;
    }
  }
  for (int k = 0; k < opts->n_rw; k++) {
    if (caged_allow_read_write_access(ruleset, opts->rw_dir[k], abi) < 0) {
      return CAGED_ERR_RW_ACCESS;
    }
  }
  for (int k = 0; k < opts->n_connect; k++) {
    if (caged_allow_net_connect_access(ruleset, opts->connect_ports[k]) < 0) {
      return CAGED_ERR_CONNECT_ACCESS;
    }
  }
  for (int k = 0; k < opts->n_bind; k++) {
    if (caged_allow_net_bind_access(ruleset, opts->bind_ports[k]) < 0) {
      return CAGED_ERR_BIND_ACCESS;
    }
  }
  if (caged_restrict_self(ruleset, opts->restrict_flags &
                                       caged_get_supported_restrict_flags(
                                           abi)) < 0) {
    return CAGED_ERR_RESTRICT_SELF;
  }
  close(ruleset);
  enum caged_return r =
      caged_apply_seccomp(opts->allow_unix_sockets, opts->allow_network_sockets,
                          opts->allow_sysv_ipc,
                          (opts->restrict_flags &
                           LANDLOCK_RESTRICT_SELF_TSYNC) != 0);
  if (r != CAGED_OK) {
    return r;
  }
  if (caged_close_inherited_fds(opts->report_fd) < 0) {
    return CAGED_ERR_CLOSE_FDS;
  }
  /* The environment is the last step so the allowed entries are computed
     from the inherited environ, which caged_replace_environ() then drops.
     The warning switch is read first because it is not part of the base
     set. */
  const char *disable = getenv("CAGED_DISABLE_WARNINGS");
  caged_warnings_disabled = disable != NULL && strcmp(disable, "1") == 0;
  char **new_env = caged_build_env(opts);
  if (new_env == NULL) {
    return CAGED_ERR_ENV;
  }
  caged_replace_environ(new_env);
  if (env != NULL) {
    *env = new_env;
  } else {
    free(new_env);
  }
  return CAGED_OK;
}
