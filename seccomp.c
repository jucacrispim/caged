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
  The seccomp layer: the filter that closes what Landlock has no right for
  (socket families, IPC, and the syscalls that escape the sandbox). It is
  built with libseccomp and installed by the setup, after the Landlock domain.
*/

#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

#include "caged_internal.h"

/*
  The sandbox diagnostics declared in caged.h. They are file-global here so
  the caller can report what went wrong after caged_setup returns.
*/
int seccomp_detail;
int seccomp_failed_family = -1;
const char *seccomp_failed_syscall;

/*
  System V IPC syscalls are blocked. They will return ENOSYS
*/
const char *caged_sysv_ipc_syscalls[] = {
    "msgget",     "msgsnd", "msgrcv", "msgctl", "semget", "semop",
    "semtimedop", "semctl", "shmget", "shmat",  "shmdt",  "shmctl",
};

const size_t caged_sysv_ipc_syscalls_n =
    sizeof caged_sysv_ipc_syscalls / sizeof caged_sysv_ipc_syscalls[0];

/*
  Namespace flags for clone().
*/
const unsigned long long caged_clone_ns_flags[] = {
    CLONE_NEWNS,   CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC,
    CLONE_NEWUSER, CLONE_NEWPID,    CLONE_NEWNET, CLONE_NEWTIME,
};

const size_t caged_clone_ns_flags_n =
    sizeof caged_clone_ns_flags / sizeof caged_clone_ns_flags[0];

/*
  Syscalls that escape the sandbox, act on other processes or attack the
  kernel are blocked. They will return ENOSYS.
*/
const char *caged_deny_syscalls[] = {
    /* inspect or write the memory of another process */
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "pidfd_getfd",
    "process_madvise",
    "process_mrelease",
    "kcmp",
    /* the caller's own keyrings */
    "keyctl",
    "add_key",
    "request_key",
    /* kernel attack surface */
    "io_uring_setup",
    "bpf",
    "perf_event_open",
    "userfaultfd",
    /* load code into the kernel, or take the machine down */
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "reboot",
    "swapon",
    "swapoff",
    "acct",
    "quotactl",
    "iopl",
    "ioperm",
    "modify_ldt",
    "open_by_handle_at",
    /*
      Mounting and namespaces
    */
    "unshare",
    "setns",
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "move_mount",
    "open_tree",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "mount_setattr",
    "clone3",
};

const size_t caged_deny_syscalls_n =
    sizeof caged_deny_syscalls / sizeof caged_deny_syscalls[0];

/*
  Blocks the use of all socket families except for AF_INET, AF_INET6,
  AF_NETLINK and AF_UNIX. These have individual rules for each one.
*/
int caged_deny_socket_families(scmp_filter_ctx ctx) {
  int r;

  for (int f = 0; f < AF_MAX; f++) {
    if (f == AF_INET || f == AF_INET6 || f == AF_NETLINK || f == AF_UNIX) {
      continue;
    }
    r = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 1,
                               SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)f));
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
int caged_deny_inet_raw(scmp_filter_ctx ctx) {
  int r;

  r = seccomp_rule_add_exact(
      ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 2,
      SCMP_A0(SCMP_CMP_EQ, AF_INET),
      SCMP_A1(SCMP_CMP_MASKED_EQ, CAGED_SOCK_TYPE_MASK, SOCK_RAW));
  if (r < 0) {
    seccomp_detail = r;
    return -1;
  }
  r = seccomp_rule_add_exact(
      ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 2,
      SCMP_A0(SCMP_CMP_EQ, AF_INET6),
      SCMP_A1(SCMP_CMP_MASKED_EQ, CAGED_SOCK_TYPE_MASK, SOCK_RAW));
  if (r < 0) {
    seccomp_detail = r;
    return -1;
  }
  return 0;
}

/* Blocks the use of AF_NETLINK NETLINK_USERSOCK as this protocol is
   used to IPC.
*/
int caged_deny_netlink_usersock(scmp_filter_ctx ctx) {
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
int caged_deny_unix_sockets(scmp_filter_ctx ctx) {
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
int caged_deny_network_sockets(scmp_filter_ctx ctx) {
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
  Blocks a clone() with new namespace.
*/
int caged_deny_clone_namespaces(scmp_filter_ctx ctx) {
  for (size_t k = 0; k < caged_clone_ns_flags_n; k++) {
    unsigned long long flag = caged_clone_ns_flags[k];
    int r = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone),
                                   1, SCMP_A0(SCMP_CMP_MASKED_EQ, flag, flag));
    if (r < 0) {
      seccomp_detail = r;
      return -1;
    }
  }
  return 0;
}

/*
  Denies each named syscall with ENOSYS. A name libseccomp cannot resolve
  returns an error.
*/
int caged_deny_syscall_list(scmp_filter_ctx ctx, const char *const *names,
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
int caged_deny_sysv_ipc(scmp_filter_ctx ctx) {
  return caged_deny_syscall_list(ctx, caged_sysv_ipc_syscalls,
                                 caged_sysv_ipc_syscalls_n);
}

/* Blocks the syscalls that escape the sandbox or attack the kernel */
int caged_deny_dangerous_syscalls(scmp_filter_ctx ctx) {
  return caged_deny_syscall_list(ctx, caged_deny_syscalls,
                                 caged_deny_syscalls_n);
}

/*
  Builds and loads the seccomp filter.
*/
enum caged_return caged_apply_seccomp(int allow_unix_sockets,
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
  if (caged_deny_socket_families(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_FAMILIES;
  }
  if (caged_deny_inet_raw(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_INET_RAW;
  }
  if (caged_deny_netlink_usersock(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_NETLINK;
  }
  if (!allow_unix_sockets && caged_deny_unix_sockets(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_UNIX;
  }
  if (!allow_network_sockets && caged_deny_network_sockets(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_NETWORK;
  }
  if (caged_deny_clone_namespaces(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_CLONE_NS;
  }
  if (!allow_sysv_ipc && caged_deny_sysv_ipc(ctx) < 0) {
    seccomp_release(ctx);
    return CAGED_ERR_SECCOMP_SYSVIPC;
  }
  if (caged_deny_dangerous_syscalls(ctx) < 0) {
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
