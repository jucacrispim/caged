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

/* Here we test the seccomp rules by checking the generated pseudo code
 from seccomp_export_pfc
*/

#define main caged_program_main
#include "../../caged.c"
#undef main

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Renders the filter as pseudo code and leaves it in buf. */
static void export_pfc(scmp_filter_ctx ctx, char *buf, size_t size) {
  /*
    A memfd keeps the pseudo code off the filesystem: there is no /tmp path to
    honour (or to ignore $TMPDIR), no template to collide and nothing left
    behind when the test dies halfway. seccomp_export_pfc only needs a
    seekable, readable descriptor.
  */
  int fd = memfd_create("caged_pfc", 0);

  assert(fd >= 0);
  assert(seccomp_export_pfc(ctx, fd) == 0);
  assert(lseek(fd, 0, SEEK_SET) == 0);

  ssize_t n = read(fd, buf, size - 1);
  assert(n > 0);
  buf[n] = '\0';
  close(fd);
}

/* Builds the filter exactly as apply_seccomp does, with the given steps
   enabled, and returns the rendered pseudo code. */
static void build_and_export(int with_unix, int with_network, char *buf,
                             size_t size) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

  assert(ctx != NULL);
  assert(deny_socket_families(ctx) == 0);
  assert(deny_inet_raw(ctx) == 0);
  assert(deny_netlink_usersock(ctx) == 0);
  if (with_unix) {
    assert(deny_unix_sockets(ctx) == 0);
  }
  if (with_network) {
    assert(deny_network_sockets(ctx) == 0);
  }
  assert(deny_clone_namespaces(ctx) == 0);
  assert(deny_sysv_ipc(ctx) == 0);
  assert(deny_dangerous_syscalls(ctx) == 0);
  export_pfc(ctx, buf, size);
  seccomp_release(ctx);
}

/* True when the pseudo code compares the first element to the family value */
static int has_family(const char *buf, int value) {
  char needle[64];

  snprintf(needle, sizeof needle, "$a0.lo32 == %d)", value);
  return strstr(buf, needle) != NULL;
}

/* True when the rule after the family comparison is an action */
static int family_is_plainly_denied(const char *buf, int value) {
  char needle[64];
  const char *p;

  snprintf(needle, sizeof needle, "$a0.lo32 == %d)", value);
  p = strstr(buf, needle);
  if (p == NULL) {
    return 0;
  }
  p += strlen(needle);
  while (*p == ' ' || *p == '\t' || *p == '\n') {
    p++;
  }
  return strncmp(p, "action", 6) == 0;
}

/* By default we allow everthing for seccomp and then close all socket
   families
*/
void test_default_seccomp_filter(void) {
  char buf[65536];
  char needle[64];

  build_and_export(1, 1, buf, sizeof buf);
  assert(strstr(buf, "action ALLOW;") != NULL);

  assert(strstr(buf, "# filter for syscall \"socket\" (") != NULL);
  for (int f = 0; f < AF_MAX; f++) {
    assert(has_family(buf, f));
  }

  /* also check if families above AF_MAX are denied */
  snprintf(needle, sizeof needle, "$a0.lo32 >= %d)", AF_MAX);
  assert(strstr(buf, needle) != NULL);
}

void test_allow_unix_sockets(void) {
  char buf[65536];

  build_and_export(0, 1, buf, sizeof buf);
  assert(!has_family(buf, AF_UNIX));
}

/* when network sockets are allowed the AF_INET, AF_INET6 and AF_NETLINK
   families are not closed, but raw sockets and NETLINK_USERSOCK
   are denied.
*/
void test_allow_network_sockets(void) {
  char buf[65536];
  build_and_export(1, 0, buf, sizeof buf);
  assert(!family_is_plainly_denied(buf, AF_INET));
  assert(!family_is_plainly_denied(buf, AF_INET6));
  assert(!family_is_plainly_denied(buf, AF_NETLINK));

  /* checks if raw sockets are denied */
  assert(strstr(buf, "$a1.lo32 & 0x0000000f == 3)") != NULL);
  /* checks if NETLINK_USERSOCK is denied */
  assert(strstr(buf, "$a2.lo32 == 2)") != NULL);
}

/* Checks if every System V IPC entry point is denied */
void test_sysv_ipc_denied(void) {
  static const char *names[] = {
      "msgget",     "msgsnd", "msgrcv", "msgctl", "semget", "semop",
      "semtimedop", "semctl", "shmget", "shmat",  "shmdt",  "shmctl",
  };
  char buf[131072];
  char needle[96];

  build_and_export(1, 1, buf, sizeof buf);
  for (size_t k = 0; k < sizeof names / sizeof names[0]; k++) {
    snprintf(needle, sizeof needle, "# filter for syscall \"%s\" (", names[k]);
    assert(strstr(buf, needle) != NULL);
  }
}

/* Every dangerous syscall from the table has a rule of its own, and it is
   ENOSYS so callers take their "not implemented" fallback. */
void test_dangerous_syscalls_denied(void) {
  static const char *names[] = {
      "ptrace",          "process_vm_readv", "process_vm_writev",
      "pidfd_getfd",     "process_madvise",  "process_mrelease",
      "kcmp",            "keyctl",           "add_key",
      "request_key",     "io_uring_setup",   "bpf",
      "perf_event_open", "userfaultfd",      "init_module",
      "finit_module",    "delete_module",    "kexec_load",
      "kexec_file_load", "reboot",           "swapon",
      "swapoff",         "acct",             "quotactl",
      "iopl",            "ioperm",           "modify_ldt",
      "open_by_handle_at", "unshare",        "setns",
      "mount",           "umount2",          "pivot_root",
      "chroot",          "move_mount",       "open_tree",
      "fsopen",          "fsconfig",         "fsmount",
      "fspick",          "mount_setattr",    "clone3",
  };
  char buf[262144];
  char needle[96];
  const char *p;

  build_and_export(1, 1, buf, sizeof buf);
  for (size_t k = 0; k < sizeof names / sizeof names[0]; k++) {
    snprintf(needle, sizeof needle, "# filter for syscall \"%s\" (", names[k]);
    assert(strstr(buf, needle) != NULL);
  }

  /* io_uring_setup is the bypass this table exists for: its rule must be an
     action, not a nested comparison. */
  p = strstr(buf, "# filter for syscall \"io_uring_setup\" (");
  assert(p != NULL);
  p = strstr(p, "action ERRNO(38);");
  assert(p != NULL);
}

/* clone() is filtered by flag, one masked comparison per namespace, so a
   call asking for any of them is denied. clone3() cannot be filtered that
   way (its flags are behind a pointer) and is denied whole. */
void test_clone_namespaces_denied(void) {
  char buf[262144];
  char needle[128];
  const char *p;

  build_and_export(1, 1, buf, sizeof buf);

  p = strstr(buf, "# filter for syscall \"clone\" (");
  assert(p != NULL);
  for (size_t k = 0; k < CLONE_NS_N; k++) {
    unsigned long long flag = CLONE_NS_FLAGS[k];
    snprintf(needle, sizeof needle, "$a0.lo32 & 0x%08llx == %llu)", flag, flag);
    assert(strstr(p, needle) != NULL);
  }

  /* a bit outside the table is not blocked: the table is what decides */
  assert(strstr(p, "$a0.lo32 & 0x00800000") == NULL);

  p = strstr(buf, "# filter for syscall \"clone3\" (");
  assert(p != NULL);
  p = strstr(p, "action ERRNO(38);");
  assert(p != NULL);
}

int main(void) {
  test_default_seccomp_filter();
  test_allow_unix_sockets();
  test_allow_network_sockets();
  test_sysv_ipc_denied();
  test_dangerous_syscalls_denied();
  test_clone_namespaces_denied();

  printf("OK\n");
  return 0;
}
