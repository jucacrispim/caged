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

#define _GNU_SOURCE
#include "fake_syscalls.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/landlock.h>
#include <net/if.h>
#include <seccomp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

struct fake_context fake;

void reset_fake(void) {
  fake = (struct fake_context){
      .abi = 6,
      .open_ret = 9876,
      .socket_fd = 9877,
      .proc_open_fd = 9878,
  };
}

long __wrap_syscall(long num, ...) {
  va_list ap;
  va_start(ap, num);
  long ret = -1;
  switch (num) {
  case SYS_landlock_create_ruleset: {
    void *attr = va_arg(ap, void *);
    size_t size = va_arg(ap, size_t);
    int flags = va_arg(ap, int);
    if (attr == NULL && size == 0 && flags == LANDLOCK_CREATE_RULESET_VERSION) {
      ret = fake.abi;
    } else {
      struct landlock_ruleset_attr *rs = attr;
      fake.create_calls_count++;
      fake.last_scoped = rs ? rs->scoped : 0;
      fake.last_handled_net = rs ? rs->handled_access_net : 0;
      if (fake.create_ruleset_ret < 0) {
        errno = fake.create_ruleset_err;
      }
      ret = fake.create_ruleset_ret;
    }
    break;
  }
  case SYS_landlock_add_rule: {
    int fd = va_arg(ap, int);
    int rule_type = va_arg(ap, int);
    void *attr = va_arg(ap, void *);
    int flags = va_arg(ap, int);
    (void)fd;
    (void)flags;
    fake.add_calls_count++;
    if (rule_type == LANDLOCK_RULE_NET_PORT) {
      struct landlock_net_port_attr *np = attr;
      fake.last_net_allowed_access = (long)np->allowed_access;
      fake.last_net_port = (long)np->port;
    } else {
      struct landlock_path_beneath_attr *pb = attr;
      fake.last_allowed_access = (long)pb->allowed_access;
      fake.last_parent_fd = pb->parent_fd;
    }
    if (fake.add_rule_ret < 0) {
      errno = fake.add_rule_err;
    }
    ret = fake.add_rule_ret;
    break;
  }
  case SYS_landlock_restrict_self: {
    int fd = va_arg(ap, int);
    unsigned long flags = va_arg(ap, unsigned long);
    (void)fd;
    fake.last_restrict_flags = flags;
    fake.restrict_calls_count++;
    ret = fake.restrict_self_ret;
    break;
  }
  /*
    capset has no glibc header (the declaration belongs to libcap) and older
    libcs export a stub that always fails, so caged issues it with syscall().
    That makes it the one piece of the namespace setup left in this switch;
    unshare, socket and ioctl have wrappers and are faked as such below.
  */
  case SYS_capset: {
    struct __user_cap_header_struct *header = va_arg(ap, void *);
    struct __user_cap_data_struct *data = va_arg(ap, void *);
    fake.capset_calls_count++;
    fake.last_capset_version = header ? header->version : 0;
    fake.last_capset_permitted = data ? data[0].permitted : 1;
    fake.last_capset_effective = data ? data[0].effective : 1;
    if (fake.capset_ret < 0) {
      errno = fake.capset_err;
    }
    ret = fake.capset_ret;
    break;
  }
  default:
    abort();
  }
  va_end(ap);
  return ret;
}

/*
  unshare() is never delegated: letting it through would put the test process
  inside a real user namespace, irreversibly. caged calls it twice (user
  namespace, then network namespace), and unshare_fail_at picks which of the
  two fails.
*/
int __wrap_unshare(int flags) {
  fake.unshare_calls_count++;
  fake.last_unshare_flags = (unsigned long)flags;

  if (fake.unshare_ret >= 0) {
    return fake.unshare_ret;
  }
  if (fake.unshare_fail_at != 0 &&
      fake.unshare_calls_count != fake.unshare_fail_at) {
    return 0;
  }
  errno = fake.unshare_err;
  return -1;
}

/*
  caged creates one socket, the AF_INET datagram that brings loopback up, so
  the fake owns the call: a real one would leave a descriptor behind for no
  reason and tell nothing.
*/
int __wrap_socket(int domain, int type, int protocol) {
  (void)protocol;
  fake.socket_calls_count++;
  fake.last_socket_family = domain;
  fake.last_socket_type = type;
  if (fake.socket_fd < 0) {
    errno = fake.socket_err;
    return -1;
  }
  return fake.socket_fd;
}

extern int __real_ioctl(int fd, unsigned long request, ...);

/*
  Only the two interface requests are faked. Anything else goes to the real
  ioctl — stdio asks whether a descriptor is a tty when it first buffers, and
  that call arrives here too — the same way __wrap_open delegates everything
  that is not caged's O_PATH probe.
*/
int __wrap_ioctl(int fd, unsigned long request, ...) {
  va_list ap;
  void *arg;

  va_start(ap, request);
  arg = va_arg(ap, void *);
  va_end(ap);

  if (request != SIOCGIFFLAGS && request != SIOCSIFFLAGS) {
    return __real_ioctl(fd, request, arg);
  }

  struct ifreq *ifr = arg;
  fake.ioctl_calls_count++;
  fake.last_ioctl_request = request;
  if (fake.ioctl_ret < 0 && (fake.ioctl_fail_at == 0 ||
                             fake.ioctl_calls_count == fake.ioctl_fail_at)) {
    errno = fake.ioctl_err;
    return -1;
  }
  if (request == SIOCGIFFLAGS) {
    ifr->ifr_flags = fake.ioctl_flags;
  } else {
    fake.last_ioctl_flags = ifr->ifr_flags;
  }
  return 0;
}

extern int __real_open(const char *path, int flags, ...);
extern int __real_fstat(int fd, struct stat *st);
extern int __real_close(int fd);
extern void *__real_realloc(void *ptr, size_t size);

/* only fails when the test asks for it; otherwise delegates to the real one */
void *__wrap_realloc(void *ptr, size_t size) {
  if (fake.fail_realloc) {
    errno = fake.realloc_err;
    return NULL;
  }
  return __real_realloc(ptr, size);
}

extern char *__real_strndup(const char *s, size_t n);

/* only fails when the test asks for it; otherwise delegates to the real one */
char *__wrap_strndup(const char *s, size_t n) {
  if (fake.fail_strndup) {
    errno = fake.strndup_err;
    return NULL;
  }
  return __real_strndup(s, n);
}

/* True when the path belongs to the user namespace configuration. Those files
   are never touched for real: the test process would either fail or, worse,
   change its own mappings. */
static int is_proc_self(const char *path) {
  return path != NULL && strncmp(path, "/proc/self/", 11) == 0;
}

int __wrap_open(const char *path, int flags, ...) {
  /* caged uses O_PATH on open. If it is not used, return the real stuff*/
  if (!(flags & O_PATH)) {
    if (is_proc_self(path)) {
      fake.proc_open_calls_count++;
      fake.last_proc_path = path;
      if (fake.proc_open_calls_count <= 8) {
        fake.proc_paths[fake.proc_open_calls_count - 1] = path;
      }
      if (fake.proc_open_fail &&
          (fake.proc_open_fail_at == 0 ||
           fake.proc_open_calls_count == fake.proc_open_fail_at)) {
        errno = fake.proc_open_err;
        return -1;
      }
      return fake.proc_open_fd;
    }
    if (flags & O_CREAT) {
      va_list ap;
      va_start(ap, flags);
      mode_t mode = va_arg(ap, mode_t);
      va_end(ap);
      return __real_open(path, flags, mode);
    }
    return __real_open(path, flags);
  }
  /* fake when called by caged */
  fake.open_calls_count++;
  fake.last_open.path = path;
  fake.last_open.flags = flags;
  if (fake.open_ret < 0) {
    errno = fake.open_err;
    fake.last_open.ret_fd = -1;
    return -1;
  }
  fake.last_open.ret_fd = fake.open_ret;
  return fake.open_ret;
}

int __wrap_fstat(int fd, struct stat *st) {
  if (fd != fake.open_ret) {
    return __real_fstat(fd, st);
  }
  if (fake.stat_ret < 0) {
    errno = fake.stat_err;
    return -1;
  }
  memset(st, 0, sizeof *st);
  st->st_mode = fake.isdir_ret ? (S_IFDIR | 0755) : (S_IFREG | 0644);
  return 0;
}

int __wrap_close(int fd) {
  /* The ruleset fd comes from create_ruleset, not from open: never let it
     reach the real close(), or the test process loses a real descriptor. */
  if (fd >= 0 && fd == (int)fake.create_ruleset_ret) {
    fake.ruleset_close_calls_count++;
    return 0;
  }
  /* Same for the descriptors that stand in for the socket and for the
     /proc entries of the user namespace: they are not real. */
  if (fd >= 0 && fd == fake.socket_fd) {
    fake.socket_close_calls_count++;
    return 0;
  }
  if (fd >= 0 && fd == fake.proc_open_fd) {
    fake.proc_close_calls_count++;
    return 0;
  }
  if (fd != fake.open_ret) {
    return __real_close(fd);
  }
  fake.close_calls_count++;
  return 0;
}

extern ssize_t __real_write(int fd, const void *buf, size_t count);

/* Only the /proc entries written by the namespace setup are faked; anything
   else (the diagnostics, libgcov) goes to the real one. */
ssize_t __wrap_write(int fd, const void *buf, size_t count) {
  if (fd != fake.proc_open_fd) {
    return __real_write(fd, buf, count);
  }
  fake.write_calls_count++;
  size_t n = count < sizeof fake.last_write - 1 ? count
                                               : sizeof fake.last_write - 1;
  memcpy(fake.last_write, buf, n);
  fake.last_write[n] = '\0';
  if (fake.write_calls_count <= 8) {
    memcpy(fake.proc_writes[fake.write_calls_count - 1], fake.last_write,
           sizeof fake.last_write);
  }
  if (fake.write_ret < 0) {
    errno = fake.write_err;
    return -1;
  }
  if (fake.write_ret > 0) {
    return fake.write_ret;
  }
  return (ssize_t)count;
}

/* caged only uses prctl(PR_SET_NO_NEW_PRIVS), so we mock just that one */
/*
  caged uses three prctl options: PR_SET_NO_NEW_PRIVS (the Landlock step),
  PR_CAPBSET_DROP (one call per capability, in the drop) and PR_CAP_AMBIENT
  (clearing the ambient set). Anything else is a bug and aborts.
*/
int __wrap_prctl(int option, ...) {
  va_list ap;
  int ret = 0;

  va_start(ap, option);
  switch (option) {
  case PR_SET_NO_NEW_PRIVS:
    if (fake.prctl_ret < 0) {
      errno = fake.prctl_err;
    }
    ret = fake.prctl_ret;
    break;
  case PR_CAPBSET_DROP: {
    int cap = va_arg(ap, int);
    fake.capbset_drop_calls_count++;
    fake.last_capbset_cap = cap;
    if (fake.capbset_drop_ret < 0) {
      errno = fake.capbset_drop_err;
      ret = -1;
    }
    break;
  }
  case PR_CAP_AMBIENT: {
    int sub = va_arg(ap, int);
    fake.ambient_calls_count++;
    fake.last_ambient_option = sub;
    if (fake.ambient_ret < 0) {
      errno = fake.ambient_err;
      ret = -1;
    }
    break;
  }
  default:
    abort();
  }
  va_end(ap);
  return ret;
}

int __wrap_setrlimit(int resource, const struct rlimit *rlim) {
  fake.setrlimit_calls_count++;
  fake.last_rlimit_resource = resource;
  fake.last_rlimit_cur = rlim ? (unsigned long)rlim->rlim_cur : 0;
  fake.last_rlimit_max = rlim ? (unsigned long)rlim->rlim_max : 0;

  if (fake.setrlimit_ret >= 0) {
    return fake.setrlimit_ret;
  }
  if (fake.setrlimit_fail_at != 0 &&
      fake.setrlimit_calls_count != fake.setrlimit_fail_at) {
    return 0;
  }
  errno = fake.setrlimit_err;
  return fake.setrlimit_ret;
}

/* Never delegates to the real one: it would close every descriptor of the
   test process, including the ones libgcov writes through. */
int __wrap_close_range(unsigned int first, unsigned int last, int flags) {
  fake.close_range_calls_count++;
  fake.last_close_range_first = first;
  fake.last_close_range_last = last;
  fake.last_close_range_flags = flags;
  fake.close_range_seen_loads = fake.seccomp_load_calls_count;
  if (fake.close_range_ret < 0) {
    errno = fake.close_range_err;
  }
  return fake.close_range_ret;
}

/*
  seccomp mocks. The real filter must never be installed in a unit test: it
  is irreversible, applies to the test process itself and breaks libgcov.
  A non-NULL sentinel stands in for the real context.
*/
scmp_filter_ctx __wrap_seccomp_init(uint32_t def_action) {
  (void)def_action;
  if (fake.seccomp_init_null) {
    return NULL;
  }
  return (scmp_filter_ctx)(void *)&fake;
}

/* Variadic, like the real one: the comparisons must be walked or the va_list
   is left in an inconsistent state. The fake is authoritative here. */
int __wrap_seccomp_rule_add_exact(scmp_filter_ctx ctx, uint32_t action,
                                  int syscall, unsigned int arg_cnt, ...) {
  va_list ap;

  (void)ctx;
  fake.seccomp_rule_calls_count++;
  fake.last_seccomp_action = action;
  fake.last_seccomp_syscall = syscall;
  fake.last_seccomp_arg_cnt = arg_cnt;

  va_start(ap, arg_cnt);
  for (unsigned int k = 0; k < arg_cnt; k++) {
    (void)va_arg(ap, struct scmp_arg_cmp);
  }
  va_end(ap);

  if (fake.seccomp_rule_ret >= 0) {
    return fake.seccomp_rule_ret;
  }
  /* fail_at == 0 keeps the old behaviour: every call fails. */
  if (fake.seccomp_rule_fail_at != 0 &&
      fake.seccomp_rule_calls_count != fake.seccomp_rule_fail_at) {
    return 0;
  }
  errno = -fake.seccomp_rule_ret;
  return fake.seccomp_rule_ret;
}

/* Only the TSYNC attribute is set by caged; the spy records what was asked
   for so the test can check the flag reaches libseccomp. */
int __wrap_seccomp_attr_set(scmp_filter_ctx ctx, enum scmp_filter_attr attr,
                            uint32_t value) {
  (void)ctx;
  fake.seccomp_attr_calls_count++;
  fake.last_seccomp_attr = attr;
  fake.last_seccomp_attr_value = value;
  if (fake.seccomp_attr_ret < 0) {
    errno = -fake.seccomp_attr_ret;
  }
  return fake.seccomp_attr_ret;
}

int __wrap_seccomp_load(scmp_filter_ctx ctx) {
  if (ctx == NULL) {
    return -EINVAL;
  }
  fake.seccomp_load_calls_count++;
  return fake.seccomp_load_ret;
}

int __wrap_seccomp_release(scmp_filter_ctx ctx) {
  (void)ctx;
  fake.seccomp_release_calls_count++;
  return 0;
}

extern int __real_seccomp_syscall_resolve_name(const char *name);

/* By default the real lookup runs. */
int __wrap_seccomp_syscall_resolve_name(const char *name) {
  fake.seccomp_resolve_calls_count++;
  if (fake.seccomp_resolve_fail_at != 0 &&
      fake.seccomp_resolve_calls_count == fake.seccomp_resolve_fail_at) {
    return __NR_SCMP_ERROR;
  }
  return __real_seccomp_syscall_resolve_name(name);
}
