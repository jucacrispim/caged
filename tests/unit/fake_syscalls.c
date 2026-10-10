#define _GNU_SOURCE
#include "fake_syscalls.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

struct fake_context fake;

void reset_fake(void) {
  fake = (struct fake_context){.abi = 6, .open_ret = 9876};
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
    fake.restrict_calls_count++;
    ret = fake.restrict_self_ret;
    break;
  }
  default:
    abort();
  }
  va_end(ap);
  return ret;
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

int __wrap_open(const char *path, int flags, ...) {
  /* caged uses O_PATH on open. If it is not used, return the real stuff*/
  if (!(flags & O_PATH)) {
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
  if (fd != fake.open_ret) {
    return __real_close(fd);
  }
  fake.close_calls_count++;
  return 0;
}

/* caged only uses prctl(PR_SET_NO_NEW_PRIVS), so we mock just that one */
int __wrap_prctl(int option, ...) {
  if (option != PR_SET_NO_NEW_PRIVS) {
    abort();
  }
  if (fake.prctl_ret < 0) {
    errno = fake.prctl_err;
  }
  return fake.prctl_ret;
}
