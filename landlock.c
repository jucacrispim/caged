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
  The Landlock layer: the ABI probe, the ruleset, the rules and the getters
  that drop what the host ABI does not know. The masks themselves are in
  caged_internal.h, because the setup decides what to handle from them.
*/

#define _GNU_SOURCE

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "caged_internal.h"

/* The Landlock ABI version on the host. Kept so the caller can compare what
   the kernel offers against what --require-abi asked for. */
long abi_found = -1;

long caged_check_abi(void) {
  return syscall(SYS_landlock_create_ruleset, NULL, 0,
                 LANDLOCK_CREATE_RULESET_VERSION);
}

/*
  Creates a new landlock ruleset.
  By default it denies permission for all the handled accesses.
  The handled accesses are held by the *attr pointer
*/
long caged_create_ruleset(const struct landlock_ruleset_attr *attr) {
  return syscall(SYS_landlock_create_ruleset, attr,
                 sizeof(struct landlock_ruleset_attr), 0);
}

/* Adds an exception (grants access) on the ruleset for the given accesses.
   The accesses for the grants are held by the *pb pointer
 */
static long add_rule(int ruleset_fd,
                     const struct landlock_path_beneath_attr *pb) {
  return syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                 pb, 0);
}

/* Locks the current process and its children to the rules added up to point */
long caged_restrict_self(int ruleset_fd, unsigned long long flags) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    return -1;
  }
  return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}

/*
  Returns the handled fs accesses supported by the abi version available on
  the host
*/
unsigned long long caged_get_handled_access_fs(long abi) {
  unsigned long long handled = CAGED_FS_HANDLED;
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

unsigned long long caged_get_perms_read_write(long abi) {
  unsigned long long perms = CAGED_PERMS_READ_WRITE;
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
unsigned long long caged_get_handled_scopes(long abi) {
  unsigned long long scopes = CAGED_SCOPED;
  if (abi < 6) {
    scopes = 0;
  }
  return scopes;
}

/*
  Returns the net accesses supported by the abi version available on the host.
  Net accesses were added in ABI 4.
*/
unsigned long long caged_get_handled_access_net(long abi) {
  unsigned long long handled = CAGED_NET_HANDLED;
  if (abi < 4) {
    handled = 0;
  }
  return handled;
}

/*
  Returns the restrict-self flags supported by the abi version available on
  the host. The log flags were added in ABI 7 and TSYNC in ABI 8.
*/
unsigned long long caged_get_supported_restrict_flags(long abi) {
  unsigned long long flags = CAGED_RESTRICT_FLAGS;
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
static long allow_access(int ruleset_fd, const char *path,
                         struct landlock_path_beneath_attr *pb) {
  long r;
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
    pb->allowed_access &= ~CAGED_PERMS_DIRS_ONLY;
  }
  pb->parent_fd = parent_fd;
  r = add_rule(ruleset_fd, pb);
  close(pb->parent_fd);
  return r;
}

/* Grant read access for a given path */
long caged_allow_read_access(int ruleset_fd, const char *path) {
  struct landlock_path_beneath_attr pb = {.allowed_access = CAGED_PERMS_READ};

  return allow_access(ruleset_fd, path, &pb);
}

/* Grant read and write access for a give path */
long caged_allow_read_write_access(int ruleset_fd, const char *path, long abi) {
  struct landlock_path_beneath_attr pb = {.allowed_access =
                                              caged_get_perms_read_write(abi)};
  return allow_access(ruleset_fd, path, &pb);
}

/* Adds a net rule granting the given access for a single port. */
long caged_add_net_rule(int ruleset_fd, unsigned long long allowed_access,
                        unsigned short port) {
  struct landlock_net_port_attr attr = {
      .allowed_access = allowed_access,
      .port = port,
  };
  return syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_NET_PORT,
                 &attr, 0);
}

/* Grant the ability to connect to the given port. */
long caged_allow_net_connect_access(int ruleset_fd, unsigned short port) {
  return caged_add_net_rule(ruleset_fd, LANDLOCK_ACCESS_NET_CONNECT_TCP, port);
}

/* Grant the ability to bind the given port. */
long caged_allow_net_bind_access(int ruleset_fd, unsigned short port) {
  return caged_add_net_rule(ruleset_fd, LANDLOCK_ACCESS_NET_BIND_TCP, port);
}
