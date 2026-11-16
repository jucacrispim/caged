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
  Interface the sandbox shares between landlock.c, seccomp.c, namespaces.c,
  env.c and caged.c. Nothing here is part of the library contract: caged.h is.

  It carries the system headers the declarations depend on, so every
  translation unit that includes it sees the same types. _GNU_SOURCE must be
  defined before it; every .c here does that on its first line.
*/

#ifndef CAGED_INTERNAL_H
#define CAGED_INTERNAL_H

#include <linux/capability.h>
#include <linux/landlock.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <sched.h>
#include <seccomp.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "caged.h"

/*
  The socket type lives in the low 4 bits of socket()'s type argument; the
  high bits are flags (SOCK_CLOEXEC, SOCK_NONBLOCK). The kernel does not
  export the mask to userspace.
*/
#define CAGED_SOCK_TYPE_MASK 0xf

/* fs access handled by the latest api */
#define CAGED_FS_HANDLED                                                       \
  (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |                \
   LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |                \
   LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |            \
   LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |                \
   LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |                \
   LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |              \
   LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |                    \
   LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV |                \
   LANDLOCK_ACCESS_FS_RESOLVE_UNIX)

/* scopes restricted by default (added in Landlock ABI 6) */
#define CAGED_SCOPED                                                           \
  (LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL)

/* net access handled by the latest api (added in Landlock ABI 4) */
#define CAGED_NET_HANDLED                                                      \
  (LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP)

/* restrict-self flags supported by the latest api: the log flags were added
   in ABI 7 and TSYNC in ABI 8 */
#define CAGED_RESTRICT_FLAGS                                                   \
  (LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF |                                  \
   LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON |                                    \
   LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF | LANDLOCK_RESTRICT_SELF_TSYNC)

#define CAGED_PERMS_READ                                                       \
  (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |                \
   LANDLOCK_ACCESS_FS_EXECUTE)

#define CAGED_PERMS_READ_WRITE                                                 \
  (CAGED_PERMS_READ | LANDLOCK_ACCESS_FS_WRITE_FILE |                          \
   LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |            \
   LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |                 \
   LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_RESOLVE_UNIX)

/* fs access only relevant for directories */
#define CAGED_PERMS_DIRS_ONLY                                                  \
  (LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |               \
   LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR |              \
   LANDLOCK_ACCESS_FS_MAKE_REG)

/* The user namespace configuration is write-only and lives in /proc. */
#define CAGED_PROC_SELF_SETGROUPS "/proc/self/setgroups"
#define CAGED_PROC_SELF_UID_MAP "/proc/self/uid_map"
#define CAGED_PROC_SELF_GID_MAP "/proc/self/gid_map"

/* Where --private-tmp and --private-shm mount the private directories. */
#define CAGED_PRIVATE_TMP "/tmp"
#define CAGED_PRIVATE_SHM "/dev/shm"
#define CAGED_PRIVATE_TMPFS_OPTS "mode=1777,size=1g"

/*
  The Landlock layer. The masks above are what the setup asks the kernel to
  handle; the getters drop the bits a given ABI does not know.
*/
long caged_check_abi(void);
long caged_create_ruleset(const struct landlock_ruleset_attr *attr);
long caged_restrict_self(int ruleset_fd, unsigned long long flags);
unsigned long long caged_get_handled_access_fs(long abi);
unsigned long long caged_get_handled_access_net(long abi);
unsigned long long caged_get_handled_scopes(long abi);
unsigned long long caged_get_supported_restrict_flags(long abi);
unsigned long long caged_get_perms_read_write(long abi);
long caged_allow_read_access(int ruleset_fd, const char *path);
long caged_allow_read_write_access(int ruleset_fd, const char *path, long abi);
long caged_add_net_rule(int ruleset_fd, unsigned long long allowed_access,
                        unsigned short port);
long caged_allow_net_connect_access(int ruleset_fd, unsigned short port);
long caged_allow_net_bind_access(int ruleset_fd, unsigned short port);

/*
  The seccomp layer. Each deny_ helper adds its rules to the context and
  returns 0, or -1 having recorded what failed in the diagnostics globals.
*/
/*
  The tables the seccomp layer installs. The number of entries is exported as
  a variable and not computed with sizeof: an extern array declaration has an
  incomplete type, so sizeof is only valid where the definition is.
*/
extern const char *caged_sysv_ipc_syscalls[];
extern const size_t caged_sysv_ipc_syscalls_n;
extern const unsigned long long caged_clone_ns_flags[];
extern const size_t caged_clone_ns_flags_n;
extern const char *caged_deny_syscalls[];
extern const size_t caged_deny_syscalls_n;

int caged_deny_socket_families(scmp_filter_ctx ctx);
int caged_deny_inet_raw(scmp_filter_ctx ctx);
int caged_deny_netlink_usersock(scmp_filter_ctx ctx);
int caged_deny_unix_sockets(scmp_filter_ctx ctx);
int caged_deny_network_sockets(scmp_filter_ctx ctx);
int caged_deny_clone_namespaces(scmp_filter_ctx ctx);
int caged_deny_syscall_list(scmp_filter_ctx ctx, const char *const *names,
                            size_t n);
int caged_deny_sysv_ipc(scmp_filter_ctx ctx);
int caged_deny_dangerous_syscalls(scmp_filter_ctx ctx);
enum caged_return caged_apply_seccomp(int allow_unix_sockets,
                                      int allow_network_sockets,
                                      int allow_sysv_ipc, int tsync);

/* The namespaces the command can be given. */
extern const char *caged_base_env[];

#define CAGED_BASE_ENV_N (sizeof caged_base_env / sizeof caged_base_env[0])

int caged_push_env_entry(char ***list, int *n, int *cap, const char *entry);
size_t caged_env_name_len(const char *entry);
int caged_env_same_name(const char *entry, const char *name, size_t name_len);
int caged_env_is_base(const char *entry);
int caged_env_overridden(const char *entry, const struct caged_opts *opts);
char **caged_build_env(const struct caged_opts *opts);
void caged_replace_environ(char **env);

int caged_write_file(const char *path, const char *text);
int caged_write_id_map(const char *path, unsigned int id);
int caged_loopback_up(void);
int caged_drop_capabilities(void);
enum caged_return caged_setup_userns(void);
enum caged_return caged_setup_mountns(void);
int caged_mount_tmpfs(const char *target);
enum caged_return caged_setup_private_tmp(const char *src);
enum caged_return caged_setup_private_shm(void);
enum caged_return caged_setup_netns(void);
enum caged_return caged_setup_namespaces(int private_tmp,
                                         const char *private_tmp_src,
                                         int private_shm, int loopback_only);

/* Steps of the setup that do not belong to a single subsystem. */
int caged_set_limit(int resource, rlim_t value);
int caged_apply_rlimits(long max_procs);
int caged_close_inherited_fds(int report_fd);
int caged_abi_satisfies(long abi, long require);

#endif
