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
  Public interface of caged.

  `caged_setup` is the entry point for embedding caged in another program:
  call it with the options the sandbox should have and it locks the calling
  process (and its future children) in place. The command-line front end
  (main.c) additionally uses the parsing and environment helpers declared at
  the bottom of this header.
*/

#ifndef CAGED_H
#define CAGED_H

#include <linux/landlock.h>
#include <stdio.h>

/*
  These LANDLOCK_* definitions are here because they are not defined in my
  current system. They live in the public header because both the library and
  the command-line front end need them: the library to compute the handled
  masks, the front end to fill struct cmd_opts.
 */
#ifndef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX (1ULL << 16)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF
#define LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF (1ULL << 0)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
#define LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON (1ULL << 1)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF
#define LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF (1ULL << 2)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_TSYNC
#define LANDLOCK_RESTRICT_SELF_TSYNC (1ULL << 3)
#endif

enum caged_return {
  CAGED_OK = 0,
  CAGED_ERR_NO_LANDLOCK,
  CAGED_ERR_ABI_TOO_OLD,
  CAGED_ERR_CREATE_RULESET,
  CAGED_ERR_READ_ACCESS,
  CAGED_ERR_RW_ACCESS,
  CAGED_ERR_CONNECT_ACCESS,
  CAGED_ERR_BIND_ACCESS,
  CAGED_ERR_RESTRICT_SELF,
  CAGED_ERR_RLIMIT,
  CAGED_ERR_CLOSE_FDS,
  CAGED_ERR_SECCOMP_INIT,
  CAGED_ERR_SECCOMP_FAMILIES,
  CAGED_ERR_SECCOMP_INET_RAW,
  CAGED_ERR_SECCOMP_NETLINK,
  CAGED_ERR_SECCOMP_UNIX,
  CAGED_ERR_SECCOMP_NETWORK,
  CAGED_ERR_SECCOMP_SYSVIPC,
  CAGED_ERR_SECCOMP_SYSCALLS,
  CAGED_ERR_SECCOMP_LOAD,
};

struct cmd_opts {
  const char **r_dir;
  int n_r;
  int cap_r;
  const char **rw_dir;
  int n_rw;
  int cap_rw;
  unsigned long released_scopes;
  unsigned long released_net;
  unsigned long restrict_flags;
  unsigned short *connect_ports;
  int n_connect;
  int cap_connect;
  unsigned short *bind_ports;
  int n_bind;
  int cap_bind;
  int allow_unix_sockets;
  int allow_network_sockets;
  int allow_sysv_ipc;
  long max_procs;
  long require_abi;
  int keep_env;
  char **env;
  int n_env;
  int cap_env;
  char **cmd;
  int help;
};

/*
  Diagnostics of the last caged_setup call.

  `seccomp_detail` holds the error libseccomp returned, `seccomp_failed_family`
  the socket family that a rule could not be added for and
  `seccomp_failed_syscall` the syscall name that a rule could not be added for.
  `abi_found` holds the Landlock ABI version the kernel reported. They exist so
  the caller knows which error happened and what it was about.
*/
extern int seccomp_detail;
extern int seccomp_failed_family;
extern const char *seccomp_failed_syscall;
extern long abi_found;

/* Human-readable message for a return code. */
const char *caged_strreturn(enum caged_return r);

/*
  Creates the sandbox. If the return is not CAGED_OK the process must be
  terminated with an error; use caged_strreturn for a sane message.
*/
enum caged_return caged_setup(const struct cmd_opts *opts);

/* Releases the memory held by the lists of a cmd_opts. */
void cmd_opts_free(struct cmd_opts *opts);

/*
  Command-line front-end helpers, used by main.c. They are declared here
  because they share struct cmd_opts with the library part.
*/

/* Parses argv into opts. Returns 0 on success, -1 on a usage error. */
int parse_cmd_line(int argc, char *argv[], struct cmd_opts *opts);

/* Prints the command usage to the given stream. */
void print_help(FILE *out);

/*
  Builds the environment variables for the command: the default base, or
  everything inherited with --keep-env, plus the --env values. Returns a
  NULL-terminated array, or NULL on allocation failure.
*/
char **build_env(const struct cmd_opts *opts);

#endif
