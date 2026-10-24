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
  Command-line front end: argument parsing, usage text and ABI warnings.
  None of this is part of the sandbox; caged.c holds the library, the
  environment included.
*/

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cli.h"

/* These feature stuff are used by the warning messages about
   landlock features not supported by the hosts ABI
*/
struct feature {
  long min_abi;
  const char *name;
};

static const struct feature FEATURES[] = {
    {4, "network access control"},
    {5, "ioctl on device files"},
    {6, "IPC scopes"},
    {7, "restrict-self log flags"},
    {8, "restrict-self TSYNC"},
    {9, "UNIX socket name resolution"},
};

static int fatal(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  return -1;
}

/* Prints the command usage to the given stream. */
void print_help(FILE *out) {
  fprintf(
      out,
      "usage: caged [OPTIONS] -- CMD [ARGS...]\n"
      "\n"
      "Run CMD in a Landlock sandbox. Filesystem, network and IPC access\n"
      "is denied by default; only what is explicitly allowed is "
      "reachable.\n"
      "\n"
      "Options:\n"
      "  --ro PATH                      allow reading PATH (file or "
      "directory)\n"
      "  --rw PATH                      allow reading and writing PATH\n"
      "  --allow-connect-port PORT      allow TCP connect to PORT (0 = "
      "ephemeral)\n"
      "  --allow-bind-port PORT         allow TCP bind to PORT (0 = "
      "ephemeral)\n"
      "  --allow-connect-tcp            allow TCP connect to any port\n"
      "  --allow-bind-tcp               allow TCP bind to any port\n"
      "  --allow-scoped-signal          allow signalling outside the "
      "sandbox\n"
      "  --allow-scoped-abstract-unix   allow abstract unix socket "
      "connects\n"
      "  --log-same-exec-off            no audit log before execve (ABI >= "
      "7)\n"
      "  --log-new-exec-on              audit log after execve (ABI >= 7)\n"
      "  --log-subdomains-off           no audit log for subdomains (ABI >= "
      "7)\n"
      "  --tsync                        apply the sandbox to all threads "
      "(ABI >= 8)\n"
      "  --allow-unix-sockets           allow AF_UNIX sockets (IPC)\n"
      "  --allow-network-sockets        allow AF_INET, AF_INET6, AF_NETLINK\n"
      "  --allow-sysv-ipc               allow System V IPC (shm, msg, sem)\n"
      "  --max-procs N                  set RLIMIT_NPROC to N (default: no "
      "limit)\n"
      "  --require-abi N                fail unless Landlock ABI >= N\n"
      "  --keep-env                     keep the inherited environment\n"
      "  --env NAME=VALUE               set NAME in the command's "
      "environment\n"
      "  -h, --help                     show this help and exit\n"
      "\n"
      "Environment:\n"
      "  CAGED_DISABLE_WARNINGS=1       silence kernel ABI compatibility "
      "warnings\n");
}

/*
  Warns on stderr about every feature the running kernel cannot support
  because its Landlock ABI is older than the one that introduced it. This is
  only a warning, not an error: caged still runs with the features that are
  available.
*/
void warn_unsupported_features(long abi) {
  if (caged_warnings_disabled) {
    return;
  }
  size_t n = sizeof FEATURES / sizeof FEATURES[0];
  int warned = 0;
  for (size_t k = 0; k < n; k++) {
    if (FEATURES[k].min_abi > abi) {
      if (!warned) {
        fprintf(stderr,
                "caged: warning: Landlock ABI %ld does not support some "
                "features; they are unavailable:\n",
                abi);
        warned = 1;
      }
      fprintf(stderr, "caged: warning:   - %s (needs ABI %ld)\n",
              FEATURES[k].name, FEATURES[k].min_abi);
    }
  }
}

/*
  Appends `path` to a dynamic list, growing the backing array (doubling its
  capacity) when it is full. Returns 0 on success, -1 on allocation failure.
*/
static int push_path(const char ***list, int *n, int *cap, const char *path) {
  if (*n == *cap) {
    int new_cap = *cap ? *cap * 2 : 4;
    const char **grown =
        realloc((void *)*list, (size_t)new_cap * sizeof **list);
    if (grown == NULL) {
      return -1;
    }
    *list = grown;
    *cap = new_cap;
  }
  (*list)[(*n)++] = path;
  return 0;
}

/*
  Parses a decimal port number into `out`. Returns 0 on success, -1 when the
  string is not a valid port in the 0..65535 range.
*/
static int parse_port(const char *s, unsigned short *out) {
  char *end;
  errno = 0;
  unsigned long v = strtoul(s, &end, 10);
  if (end == s || *end != '\0' || errno != 0 || v > 65535) {
    return -1;
  }
  *out = (unsigned short)v;
  return 0;
}

/*
  Parses a positive decimal into `out`. Returns 0 on success, -1 when the
  string is not a positive integer.
*/
static int parse_positive(const char *s, long *out) {
  char *end;
  errno = 0;
  long v = strtol(s, &end, 10);
  if (end == s || *end != '\0' || errno != 0 || v <= 0) {
    return -1;
  }
  *out = v;
  return 0;
}

/*
  Appends `port` to a dynamic list, growing the backing array (doubling its
  capacity) when it is full. Returns 0 on success, -1 on allocation failure.
*/
static int push_port(unsigned short **list, int *n, int *cap,
                     unsigned short port) {
  if (*n == *cap) {
    int new_cap = *cap ? *cap * 2 : 4;
    unsigned short *grown = realloc(*list, (size_t)new_cap * sizeof **list);
    if (grown == NULL) {
      return -1;
    }
    *list = grown;
    *cap = new_cap;
  }
  (*list)[(*n)++] = port;
  return 0;
}

/*
  Appends `entry` to a dynamic list of environment strings, growing the
  backing array (doubling its capacity) when it is full. Returns 0 on
  success, -1 on allocation failure.
*/
static int push_env(char ***list, int *n, int *cap, const char *entry) {
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

int parse_cmd_line(int argc, char *argv[], struct cmd_opts *opts) {
  if (argc <= 1) {
    print_help(stderr);
    return -1;
  }
  int i = 1;
  while (argc > i) {
    if (strcmp(argv[i], "--ro") == 0) {
      if (i + 1 >= argc) {
        return fatal("--ro must have a value");
      }
      if (push_path(&opts->r_dir, &opts->n_r, &opts->cap_r, argv[i + 1]) < 0) {
        return fatal("out of memory");
      }
      i += 2;
    } else if (strcmp(argv[i], "--rw") == 0) {
      if (i + 1 >= argc) {
        return fatal("--rw must have a value");
      }
      if (push_path(&opts->rw_dir, &opts->n_rw, &opts->cap_rw, argv[i + 1]) <
          0) {
        return fatal("out of memory");
      }
      i += 2;
    } else if (strcmp(argv[i], "--allow-scoped-signal") == 0) {
      opts->released_scopes |= LANDLOCK_SCOPE_SIGNAL;
      i += 1;
    } else if (strcmp(argv[i], "--allow-scoped-abstract-unix") == 0) {
      opts->released_scopes |= LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
      i += 1;
    } else if (strcmp(argv[i], "--log-same-exec-off") == 0) {
      opts->restrict_flags |= LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF;
      i += 1;
    } else if (strcmp(argv[i], "--log-new-exec-on") == 0) {
      opts->restrict_flags |= LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;
      i += 1;
    } else if (strcmp(argv[i], "--log-subdomains-off") == 0) {
      opts->restrict_flags |= LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF;
      i += 1;
    } else if (strcmp(argv[i], "--tsync") == 0) {
      opts->restrict_flags |= LANDLOCK_RESTRICT_SELF_TSYNC;
      i += 1;
    } else if (strcmp(argv[i], "--allow-unix-sockets") == 0) {
      opts->allow_unix_sockets = 1;
      i += 1;
    } else if (strcmp(argv[i], "--allow-network-sockets") == 0) {
      opts->allow_network_sockets = 1;
      i += 1;
    } else if (strcmp(argv[i], "--allow-sysv-ipc") == 0) {
      opts->allow_sysv_ipc = 1;
      i += 1;
    } else if (strcmp(argv[i], "--max-procs") == 0) {
      if (i + 1 >= argc) {
        return fatal("--max-procs must have a value");
      }
      if (parse_positive(argv[i + 1], &opts->max_procs) < 0) {
        return fatal("--max-procs must be a positive number");
      }
      i += 2;
    } else if (strcmp(argv[i], "--require-abi") == 0) {
      if (i + 1 >= argc) {
        return fatal("--require-abi must have a value");
      }
      if (parse_positive(argv[i + 1], &opts->require_abi) < 0) {
        return fatal("--require-abi must be a positive number");
      }
      i += 2;
    } else if (strcmp(argv[i], "--keep-env") == 0) {
      opts->keep_env = 1;
      i += 1;
    } else if (strcmp(argv[i], "--env") == 0) {
      if (i + 1 >= argc) {
        return fatal("--env must have a value");
      }
      if (strchr(argv[i + 1], '=') == NULL || argv[i + 1][0] == '=') {
        return fatal("--env must have the form NAME=VALUE");
      }
      if (push_env(&opts->env, &opts->n_env, &opts->cap_env, argv[i + 1]) < 0) {
        return fatal("out of memory");
      }
      i += 2;
    } else if (strcmp(argv[i], "--allow-connect-tcp") == 0) {
      if (opts->n_connect > 0) {
        return fatal("--allow-connect-tcp conflicts with --allow-connect-port");
      }
      opts->released_net |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
      i += 1;
    } else if (strcmp(argv[i], "--allow-bind-tcp") == 0) {
      if (opts->n_bind > 0) {
        return fatal("--allow-bind-tcp conflicts with --allow-bind-port");
      }
      opts->released_net |= LANDLOCK_ACCESS_NET_BIND_TCP;
      i += 1;
    } else if (strcmp(argv[i], "--allow-connect-port") == 0) {
      unsigned short port;
      if (i + 1 >= argc) {
        return fatal("--allow-connect-port must have a value");
      }
      if (opts->released_net & LANDLOCK_ACCESS_NET_CONNECT_TCP) {
        return fatal("--allow-connect-port conflicts with --allow-connect-tcp");
      }
      if (parse_port(argv[i + 1], &port) < 0) {
        return fatal("--allow-connect-port must be a port number (0..65535)");
      }
      if (push_port(&opts->connect_ports, &opts->n_connect, &opts->cap_connect,
                    port) < 0) {
        return fatal("out of memory");
      }
      i += 2;
    } else if (strcmp(argv[i], "--allow-bind-port") == 0) {
      unsigned short port;
      if (i + 1 >= argc) {
        return fatal("--allow-bind-port must have a value");
      }
      if (opts->released_net & LANDLOCK_ACCESS_NET_BIND_TCP) {
        return fatal("--allow-bind-port conflicts with --allow-bind-tcp");
      }
      if (parse_port(argv[i + 1], &port) < 0) {
        return fatal("--allow-bind-port must be a port number (0..65535)");
      }
      if (push_port(&opts->bind_ports, &opts->n_bind, &opts->cap_bind, port) <
          0) {
        return fatal("out of memory");
      }
      i += 2;
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      opts->help = 1;
      return 0;
    } else if (strcmp(argv[i], "--") == 0) {
      if (i + 1 >= argc) {
        return fatal("missing command after --");
      }
      i++;
      opts->cmd = &argv[i];
      return 0;
    } else {
      return fatal("unknown option (use --help)");
    }
  }
  return fatal("missing command (use -- cmd)");
}
