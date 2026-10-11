#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
  These LANDLOCK_* definitions are here because they are not
  defined in my current system. So I define them here in order
  to be able to write/compile code that supports these without
  having them on my system.
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

enum caged_return {
  CAGED_OK = 0,
  CAGED_ERR_NO_LANDLOCK,
  CAGED_ERR_CREATE_RULESET,
  CAGED_ERR_READ_ACCESS,
  CAGED_ERR_RW_ACCESS,
  CAGED_ERR_CONNECT_ACCESS,
  CAGED_ERR_BIND_ACCESS,
  CAGED_ERR_RESTRICT_SELF,
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
  char **cmd;
  int help;
};

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

/* Releases the memory held by the lists of a cmd_opts. */
static void cmd_opts_free(struct cmd_opts *opts) {
  free((void *)opts->r_dir);
  free((void *)opts->rw_dir);
  free(opts->connect_ports);
  free(opts->bind_ports);
  opts->r_dir = NULL;
  opts->rw_dir = NULL;
  opts->connect_ports = NULL;
  opts->bind_ports = NULL;
  opts->n_r = 0;
  opts->n_rw = 0;
  opts->n_connect = 0;
  opts->n_bind = 0;
  opts->cap_r = 0;
  opts->cap_rw = 0;
  opts->cap_connect = 0;
  opts->cap_bind = 0;
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

static long check_abi() {
  return syscall(SYS_landlock_create_ruleset, NULL, 0,
                 LANDLOCK_CREATE_RULESET_VERSION);
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

/* A feature implemented by caged and the Landlock ABI that introduced it. */
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

/*
  Warns on stderr about every feature the running kernel cannot support
  because its Landlock ABI is older than the one that introduced it. This is
  only a warning, not an error: caged still runs with the features that are
  available.
*/
static void warn_unsupported_features(long abi) {
  const char *disable = getenv("CAGED_DISABLE_WARNINGS");
  if (disable != NULL && strcmp(disable, "1") == 0) {
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

static const char *caged_strreturn(enum caged_return r) {
  switch (r) {
  case CAGED_OK:
    return "ok";
  case CAGED_ERR_NO_LANDLOCK:
    return "Landlock not supported";
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
  }
  return "unknown error";
}

/* GCOV_EXCL_START */
static void die(const char *msg) {
  fprintf(stderr, "%s: %s\n", msg, strerror(errno));
  exit(1);
}
/* GCOV_EXCL_STOP */

static int fatal(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  return -1;
}

/* Prints the command usage to the given stream. */
static void print_help(FILE *out) {
  fprintf(out, "usage: caged [OPTIONS] -- CMD [ARGS...]\n"
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
         "  -h, --help                     show this help and exit\n"
         "\n"
         "Environment:\n"
         "  CAGED_DISABLE_WARNINGS=1       silence kernel ABI compatibility "
         "warnings\n");
}

static int parse_cmd_line(int argc, char *argv[], struct cmd_opts *opts) {
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

/*
  Creates the sandbox. If return != CAGED_OK the process must be terminated
  with an error.

  Use caged_strreturn for a sane message.
*/
static enum caged_return caged_setup(const struct cmd_opts *opts) {
  long abi = check_abi();
  if (abi < 1) {
    return CAGED_ERR_NO_LANDLOCK;
  }
  warn_unsupported_features(abi);
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
  return CAGED_OK;
}

/* GCOV_EXCL_START */
int main(int argc, char *argv[]) {
  struct cmd_opts opts = {0};

  if (parse_cmd_line(argc, argv, &opts) < 0) {
    cmd_opts_free(&opts);
    return 2;
  }

  if (opts.help) {
    print_help(stdout);
    cmd_opts_free(&opts);
    return 0;
  }

  enum caged_return r = caged_setup(&opts);
  if (r != CAGED_OK) {
    die(caged_strreturn(r));
  }

  cmd_opts_free(&opts);
  if (execvp(opts.cmd[0], opts.cmd) < 0) {
    die("error execvp");
  }
  return 1;
}
/* GCOV_EXCL_STOP */
