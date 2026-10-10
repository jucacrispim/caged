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

#define MAX_PATHS 32
/* fs access handled by the latest api */
#define FS_HANDLED                                                             \
  (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |                \
   LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |                \
   LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |            \
   LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |                \
   LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |                \
   LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |              \
   LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |                    \
   LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV)

#define PERMS_READ                                                             \
  (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |                \
   LANDLOCK_ACCESS_FS_EXECUTE)

#define PERMS_READ_WRITE                                                       \
  (PERMS_READ | LANDLOCK_ACCESS_FS_WRITE_FILE |                                \
   LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |            \
   LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |                 \
   LANDLOCK_ACCESS_FS_TRUNCATE)

/* fs access only relevant for directories */
#define PERMS_DIRS_ONLY                                                        \
  (LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |               \
   LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR |              \
   LANDLOCK_ACCESS_FS_MAKE_REG)

enum caged_return {
  CAGED_OK = 0,
  CAGED_ERR_NO_LANDLOCK,
  CAGED_ERR_CREATE_RULESET,
  CAGED_ERR_READ_ACCESS,
  CAGED_ERR_RW_ACCESS,
  CAGED_ERR_RESTRICT_SELF,
};

struct cmd_opts {
  const char *r_dir[MAX_PATHS];
  int n_r;
  const char *rw_dir[MAX_PATHS];
  int n_rw;
  char **cmd;
};

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
static int restrict_self(int ruleset_fd) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    return -1;
  }
  return syscall(SYS_landlock_restrict_self, ruleset_fd, 0);
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
  return handled;
}

static int get_perms_read_write(long abi) {
  int perms = PERMS_READ_WRITE;
  if (abi < 3) {
    perms &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
  }
  return perms;
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

static int parse_cmd_line(int argc, char *argv[], struct cmd_opts *opts) {
  int i = 1;
  while (argc > i) {
    if (strcmp(argv[i], "--ro") == 0) {
      if (i + 1 >= argc) {
        return fatal("--ro must have a value");
      }
      if (opts->n_r >= MAX_PATHS) {
        return fatal("too many ro dirs");
      }
      opts->r_dir[opts->n_r++] = argv[i + 1];
      i += 2;
    } else if (strcmp(argv[i], "--rw") == 0) {
      if (i + 1 >= argc) {
        return fatal("--rw must have a value");
      }
      if (opts->n_rw >= MAX_PATHS) {
        return fatal("too many rw dirs");
      }
      opts->rw_dir[opts->n_rw++] = argv[i + 1];
      i += 2;
    } else if (strcmp(argv[i], "--") == 0) {
      if (i + 1 >= argc) {
        return fatal("missing command after --");
      }
      i++;
      opts->cmd = &argv[i];
      return 0;
    } else {
      return fatal("unknown option");
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
  int handled = get_handled_access_fs(abi);
  struct landlock_ruleset_attr r_perm = {.handled_access_fs = handled};

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
  if (restrict_self(ruleset) < 0) {
    return CAGED_ERR_RESTRICT_SELF;
  }
  return CAGED_OK;
}

/* GCOV_EXCL_START */
int main(int argc, char *argv[]) {
  struct cmd_opts opts = {0};

  if (parse_cmd_line(argc, argv, &opts) < 0) {
    return 2;
  }

  enum caged_return r = caged_setup(&opts);
  if (r != CAGED_OK) {
    die(caged_strreturn(r));
  }

  if (execvp(opts.cmd[0], opts.cmd) < 0) {
    die("error execvp");
  }
  return 1;
}
/* GCOV_EXCL_STOP */
