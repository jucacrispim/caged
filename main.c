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
  Command-line front end. It parses argv, asks caged_setup to build the
  sandbox and then replaces the process image with the command. The sandbox
  itself lives in caged.c; see caged.h for the interface.
*/

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "caged.h"
#include "cli.h"

/*
  Exit status 125 means "caged itself failed": the sandbox could not be built
  or the command could not be executed. 2 is the usage error and 125 is the
  sh/docker/sudo convention for "the wrapper failed".

  Neither status can ever be reserved, though: the command shares them, and a
  command may legitimately exit with 2 or 125. The proof is --report-fd, the
  descriptor report_line() writes every diagnostic of ours to (and nothing
  when the setup succeeded), so a wrapper that passed it never has to guess.
*/
#define EXIT_SETUP_FAILED 125

/* GCOV_EXCL_START */
static void die(int fd, const char *msg) {
  char line[512];
  snprintf(line, sizeof line, "%s: %s", msg, strerror(errno));
  report_line(fd, line);
  exit(EXIT_SETUP_FAILED);
}
/* GCOV_EXCL_STOP */

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

  char **envp = NULL;
  enum caged_return r = caged_setup(&opts, &envp);
  if (r != CAGED_OK) {
    char line[512];
    if (seccomp_detail < -1) {
      errno = -seccomp_detail;
    }
    if (seccomp_failed_family >= 0) {
      snprintf(line, sizeof line, "caged: socket family %d",
               seccomp_failed_family);
      report_line(opts.report_fd, line);
    }
    if (seccomp_failed_syscall != NULL) {
      snprintf(line, sizeof line, "caged: syscall %s", seccomp_failed_syscall);
      report_line(opts.report_fd, line);
    }
    if (r == CAGED_ERR_ABI_TOO_OLD) {
      snprintf(line, sizeof line, "caged: Landlock ABI %ld, %ld required",
               abi_found, opts.require_abi);
      report_line(opts.report_fd, line);
    }
    die(opts.report_fd, caged_strreturn(r));
  }

  /* The library does not print: the warnings about what the kernel ABI
     cannot support are the front end's job, on the successful path only.
     caged_setup already replaced environ, so it recorded the
     CAGED_DISABLE_WARNINGS switch before doing that. */
  warn_unsupported_features(abi_found);

  cmd_opts_free(&opts);
  /* execvpe searches for the binary with the *caller's* PATH, not with envp,
     so a cleared environment does not stop "caged -- sh" from finding sh. */
  if (execvpe(opts.cmd[0], opts.cmd, envp) < 0) {
    die(opts.report_fd, "error execvpe");
  }
  return EXIT_SETUP_FAILED;
}
/* GCOV_EXCL_STOP */
