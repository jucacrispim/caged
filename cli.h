/*
  Command-line front end, shared by main.c and the unit tests.

  Nothing here belongs to the library: these helpers exist to turn argv into
  a struct cmd_opts, to print the usage and to warn about the kernel ABI. The
  sandbox and the command environment are in caged.h / caged.c.
*/

#ifndef CAGED_CLI_H
#define CAGED_CLI_H

#include <stdio.h>

#include "caged.h"

/* Parses argv into opts. Returns 0 on success, -1 on a usage error. */
int parse_cmd_line(int argc, char *argv[], struct cmd_opts *opts);

/* Prints the command usage to the given stream. */
void print_help(FILE *out);

/*
  Writes one diagnostic line (no trailing newline needed) to stderr and, when
  fd is a report descriptor (>= 3, see --report-fd), to that descriptor too.

  The descriptor is what makes caged's own failures unambiguous: the exit
  status space is shared with the command, so no status can be reserved. A
  caller that passed --report-fd and got nothing back knows the failure, if
  any, was the command's.
*/
void report_line(int fd, const char *line);

/*
  Warns on stderr about every Landlock feature the running kernel cannot
  support because its ABI is older than the one that introduced it. This is
  only a warning, not an error: caged still runs with the features that are
  available. CAGED_DISABLE_WARNINGS=1 silences it.

  Called after caged_setup, which replaces environ with the allowed set: to
  keep the switch usable, the value is read before the environment is
  replaced (see caged.h) and the ABI comes from abi_found.
*/
void warn_unsupported_features(long abi);

#endif
