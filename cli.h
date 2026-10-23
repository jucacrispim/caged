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
  Command-line front end, shared by main.c and the unit tests.

  Nothing here belongs to the library: these helpers exist to turn argv into
  a struct cmd_opts, to print the usage and to build the command's
  environment. The sandbox itself is in caged.h / caged.c.
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
  Warns on stderr about every Landlock feature the running kernel cannot
  support because its ABI is older than the one that introduced it. This is
  only a warning, not an error: caged still runs with the features that are
  available. CAGED_DISABLE_WARNINGS=1 silences it.
*/
void warn_unsupported_features(long abi);

/*
  Builds the environment variables for the command: the default base, or
  everything inherited with --keep-env, plus the --env values. Returns a
  NULL-terminated array, or NULL on allocation failure.
*/
char **build_env(const struct cmd_opts *opts);

#endif
