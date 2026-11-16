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
  Helpers of the command-line front end that the unit tests drive directly.
  They are not part of anything an embedder should call: the public CLI
  surface is in cli.h.
*/

#ifndef CAGED_CLI_INTERNAL_H
#define CAGED_CLI_INTERNAL_H

#include "caged.h"
#include "cli.h"

/* Appends `path` to a dynamic list of paths. 0 on success, -1 on OOM. */
int caged_push_path(const char ***list, int *n, int *cap, const char *path);

/* Parses a decimal port into `out`. 0 on success, -1 outside 0..65535. */
int caged_parse_port(const char *s, unsigned short *out);

/* Parses a positive decimal into `out`. 0 on success, -1 otherwise. */
int caged_parse_positive(const char *s, long *out);

/* Appends `port` to a dynamic list. 0 on success, -1 on OOM. */
int caged_push_port(unsigned short **list, int *n, int *cap,
                    unsigned short port);

/* Appends `entry` to a dynamic list. 0 on success, -1 on OOM. */
int caged_push_env(char ***list, int *n, int *cap, const char *entry);

#endif
