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
  The environment of the command: what is inherited by default, what --env
  overrides and how the process environment is replaced.
*/

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "caged_internal.h"

/*
  Environment variables that will be inherited by default.
*/
const char *caged_base_env[] = {
    "PATH",           "HOME",           "LANG",
    "LANGUAGE",       "LC_ALL",         "LC_CTYPE",
    "LC_NUMERIC",     "LC_TIME",        "LC_COLLATE",
    "LC_MONETARY",    "LC_MESSAGES",    "LC_PAPER",
    "LC_NAME",        "LC_ADDRESS",     "LC_TELEPHONE",
    "LC_MEASUREMENT", "LC_IDENTIFICATION",
};

/*
  Appends `entry` to a dynamic list of environment strings, growing the
  backing array (doubling its capacity) when it is full. Returns 0 on
  success, -1 on allocation failure.
*/
int caged_push_env_entry(char ***list, int *n, int *cap, const char *entry) {
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

/* Length of the NAME part of a NAME=VALUE entry. */
size_t caged_env_name_len(const char *entry) {
  const char *eq = strchr(entry, '=');
  return eq == NULL ? strlen(entry) : (size_t)(eq - entry);
}

/* True when `entry`'s name is exactly the `name_len` bytes of `name`. */
int caged_env_same_name(const char *entry, const char *name, size_t name_len) {
  return caged_env_name_len(entry) == name_len &&
         strncmp(entry, name, name_len) == 0;
}

/* True when `entry` is one of the variables inherited by default. */
int caged_env_is_base(const char *entry) {
  for (size_t k = 0; k < CAGED_BASE_ENV_N; k++) {
    if (caged_env_same_name(entry, caged_base_env[k],
                            strlen(caged_base_env[k]))) {
      return 1;
    }
  }
  return 0;
}

/* True when `entry` is overridden by one of the opts' env entries. */
int caged_env_overridden(const char *entry, const struct caged_opts *opts) {
  for (int k = 0; k < opts->n_env; k++) {
    if (caged_env_same_name(entry, opts->env[k],
                            caged_env_name_len(opts->env[k]))) {
      return 1;
    }
  }
  return 0;
}

/*
  Builds the environment variables. The default base, or
  everything inherited with keep_env and the env values.
  Returns a NULL-terminated array, or NULL on allocation failure.
*/
char **caged_build_env(const struct caged_opts *opts) {
  char **env = NULL;
  int n = 0;
  int cap = 0;
  int failed = 0;

  if (environ != NULL) {
    for (char **e = environ; *e != NULL; e++) {
      if (!opts->keep_env && !caged_env_is_base(*e)) {
        continue;
      }
      if (caged_env_overridden(*e, opts)) {
        continue;
      }
      failed |= caged_push_env_entry(&env, &n, &cap, *e) < 0;
    }
  }
  for (int k = 0; k < opts->n_env; k++) {
    failed |= caged_push_env_entry(&env, &n, &cap, opts->env[k]) < 0;
  }
  failed |= caged_push_env_entry(&env, &n, &cap, NULL) < 0;
  if (failed) {
    free(env);
    return NULL;
  }
  return env;
}

/*
  Replaces the process environment with the given entries. Anything not in
  `env` is dropped from environ, so every child of this process starts with
  the allowed variables only.
*/
void caged_replace_environ(char **env) {
  clearenv();
  for (int k = 0; env[k] != NULL; k++) {
    const char *eq = strchr(env[k], '=');
    if (eq == NULL) {
      setenv(env[k], "", 1);
      continue;
    }
    char *name = strndup(env[k], (size_t)(eq - env[k]));
    if (name != NULL) {
      setenv(name, eq + 1, 1);
      free(name);
    }
  }
}
