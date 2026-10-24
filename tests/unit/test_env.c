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

#define main caged_program_main
#include "../../caged.c"
#undef main
#include "fake_syscalls.h"
#include <assert.h>

/* Number of entries in a NULL-terminated env array. */
static int env_len(char **env) {
  int n = 0;

  assert(env != NULL);
  while (env[n] != NULL) {
    n++;
  }
  return n;
}

/* How many entries of `env` carry the given NAME. */
static int env_count(char **env, const char *name) {
  int n = 0;
  size_t len = strlen(name);

  for (int k = 0; env[k] != NULL; k++) {
    if (env_name_len(env[k]) == len && strncmp(env[k], name, len) == 0) {
      n++;
    }
  }
  return n;
}

/* Value of NAME in `env`, or NULL when it is absent. */
static const char *env_value(char **env, const char *name) {
  size_t len = strlen(name);

  for (int k = 0; env[k] != NULL; k++) {
    if (env_name_len(env[k]) == len && strncmp(env[k], name, len) == 0) {
      return env[k] + len + 1;
    }
  }
  return NULL;
}

static void clear_environ(void) { assert(clearenv() == 0); }

/* Makes the fake kernel good enough for caged_setup to reach the env step. */
static void setup_fake(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;
}

/* Runs caged_setup and returns the env it built. */
static char **run_setup(const struct cmd_opts *opts) {
  char **env = (char **)&env;
  setup_fake();
  assert(caged_setup(opts, &env) == CAGED_OK);
  return env;
}

/* Pushes a NAME=VALUE into opts.env, as the parser would. */
static void add_env(struct cmd_opts *opts, const char *entry) {
  assert(push_env_entry(&opts->env, &opts->n_env, &opts->cap_env, entry) == 0);
}

/* The default is a closed base: PATH/HOME/LANG/LC_* survive, anything else
   (credentials included) does not. */
void test_default_keeps_only_base(void) {
  clear_environ();
  assert(setenv("PATH", "/usr/bin:/bin", 1) == 0);
  assert(setenv("HOME", "/home/juca", 1) == 0);
  assert(setenv("LANG", "pt_BR.UTF-8", 1) == 0);
  assert(setenv("LC_ALL", "pt_BR.UTF-8", 1) == 0);
  assert(setenv("LC_TELEPHONE", "pt_BR.UTF-8", 1) == 0);
  assert(setenv("DEEPSEEK_API_KEY", "secret", 1) == 0);
  assert(setenv("SSH_AUTH_SOCK", "/run/user/1000/agent", 1) == 0);

  struct cmd_opts opts = {0};
  char **env = run_setup(&opts);

  assert(env != NULL);
  assert(env_len(env) == 5);
  assert(strcmp(env_value(env, "PATH"), "/usr/bin:/bin") == 0);
  assert(strcmp(env_value(env, "HOME"), "/home/juca") == 0);
  assert(strcmp(env_value(env, "LANG"), "pt_BR.UTF-8") == 0);
  assert(strcmp(env_value(env, "LC_ALL"), "pt_BR.UTF-8") == 0);
  assert(env_count(env, "LC_TELEPHONE") == 1);
  assert(env_count(env, "DEEPSEEK_API_KEY") == 0);
  assert(env_count(env, "SSH_AUTH_SOCK") == 0);
  free(env);
  clear_environ();
}

/* The process environment is replaced: the variables that are not allowed
   are gone from environ too, not only from the returned array. */
void test_setup_clears_environ(void) {
  clear_environ();
  assert(setenv("PATH", "/usr/bin", 1) == 0);
  assert(setenv("DEEPSEEK_API_KEY", "secret", 1) == 0);

  struct cmd_opts opts = {0};
  char **env = run_setup(&opts);

  assert(getenv("DEEPSEEK_API_KEY") == NULL);
  assert(getenv("PATH") != NULL);
  assert(strcmp(getenv("PATH"), "/usr/bin") == 0);
  assert(env_count(env, "PATH") == 1);
  free(env);
  clear_environ();
}

/* --env values are installed in environ as well */
void test_setup_env_flag_reaches_environ(void) {
  clear_environ();
  assert(setenv("PATH", "/usr/bin", 1) == 0);

  struct cmd_opts opts = {0};
  add_env(&opts, "FOO=bar");
  char **env = run_setup(&opts);

  assert(strcmp(getenv("FOO"), "bar") == 0);
  assert(env_count(env, "FOO") == 1);
  free(env);
  cmd_opts_free(&opts);
  clear_environ();
}

/* with the caller not asking for the array, the environment is still
   replaced and nothing is leaked to it */
void test_setup_env_null_out(void) {
  clear_environ();
  assert(setenv("PATH", "/usr/bin", 1) == 0);
  assert(setenv("DEEPSEEK_API_KEY", "secret", 1) == 0);

  struct cmd_opts opts = {0};
  setup_fake();
  assert(caged_setup(&opts, NULL) == CAGED_OK);
  assert(getenv("DEEPSEEK_API_KEY") == NULL);
  assert(getenv("PATH") != NULL);
  clear_environ();
}

/* *env is set to NULL on every failure */
void test_setup_env_null_on_error(void) {
  clear_environ();
  reset_fake();
  fake.abi = -1;

  struct cmd_opts opts = {0};
  char **env = (char **)&env;
  assert(caged_setup(&opts, &env) == CAGED_ERR_NO_LANDLOCK);
  assert(env == NULL);
  clear_environ();
}

/* CAGED_ERR_ENV when the array cannot be allocated; environ is untouched */
void test_setup_env_out_of_memory(void) {
  clear_environ();
  assert(setenv("PATH", "/usr/bin", 1) == 0);

  struct cmd_opts opts = {0};
  char **env = (char **)&env;
  setup_fake();
  fake.fail_realloc = 1;
  fake.realloc_err = ENOMEM;

  assert(caged_setup(&opts, &env) == CAGED_ERR_ENV);
  assert(env == NULL);
  assert(strcmp(getenv("PATH"), "/usr/bin") == 0);
  clear_environ();
}

/* a failure allocating the copy of a NAME still lets the setup succeed: the
   entry is just not installed in environ */
void test_setup_env_name_alloc_failure(void) {
  clear_environ();
  assert(setenv("PATH", "/usr/bin", 1) == 0);

  struct cmd_opts opts = {0};
  char **env = (char **)&env;
  setup_fake();
  fake.fail_strndup = 1;
  fake.strndup_err = ENOMEM;

  assert(caged_setup(&opts, &env) == CAGED_OK);
  assert(env != NULL);
  assert(env_len(env) == 1);
  /* the entry could not be installed, but environ was still replaced */
  assert(getenv("PATH") == NULL);
  free(env);
  clear_environ();
}

/* CAGED_DISABLE_WARNINGS is recorded before environ is replaced */
void test_setup_records_warning_switch(void) {
  clear_environ();
  assert(setenv("PATH", "/usr/bin", 1) == 0);
  assert(setenv("CAGED_DISABLE_WARNINGS", "1", 1) == 0);

  struct cmd_opts opts = {0};
  char **env = run_setup(&opts);

  assert(caged_warnings_disabled == 1);
  /* and it is not inherited, since it is not part of the base */
  assert(getenv("CAGED_DISABLE_WARNINGS") == NULL);
  free(env);
  clear_environ();
}

/* any value other than "1" leaves the warnings enabled */
void test_setup_warning_switch_other_value(void) {
  clear_environ();
  assert(setenv("PATH", "/usr/bin", 1) == 0);
  assert(setenv("CAGED_DISABLE_WARNINGS", "0", 1) == 0);

  struct cmd_opts opts = {0};
  char **env = run_setup(&opts);

  assert(caged_warnings_disabled == 0);
  free(env);
  clear_environ();
}

/* A name that is not in the base table is dropped even when its length
   matches one (NOPE vs PATH). */
void test_default_drops_name_of_same_length(void) {
  clear_environ();
  assert(setenv("NOPE", "1", 1) == 0);

  struct cmd_opts opts = {0};
  char **env = run_setup(&opts);

  assert(env != NULL);
  assert(env_len(env) == 0);
  free(env);
  clear_environ();
}

/* keep_env inherits everything */
void test_keep_env_inherits_all(void) {
  clear_environ();
  assert(setenv("PATH", "/usr/bin", 1) == 0);
  assert(setenv("DEEPSEEK_API_KEY", "secret", 1) == 0);

  struct cmd_opts opts = {0};
  opts.keep_env = 1;
  char **env = run_setup(&opts);

  assert(env != NULL);
  assert(env_len(env) == 2);
  assert(strcmp(env_value(env, "DEEPSEEK_API_KEY"), "secret") == 0);
  free(env);
  clear_environ();
}

/* with no keep_env and no base variable the result is still a valid,
   empty (NULL-terminated) array */
void test_empty_environment(void) {
  clear_environ();

  struct cmd_opts opts = {0};
  char **env = run_setup(&opts);

  assert(env != NULL);
  assert(env_len(env) == 0);
  free(env);
}

/* --env alone adds to the base environment, which is still there */
void test_env_flag_alone(void) {
  clear_environ();
  assert(setenv("PATH", "/usr/bin", 1) == 0);

  struct cmd_opts opts = {0};
  add_env(&opts, "FOO=bar");
  char **env = run_setup(&opts);

  assert(env != NULL);
  assert(env_len(env) == 2);
  assert(strcmp(env_value(env, "PATH"), "/usr/bin") == 0);
  assert(strcmp(env_value(env, "FOO"), "bar") == 0);
  free(env);
  cmd_opts_free(&opts);
  clear_environ();
}

/* --env overrides an inherited variable by name, without duplicating it */
void test_env_flag_overrides_inherited(void) {
  clear_environ();
  assert(setenv("FOO", "old", 1) == 0);

  struct cmd_opts opts = {0};
  opts.keep_env = 1;
  add_env(&opts, "FOO=new");
  char **env = run_setup(&opts);

  assert(env != NULL);
  assert(env_len(env) == 1);
  assert(strcmp(env_value(env, "FOO"), "new") == 0);
  free(env);
  cmd_opts_free(&opts);
  clear_environ();
}

/* the override is by whole name: FOOBAR is a different variable */
void test_env_override_does_not_match_prefix(void) {
  clear_environ();
  assert(setenv("FOOBAR", "keep", 1) == 0);
  assert(setenv("FOO", "old", 1) == 0);

  struct cmd_opts opts = {0};
  opts.keep_env = 1;
  add_env(&opts, "FOO=new");
  char **env = run_setup(&opts);

  assert(env != NULL);
  assert(env_len(env) == 2);
  assert(strcmp(env_value(env, "FOOBAR"), "keep") == 0);
  assert(strcmp(env_value(env, "FOO"), "new") == 0);
  free(env);
  cmd_opts_free(&opts);
  clear_environ();
}

/* the list grows by doubling, so more entries than the initial capacity work
   and the order is preserved */
void test_env_list_grows(void) {
  clear_environ();
  for (int k = 0; k < 10; k++) {
    char name[16];
    snprintf(name, sizeof name, "V%d", k);
    assert(setenv(name, "x", 1) == 0);
  }

  struct cmd_opts opts = {0};
  opts.keep_env = 1;
  char **env = run_setup(&opts);

  assert(env != NULL);
  assert(env_len(env) == 10);
  free(env);
  clear_environ();
}

/* an entry without '=' is installed with an empty value instead of being
   skipped */
void test_setup_env_without_equals(void) {
  clear_environ();

  struct cmd_opts opts = {0};
  add_env(&opts, "NOEQ");
  char **env = run_setup(&opts);

  assert(env_count(env, "NOEQ") == 1);
  assert(getenv("NOEQ") != NULL);
  assert(strcmp(getenv("NOEQ"), "") == 0);
  free(env);
  cmd_opts_free(&opts);
  clear_environ();
}

/* the name of an entry ends at '=' and the whole string when there is none */
void test_env_name_len(void) {
  assert(env_name_len("FOO=bar") == 3);
  assert(env_name_len("PATH=") == 4);
  assert(env_name_len("NOEQ") == 4);
}

/* the base table is the documented set: no wildcard, so a new LC_* name is
   not inherited until it is added here */
void test_base_env_table(void) {
  assert(env_is_base("PATH=/usr/bin"));
  assert(env_is_base("HOME=/home/juca"));
  assert(env_is_base("LANG=pt_BR.UTF-8"));
  assert(env_is_base("LANGUAGE=pt_BR:en"));
  assert(env_is_base("LC_ALL=C"));
  assert(env_is_base("LC_IDENTIFICATION=C"));
  assert(!env_is_base("LC_UNKNOWN_CATEGORY=C"));
  assert(!env_is_base("FOO=bar"));
}

int main(void) {
  test_default_keeps_only_base();
  test_setup_clears_environ();
  test_setup_env_flag_reaches_environ();
  test_setup_env_null_out();
  test_setup_env_null_on_error();
  test_setup_env_out_of_memory();
  test_setup_env_name_alloc_failure();
  test_setup_records_warning_switch();
  test_setup_warning_switch_other_value();
  test_default_drops_name_of_same_length();
  test_keep_env_inherits_all();
  test_empty_environment();
  test_env_flag_alone();
  test_env_flag_overrides_inherited();
  test_env_override_does_not_match_prefix();
  test_env_list_grows();
  test_setup_env_without_equals();
  test_env_name_len();
  test_base_env_table();

  printf("OK\n");
  return 0;
}
