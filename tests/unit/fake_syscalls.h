#ifndef FAKE_SYSCALL_H
#define FAKE_SYSCALL_H
#include <stddef.h>

struct open_call {
  const char *path;
  int flags;
  int ret_fd;
};

struct fake_context {
  /* configuracao das respostas */
  long abi;
  long create_ruleset_ret;
  int create_ruleset_err;
  long add_rule_ret;
  long restrict_self_ret;
  int open_ret;
  int open_err;
  int stat_ret;
  int stat_err;
  int isdir_ret;
  int add_rule_err;
  int prctl_ret;
  int prctl_err;
  int fail_realloc;
  int realloc_err;

  /* spies */
  struct open_call last_open;
  int open_calls_count;
  int close_calls_count;
  long last_allowed_access;
  int last_parent_fd;
  unsigned long last_scoped;
  int create_calls_count;
  int add_calls_count;
  int restrict_calls_count;
};

extern struct fake_context fake;

void reset_fake(void);

#endif
