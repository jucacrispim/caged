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
  unsigned long last_handled_net;
  long last_net_allowed_access;
  long last_net_port;
  unsigned long last_restrict_flags;
  int create_calls_count;
  int add_calls_count;
  int restrict_calls_count;
};

extern struct fake_context fake;

void reset_fake(void);

#endif
