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
#include "../../cli.c"
#undef main
#include "fake_syscalls.h"
#include <assert.h>
#include <errno.h>

/* push_port grows the backing array and keeps the order */
void test_push_port_grows(void) {
  unsigned short *list = NULL;
  int n = 0;
  int cap = 0;

  for (int i = 0; i < 100; i++) {
    assert(push_port(&list, &n, &cap, (unsigned short)i) == 0);
  }
  assert(n == 100);
  assert(cap >= 100);
  for (int i = 0; i < 100; i++) {
    assert(list[i] == (unsigned short)i);
  }

  free(list);
}

/* allocation failure while growing the list -> error */
void test_push_port_out_of_memory(void) {
  unsigned short *list = NULL;
  int n = 0;
  int cap = 0;

  reset_fake();
  fake.fail_realloc = 1;
  fake.realloc_err = ENOMEM;

  errno = 0;
  assert(push_port(&list, &n, &cap, 80) < 0);
  assert(n == 0);
  assert(errno == ENOMEM);

  free(list);
}

void test_parse_port_valid(void) {
  unsigned short p;

  assert(parse_port("0", &p) == 0);
  assert(p == 0);
  assert(parse_port("443", &p) == 0);
  assert(p == 443);
  assert(parse_port("65535", &p) == 0);
  assert(p == 65535);
}

void test_parse_port_invalid(void) {
  unsigned short p;

  assert(parse_port("", &p) < 0);
  assert(parse_port("abc", &p) < 0);
  assert(parse_port("12x", &p) < 0);
  assert(parse_port("22 ", &p) < 0);
  assert(parse_port("65536", &p) < 0);
  assert(parse_port("-1", &p) < 0);
  /* overflows strtoul -> ERANGE */
  assert(parse_port("99999999999999999999999", &p) < 0);
}

void test_allow_net_connect_access(void) {
  reset_fake();
  fake.add_rule_ret = 0;

  int r = allow_net_connect_access(7, 443);

  assert(r == 0);
  assert(fake.add_calls_count == 1);
  assert(fake.last_net_allowed_access == LANDLOCK_ACCESS_NET_CONNECT_TCP);
  assert(fake.last_net_port == 443);
}

void test_allow_net_bind_access(void) {
  reset_fake();
  fake.add_rule_ret = 0;

  int r = allow_net_bind_access(7, 8080);

  assert(r == 0);
  assert(fake.add_calls_count == 1);
  assert(fake.last_net_allowed_access == LANDLOCK_ACCESS_NET_BIND_TCP);
  assert(fake.last_net_port == 8080);
}

void test_add_net_rule_fail(void) {
  reset_fake();
  fake.add_rule_ret = -1;
  fake.add_rule_err = EINVAL;

  errno = 0;
  int r = allow_net_connect_access(7, 1);

  assert(r == -1);
  assert(errno == EINVAL);
  assert(fake.add_calls_count == 1);
}

int main(void) {
  test_push_port_grows();
  test_push_port_out_of_memory();
  test_parse_port_valid();
  test_parse_port_invalid();
  test_allow_net_connect_access();
  test_allow_net_bind_access();
  test_add_net_rule_fail();

  printf("OK\n");
  return 0;
}
