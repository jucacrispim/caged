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
#include <errno.h>

void test_allow_read_access_dir(void) {
  reset_fake();
  fake.stat_ret = 0;
  fake.isdir_ret = 1;
  fake.add_rule_ret = 0;

  int r = allow_read_access(7, "/some/dir");

  assert(r == 0);
  assert(fake.open_calls_count == 1);
  assert(fake.add_calls_count == 1);
  assert(fake.last_allowed_access == PERMS_READ);
  assert(fake.last_parent_fd == 9876);
}

void test_allow_read_access_file(void) {
  reset_fake();
  fake.stat_ret = 0;
  fake.isdir_ret = 0;
  fake.add_rule_ret = 0;

  int r = allow_read_access(7, "/some/file");

  assert(r == 0);
  assert(fake.add_calls_count == 1);
  // read perms for file exclude the dirs only perms
  assert(fake.last_allowed_access == (PERMS_READ & ~PERMS_DIRS_ONLY));
}

void test_allow_read_write_access_dir(void) {
  reset_fake();
  fake.stat_ret = 0;
  fake.isdir_ret = 1;
  fake.add_rule_ret = 0;

  int r = allow_read_write_access(7, "/some/dir", 9);

  assert(r == 0);
  assert(fake.add_calls_count == 1);
  assert(fake.last_allowed_access == PERMS_READ_WRITE);
}

void test_allow_read_write_access_file(void) {
  reset_fake();
  fake.stat_ret = 0;
  fake.isdir_ret = 0;
  fake.add_rule_ret = 0;

  int r = allow_read_write_access(7, "/some/file", 9);

  assert(r == 0);
  assert(fake.add_calls_count == 1);
  assert(fake.last_allowed_access == (PERMS_READ_WRITE & ~PERMS_DIRS_ONLY));
}

void test_allow_access_open_fail(void) {
  reset_fake();
  fake.open_ret = -1;
  fake.open_err = ENOENT;
  fake.add_rule_ret = 0;

  errno = 0;
  int r = allow_read_access(7, "/nonexistent");

  assert(r == -1);
  assert(errno == ENOENT);
  assert(fake.open_calls_count == 1);
  assert(fake.add_calls_count == 0);
}

void test_allow_access_fstat_fail(void) {
  reset_fake();
  fake.stat_ret = -1;
  fake.stat_err = EACCES;
  fake.add_rule_ret = 0;

  errno = 0;
  int r = allow_read_access(7, "/x");

  assert(r == -1);
  assert(errno == EACCES);
  assert(fake.add_calls_count == 0);
  assert(fake.close_calls_count == 1);
}

void test_allow_access_add_rule_fail(void) {
  reset_fake();
  fake.stat_ret = 0;
  fake.isdir_ret = 1;
  fake.add_rule_ret = -1;
  fake.add_rule_err = EINVAL;

  errno = 0;
  int r = allow_read_access(7, "/x");

  assert(r == -1);
  assert(errno == EINVAL);
  assert(fake.add_calls_count == 1);
  assert(fake.close_calls_count == 1);
}

int main(void) {
  test_allow_read_access_dir();
  test_allow_read_access_file();
  test_allow_read_write_access_dir();
  test_allow_read_write_access_file();
  test_allow_access_open_fail();
  test_allow_access_fstat_fail();
  test_allow_access_add_rule_fail();

  printf("OK\n");
  return 0;
}
