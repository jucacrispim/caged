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

#define _GNU_SOURCE

#include <assert.h>

#include "../../caged_internal.h"

void test_get_handled_access_fs_abi_1(void) {
  assert(caged_get_handled_access_fs(1) ==
         (CAGED_FS_HANDLED & ~LANDLOCK_ACCESS_FS_REFER &
          ~LANDLOCK_ACCESS_FS_TRUNCATE & ~LANDLOCK_ACCESS_FS_IOCTL_DEV &
          ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_handled_access_fs_abi_gte_2(void) {
  assert(caged_get_handled_access_fs(2) ==
         (CAGED_FS_HANDLED & ~LANDLOCK_ACCESS_FS_TRUNCATE &
          ~LANDLOCK_ACCESS_FS_IOCTL_DEV &
          ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_handled_access_fs_abi_gte_3(void) {
  assert(caged_get_handled_access_fs(3) ==
         (CAGED_FS_HANDLED & ~LANDLOCK_ACCESS_FS_IOCTL_DEV &
          ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_handled_access_fs_abi_4(void) {
  assert(caged_get_handled_access_fs(4) ==
         (CAGED_FS_HANDLED & ~LANDLOCK_ACCESS_FS_IOCTL_DEV &
          ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_handled_access_fs_abi_gte_5(void) {
  assert(caged_get_handled_access_fs(5) ==
         (CAGED_FS_HANDLED & ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_handled_access_fs_abi_lt_9(void) {
  /* ABI 5..8 support IOCTL_DEV but not RESOLVE_UNIX. */
  assert(caged_get_handled_access_fs(8) ==
         (CAGED_FS_HANDLED & ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_handled_access_fs_abi_gte_9(void) {
  assert(caged_get_handled_access_fs(9) == CAGED_FS_HANDLED);
}

void test_get_perms_read_write_perms_abi_lt_3(void) {
  assert(caged_get_perms_read_write(2) ==
         (CAGED_PERMS_READ_WRITE & ~LANDLOCK_ACCESS_FS_TRUNCATE &
          ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_perms_read_write_perms_abi_lt_9(void) {
  assert(caged_get_perms_read_write(3) ==
         (CAGED_PERMS_READ_WRITE & ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_perms_read_write_perms_abi_gte_9(void) {
  assert(caged_get_perms_read_write(9) == CAGED_PERMS_READ_WRITE);
}

void test_get_handled_scopes_abi_lt_6(void) {
  /* scopes were added in ABI 6. */
  assert(caged_get_handled_scopes(1) == 0);
  assert(caged_get_handled_scopes(5) == 0);
}

void test_get_handled_scopes_abi_gte_6(void) {
  assert(caged_get_handled_scopes(6) == CAGED_SCOPED);
  assert(caged_get_handled_scopes(9) == CAGED_SCOPED);
}

void test_get_handled_access_net_abi_lt_4(void) {
  /* net accesses were added in ABI 4. */
  assert(caged_get_handled_access_net(1) == 0);
  assert(caged_get_handled_access_net(3) == 0);
}

void test_get_handled_access_net_abi_gte_4(void) {
  assert(caged_get_handled_access_net(4) == CAGED_NET_HANDLED);
  assert(caged_get_handled_access_net(6) == CAGED_NET_HANDLED);
  assert(caged_get_handled_access_net(9) == CAGED_NET_HANDLED);
}

void test_get_supported_restrict_flags_abi_lt_7(void) {
  /* the log flags were added in ABI 7. */
  assert(caged_get_supported_restrict_flags(1) == 0);
  assert(caged_get_supported_restrict_flags(6) == 0);
}

void test_get_supported_restrict_flags_abi_7(void) {
  /* ABI 7 has the log flags but not TSYNC (added in ABI 8). */
  unsigned long log_flags = CAGED_RESTRICT_FLAGS & ~LANDLOCK_RESTRICT_SELF_TSYNC;
  assert(caged_get_supported_restrict_flags(7) == log_flags);
}

void test_get_supported_restrict_flags_abi_gte_8(void) {
  assert(caged_get_supported_restrict_flags(8) == CAGED_RESTRICT_FLAGS);
  assert(caged_get_supported_restrict_flags(9) == CAGED_RESTRICT_FLAGS);
}

int main(void) {
  test_get_handled_access_fs_abi_1();
  test_get_handled_access_fs_abi_gte_2();
  test_get_handled_access_fs_abi_gte_3();
  test_get_handled_access_fs_abi_4();
  test_get_handled_access_fs_abi_gte_5();
  test_get_handled_access_fs_abi_lt_9();
  test_get_handled_access_fs_abi_gte_9();
  test_get_perms_read_write_perms_abi_lt_3();
  test_get_perms_read_write_perms_abi_lt_9();
  test_get_perms_read_write_perms_abi_gte_9();
  test_get_handled_scopes_abi_lt_6();
  test_get_handled_scopes_abi_gte_6();
  test_get_handled_access_net_abi_lt_4();
  test_get_handled_access_net_abi_gte_4();
  test_get_supported_restrict_flags_abi_lt_7();
  test_get_supported_restrict_flags_abi_7();
  test_get_supported_restrict_flags_abi_gte_8();

  printf("OK\n");
  return 0;
}
