#define main caged_program_main
#include "../../caged.c"
#undef main
#include <assert.h>

void test_get_handled_access_fs_abi_1(void) {
  assert(get_handled_access_fs(1) ==
         (FS_HANDLED & ~LANDLOCK_ACCESS_FS_REFER &
          ~LANDLOCK_ACCESS_FS_TRUNCATE & ~LANDLOCK_ACCESS_FS_IOCTL_DEV &
          ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_handled_access_fs_abi_gte_2(void) {
  assert(get_handled_access_fs(2) ==
         (FS_HANDLED & ~LANDLOCK_ACCESS_FS_TRUNCATE &
          ~LANDLOCK_ACCESS_FS_IOCTL_DEV &
          ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_handled_access_fs_abi_gte_3(void) {
  assert(get_handled_access_fs(3) ==
         (FS_HANDLED & ~LANDLOCK_ACCESS_FS_IOCTL_DEV &
          ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_handled_access_fs_abi_4(void) {
  assert(get_handled_access_fs(4) ==
         (FS_HANDLED & ~LANDLOCK_ACCESS_FS_IOCTL_DEV &
          ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_handled_access_fs_abi_gte_5(void) {
  assert(get_handled_access_fs(5) ==
         (FS_HANDLED & ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_handled_access_fs_abi_lt_9(void) {
  /* ABI 5..8 support IOCTL_DEV but not RESOLVE_UNIX. */
  assert(get_handled_access_fs(8) ==
         (FS_HANDLED & ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_handled_access_fs_abi_gte_9(void) {
  assert(get_handled_access_fs(9) == FS_HANDLED);
}

void test_get_perms_read_write_perms_abi_lt_3(void) {
  assert(get_perms_read_write(2) ==
         (PERMS_READ_WRITE & ~LANDLOCK_ACCESS_FS_TRUNCATE &
          ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_perms_read_write_perms_abi_lt_9(void) {
  assert(get_perms_read_write(3) ==
         (PERMS_READ_WRITE & ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX));
}

void test_get_perms_read_write_perms_abi_gte_9(void) {
  assert(get_perms_read_write(9) == PERMS_READ_WRITE);
}

void test_get_supported_scopes_abi_lt_6(void) {
  /* scopes were added in ABI 6. */
  assert(get_supported_scopes(1) == 0);
  assert(get_supported_scopes(5) == 0);
}

void test_get_supported_scopes_abi_gte_6(void) {
  assert(get_supported_scopes(6) == SCOPED);
  assert(get_supported_scopes(9) == SCOPED);
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
  test_get_supported_scopes_abi_lt_6();
  test_get_supported_scopes_abi_gte_6();

  printf("OK\n");
  return 0;
}
