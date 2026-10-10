#define main caged_program_main
#include "../../caged.c"
#undef main
#include "fake_syscalls.h"
#include <assert.h>
#include <errno.h>

void test_setup_ok(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.stat_ret = 0;
  fake.isdir_ret = 1;
  fake.add_rule_ret = 0;
  fake.prctl_ret = 0;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};
  push_path(&opts.r_dir, &opts.n_r, &opts.cap_r, "/usr");
  push_path(&opts.r_dir, &opts.n_r, &opts.cap_r, "/etc");
  push_path(&opts.rw_dir, &opts.n_rw, &opts.cap_rw, "/tmp/x");

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.create_calls_count == 1);
  assert(fake.add_calls_count == 3);
  assert(fake.restrict_calls_count == 1);
  /* scopes are restricted by default */
  assert(fake.last_scoped == SCOPED);
  /* net is handled (and thus denied) by default */
  assert(fake.last_handled_net == NET_HANDLED);

  cmd_opts_free(&opts);
}

/* releasing the whole connect access clears its bit from the handled mask */
void test_setup_released_net_general(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};
  opts.released_net = LANDLOCK_ACCESS_NET_CONNECT_TCP;

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.last_handled_net ==
         ((unsigned long)NET_HANDLED & ~LANDLOCK_ACCESS_NET_CONNECT_TCP));
}

/* --allow-*-port adds a rule per port */
void test_setup_net_port_rules(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.add_rule_ret = 0;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};
  push_port(&opts.connect_ports, &opts.n_connect, &opts.cap_connect, 443);
  push_port(&opts.bind_ports, &opts.n_bind, &opts.cap_bind, 80);

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.add_calls_count == 2);
  /* net stays governed when only individual ports are granted */
  assert(fake.last_handled_net == NET_HANDLED);
  /* last rule is the bind one */
  assert(fake.last_net_allowed_access == LANDLOCK_ACCESS_NET_BIND_TCP);
  assert(fake.last_net_port == 80);

  cmd_opts_free(&opts);
}

void test_setup_connect_rule_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.add_rule_ret = -1;
  fake.add_rule_err = EINVAL;

  struct cmd_opts opts = {0};
  push_port(&opts.connect_ports, &opts.n_connect, &opts.cap_connect, 443);

  assert(caged_setup(&opts) == CAGED_ERR_CONNECT_ACCESS);
  assert(fake.restrict_calls_count == 0);

  cmd_opts_free(&opts);
}

void test_setup_bind_rule_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.add_rule_ret = -1;
  fake.add_rule_err = EINVAL;

  struct cmd_opts opts = {0};
  push_port(&opts.bind_ports, &opts.n_bind, &opts.cap_bind, 80);

  assert(caged_setup(&opts) == CAGED_ERR_BIND_ACCESS);
  assert(fake.restrict_calls_count == 0);

  cmd_opts_free(&opts);
}

/* below ABI 4 net is unsupported, so nothing is handled */
void test_setup_net_unsupported_abi(void) {
  reset_fake();
  fake.abi = 3;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.last_handled_net == 0);
}

/* releasing a scope clears its bit from the default mask */
void test_setup_released_scope(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};
  opts.released_scopes = LANDLOCK_SCOPE_SIGNAL;

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.last_scoped == (SCOPED & ~LANDLOCK_SCOPE_SIGNAL));
}

/* below ABI 6 scopes are unsupported, so nothing is restricted */
void test_setup_scopes_unsupported_abi(void) {
  reset_fake();
  fake.abi = 5;
  fake.create_ruleset_ret = 3;
  fake.restrict_self_ret = 0;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_OK);
  assert(fake.last_scoped == 0);
}

void test_setup_no_landlock(void) {
  reset_fake();
  fake.abi = -1;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_NO_LANDLOCK);
  assert(fake.create_calls_count == 0);
}

void test_setup_create_ruleset_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = -1;
  fake.create_ruleset_err = EPERM;

  struct cmd_opts opts = {0};

  errno = 0;
  assert(caged_setup(&opts) == CAGED_ERR_CREATE_RULESET);
  assert(errno == EPERM);
  assert(fake.add_calls_count == 0);
}

void test_setup_allow_ro_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.open_ret = -1;
  fake.open_err = ENOENT;

  struct cmd_opts opts = {0};
  push_path(&opts.r_dir, &opts.n_r, &opts.cap_r, "/nope");

  assert(caged_setup(&opts) == CAGED_ERR_READ_ACCESS);
  assert(fake.restrict_calls_count == 0);

  cmd_opts_free(&opts);
}

void test_setup_allow_rw_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.open_ret = -1;
  fake.open_err = ENOENT;

  struct cmd_opts opts = {0};
  push_path(&opts.rw_dir, &opts.n_rw, &opts.cap_rw, "/nope");

  assert(caged_setup(&opts) == CAGED_ERR_RW_ACCESS);
  assert(fake.restrict_calls_count == 0);

  cmd_opts_free(&opts);
}

void test_setup_restrict_prctl_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.prctl_ret = -1;
  fake.prctl_err = EPERM;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_RESTRICT_SELF);
}

void test_setup_restrict_syscall_error(void) {
  reset_fake();
  fake.abi = 6;
  fake.create_ruleset_ret = 3;
  fake.prctl_ret = 0;
  fake.restrict_self_ret = -1;

  struct cmd_opts opts = {0};

  assert(caged_setup(&opts) == CAGED_ERR_RESTRICT_SELF);
  assert(fake.restrict_calls_count == 1);
}

/* test if every  return code have a message */
void test_strreturn(void) {
  enum caged_return codes[] = {
      CAGED_OK,
      CAGED_ERR_NO_LANDLOCK,
      CAGED_ERR_CREATE_RULESET,
      CAGED_ERR_READ_ACCESS,
      CAGED_ERR_RW_ACCESS,
      CAGED_ERR_CONNECT_ACCESS,
      CAGED_ERR_BIND_ACCESS,
      CAGED_ERR_RESTRICT_SELF,
  };
  for (size_t i = 0; i < sizeof codes / sizeof codes[0]; i++) {
    const char *msg = caged_strreturn(codes[i]);
    assert(msg != NULL);
    assert(msg[0] != '\0');
  }
}

void test_strreturn_unknown_error(void) {
  assert(strcmp(caged_strreturn((enum caged_return)999), "unknown error") == 0);
}

int main(void) {
  test_setup_ok();
  test_setup_released_net_general();
  test_setup_net_port_rules();
  test_setup_connect_rule_error();
  test_setup_bind_rule_error();
  test_setup_net_unsupported_abi();
  test_setup_released_scope();
  test_setup_scopes_unsupported_abi();
  test_setup_no_landlock();
  test_setup_create_ruleset_error();
  test_setup_allow_ro_error();
  test_setup_allow_rw_error();
  test_setup_restrict_prctl_error();
  test_setup_restrict_syscall_error();
  test_strreturn();
  test_strreturn_unknown_error();

  printf("OK\n");
  return 0;
}
