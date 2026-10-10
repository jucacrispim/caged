#!/bin/sh
# Functional (integration) tests for caged.
# Runs the real production binary (build/caged) against the real kernel and
# asserts the observable sandbox behaviour. This is the layer that covers
# what unit tests cannot: main(), die(), execvp() and the actual Landlock
# enforcement by the kernel.
#
# Each case is a test_* function that creates its own fixtures, so the tests
# are independent and can run in any order.
#
# Usage: sh tests/functional/run.sh      (or: make functional)
set -u

CAGED=${CAGED:-build/caged}

if [ ! -x "$CAGED" ]; then
  echo "caged binary not found at '$CAGED' (run: make)" >&2
  exit 1
fi

# minimal read perms needed to run basic shell commands
RO="--ro /usr --ro /bin --ro /lib"
# extra trees needed to run python3 (dynamic loader, locale, ...)
RO_PY="$RO --ro /lib64 --ro /etc"

pass=0
fail=0

ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$1"; }

# check NAME EXPECTED ACTUAL  (string equality)
check() {
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

# check_ne NAME NOT_EXPECTED ACTUAL
check_ne() {
  if [ "$2" != "$3" ]; then ok "$1"; else bad "$1 (should not be '$2')"; fi
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT


test_read_file_allowed() {
  printf 'hello\n' > "$work/readable.txt"
  out=$($CAGED $RO --ro "$work/readable.txt" -- cat "$work/readable.txt" 2>/dev/null)
  rc=$?
  check "read allowed with --ro file" 0 "$rc"
  check "--ro file yields the content" "hello" "$out"
}

test_read_outside_denied() {
  mkdir -p "$work/outside"
  printf 'secret\n' > "$work/outside/secret.txt"
  $CAGED $RO -- cat "$work/outside/secret.txt" >/dev/null 2>&1
  check_ne "read denied outside granted trees" 0 $?
}

test_ro_file_does_not_grant_sibling() {
  printf 'hello\n' > "$work/readable.txt"
  printf 'other\n' > "$work/other.txt"
  $CAGED $RO --ro "$work/readable.txt" -- cat "$work/other.txt" >/dev/null 2>&1
  check_ne "--ro file does not grant its sibling" 0 $?
}

test_ro_file_does_not_grant_parent() {
  printf 'hello\n' > "$work/readable.txt"
  mkdir -p "$work/outside"
  printf 'secret\n' > "$work/outside/secret.txt"
  $CAGED $RO --ro "$work/readable.txt" -- cat "$work/outside/secret.txt" >/dev/null 2>&1
  check_ne "--ro file does not grant the parent dir" 0 $?
}

test_multiple_ro_are_honoured() {
  $CAGED $RO -- ls /usr >/dev/null 2>&1
  check "multiple --ro are honoured" 0 $?
}

test_write_inside_rw_allowed() {
  mkdir -p "$work/rw"
  $CAGED $RO --rw "$work/rw" -- sh -c "echo data > '$work/rw/created.txt'" 2>/dev/null
  check "write allowed inside --rw" 0 $?
  if [ -f "$work/rw/created.txt" ]; then
    ok "--rw actually created the file"
  else
    bad "--rw actually created the file"
  fi
}

test_write_inside_ro_denied() {
  mkdir -p "$work/rw"
  $CAGED $RO --ro "$work/rw" -- sh -c "echo data > '$work/rw/denied.txt'" 2>/dev/null
  check_ne "write denied inside --ro" 0 $?
}

test_write_outside_rw_denied() {
  mkdir -p "$work/rw" "$work/outside"
  $CAGED $RO --rw "$work/rw" -- sh -c "echo data > '$work/outside/x.txt'" 2>/dev/null
  check_ne "write denied outside --rw" 0 $?
}

test_remove_inside_rw_allowed() {
  mkdir -p "$work/rw"
  printf 'x\n' > "$work/rw/todelete.txt"
  $CAGED $RO --rw "$work/rw" -- rm "$work/rw/todelete.txt" 2>/dev/null
  check "remove allowed inside --rw" 0 $?
  if [ -f "$work/rw/todelete.txt" ]; then
    bad "--rw actually removed the file"
  else
    ok "--rw actually removed the file"
  fi
}


test_append_rw_file_allowed() {
  printf 'base\n' > "$work/file.log"
  $CAGED $RO --rw "$work/file.log" -- sh -c "echo more >> '$work/file.log'" 2>/dev/null
  check "append allowed with --rw file" 0 $?
  if grep -q more "$work/file.log"; then
    ok "--rw file was appended"
  else
    bad "--rw file was appended"
  fi
}

test_write_ro_file_denied() {
  printf 'hello\n' > "$work/readable.txt"
  $CAGED $RO --ro "$work/readable.txt" -- sh -c "echo x >> '$work/readable.txt'" 2>/dev/null
  check_ne "write denied with --ro file" 0 $?
}


test_ro_without_value_exits_2() {
  $CAGED --ro 2>/dev/null
  check "--ro without value exits 2" 2 $?
}

test_rw_without_value_exits_2() {
  $CAGED --rw 2>/dev/null
  check "--rw without value exits 2" 2 $?
}

test_unknown_option_exits_2() {
  $CAGED --bogus 2>/dev/null
  check "unknown option exits 2" 2 $?
}

test_missing_separator_exits_2() {
  $CAGED --ro /usr 2>/dev/null
  check "missing -- exits 2" 2 $?
}

test_empty_command_exits_2() {
  $CAGED --ro /usr -- 2>/dev/null
  check "empty command after -- exits 2" 2 $?
}

test_no_arguments_exits_2() {
  $CAGED 2>/dev/null
  check "no arguments exits 2" 2 $?
}


test_nonexistent_path_exits_1() {
  $CAGED --ro /no/such/path -- true 2>/dev/null
  check "nonexistent path exits 1" 1 $?
}

test_missing_program_exits_1() {
  $CAGED $RO -- /nonexistent/prog 2>/dev/null
  check "missing program path exits 1" 1 $?
}

test_unknown_command_exits_1() {
  $CAGED $RO -- no_such_command_xyz 2>/dev/null
  check "unknown command exits 1" 1 $?
}


# signalling a process outside the sandbox is denied unless the signal scope
# is allowed with --allow-scoped-signal
test_scope_signal_denied_by_default() {
  sleep 30 &
  victim=$!
  $CAGED $RO -- sh -c "kill -0 $victim" 2>/dev/null
  rc=$?
  kill "$victim" 2>/dev/null
  wait "$victim" 2>/dev/null
  check_ne "signal to outside process denied by default" 0 $rc
}

test_scope_signal_allowed_with_flag() {
  sleep 30 &
  victim=$!
  $CAGED $RO --allow-scoped-signal -- sh -c "kill -0 $victim" 2>/dev/null
  rc=$?
  kill "$victim" 2>/dev/null
  wait "$victim" 2>/dev/null
  check "signal allowed with --allow-scoped-signal" 0 $rc
}

# connecting to an abstract unix socket outside the sandbox is denied unless
# the abstract unix scope is allowed with --allow-scoped-abstract-unix
start_abs_server() {
  python3 -c "
import socket, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind('\0$1')
s.listen(1)
time.sleep(30)
" >/dev/null 2>&1 &
  echo $!
}

test_scope_abstract_unix_denied_by_default() {
  name="caged-abs-$$-dd"
  srv=$(start_abs_server "$name")
  sleep 1
  $CAGED $RO_PY -- python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect('\0$name')
except PermissionError:
    sys.exit(3)
except OSError:
    sys.exit(4)
sys.exit(0)
" 2>/dev/null
  rc=$?
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  check "abstract unix connect denied by default" 3 "$rc"
}

test_scope_abstract_unix_allowed_with_flag() {
  name="caged-abs-$$-ok"
  srv=$(start_abs_server "$name")
  sleep 1
  $CAGED $RO_PY --allow-scoped-abstract-unix -- python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect('\0$name')
except OSError:
    sys.exit(3)
sys.exit(0)
" 2>/dev/null
  rc=$?
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  check "abstract unix connect allowed with --allow-scoped-abstract-unix" 0 "$rc"
}

main() {
  test_read_file_allowed
  test_read_outside_denied
  test_ro_file_does_not_grant_sibling
  test_ro_file_does_not_grant_parent
  test_multiple_ro_are_honoured
  test_write_inside_rw_allowed
  test_write_inside_ro_denied
  test_write_outside_rw_denied
  test_remove_inside_rw_allowed
  test_append_rw_file_allowed
  test_write_ro_file_denied
  test_ro_without_value_exits_2
  test_rw_without_value_exits_2
  test_unknown_option_exits_2
  test_missing_separator_exits_2
  test_empty_command_exits_2
  test_no_arguments_exits_2
  test_nonexistent_path_exits_1
  test_missing_program_exits_1
  test_unknown_command_exits_1

  test_scope_signal_denied_by_default
  test_scope_signal_allowed_with_flag
  test_scope_abstract_unix_denied_by_default
  test_scope_abstract_unix_allowed_with_flag

  printf '\n%d passed, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

main
