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

# Several tests use python3 (sockets, ctypes). Its prefix is not always /usr:
# pyenv and venvs keep the interpreter elsewhere, and then it cannot even
# start inside the cage. Derive the granted trees from the interpreter itself
# instead of assuming /usr. PYTHON may be set from outside to pick another one.
PYTHON=${PYTHON:-$(command -v python3 2>/dev/null || true)}
PY_REAL=$(readlink -f "$PYTHON" 2>/dev/null || printf '%s' "$PYTHON")
PY_PREFIX=$(dirname "$(dirname "$PY_REAL")")
# extra trees: dynamic loader, locale, and the interpreter's own two levels
# (a pyenv shim needs both the shim dir and the real prefix)
RO_PY="$RO --ro /lib64 --ro /etc --ro $PY_PREFIX --ro $(dirname "$PYTHON")"

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

# A python3 that cannot start inside the cage makes a whole batch of tests
# fail for one reason, so say it up front instead of leaving bare mismatches.
if [ -z "$PYTHON" ] ||
   ! $CAGED $RO_PY -- "$PYTHON" -c 'pass' >/dev/null 2>&1; then
  printf 'WARN - python3 (%s) does not run inside the cage; the python-based\n' \
    "${PYTHON:-not found}" >&2
  printf '       tests will fail. Set PYTHON=/path/to/python3 to override.\n' >&2
fi

# Creates a socket from inside the cage and prints "created" or the errno of
# the failure. $1 = extra caged flags, $2 = python expression creating it.
socket_probe() {
  CAGED_DISABLE_WARNINGS=1 $CAGED $RO_PY $1 -- "$PYTHON" -c "
import socket
try:
    $2
except OSError as e:
    print(e.errno)
else:
    print('created')
" 2>&1
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
  err=$($CAGED 2>&1 >/dev/null)
  check "no arguments exits 2" 2 $?
  case "$err" in
  *"usage: caged"*) ok "no arguments prints the help" ;;
  *) bad "no arguments prints the help" ;;
  esac
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
  "$PYTHON" -c "
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
  $CAGED $RO_PY -- "$PYTHON" -c "
import socket, sys
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
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
  $CAGED $RO_PY --allow-unix-sockets --allow-scoped-abstract-unix -- "$PYTHON" -c "
import socket, sys
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
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


# starts a TCP server on 127.0.0.1 with an ephemeral port; sets TCP_PID/TCP_PORT
# used for the NET access tests
start_tcp_server() {
  portfile=$(mktemp)
  "$PYTHON" -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(1)
open('$portfile', 'w').write(str(s.getsockname()[1]))
s.settimeout(30)
try:
    s.accept()
except Exception:
    pass
" >/dev/null 2>&1 &
  TCP_PID=$!
  i=0
  while [ ! -s "$portfile" ] && [ "$i" -lt 100 ]; do
    sleep 0.1
    i=$((i + 1))
  done
  TCP_PORT=$(cat "$portfile")
  rm -f "$portfile"
}

stop_tcp_server() {
  kill "$TCP_PID" 2>/dev/null
  wait "$TCP_PID" 2>/dev/null
}

# connects from inside the sandbox; $1 = net flags (may be empty), $2 = port
# exit 3 = PermissionError (denied), exit 4 = other error, exit 0 = connected
tcp_connect_rc() {
  $CAGED $RO_PY $1 -- "$PYTHON" -c "
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', $2))
except PermissionError:
    sys.exit(3)
except OSError:
    sys.exit(4)
sys.exit(0)
" 2>/dev/null
}

# binds to an ephemeral port from inside the sandbox; $1 = net flags
# exit 3 = PermissionError (denied), exit 4 = other error, exit 0 = bound
tcp_bind_rc() {
  $CAGED $RO_PY $1 -- "$PYTHON" -c "
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
except PermissionError:
    sys.exit(3)
except OSError:
    sys.exit(4)
sys.exit(0)
" 2>/dev/null
}

test_net_connect_denied_by_default() {
  start_tcp_server
  tcp_connect_rc "" "$TCP_PORT"
  rc=$?
  stop_tcp_server
  check "tcp connect denied by default" 3 "$rc"
}

test_net_connect_allowed_by_port() {
  start_tcp_server
  tcp_connect_rc "--allow-network-sockets --allow-connect-port $TCP_PORT" "$TCP_PORT"
  rc=$?
  stop_tcp_server
  check "tcp connect allowed with --allow-connect-port" 0 "$rc"
}

test_net_connect_allowed_general() {
  start_tcp_server
  tcp_connect_rc "--allow-network-sockets --allow-connect-tcp" "$TCP_PORT"
  rc=$?
  stop_tcp_server
  check "tcp connect allowed with --allow-connect-tcp" 0 "$rc"
}

test_net_bind_denied_by_default() {
  tcp_bind_rc ""
  rc=$?
  check "tcp bind denied by default" 3 "$rc"
}

test_net_bind_allowed_by_port() {
  tcp_bind_rc "--allow-network-sockets --allow-bind-port 0"
  rc=$?
  check "tcp bind allowed with --allow-bind-port 0" 0 "$rc"
}

test_net_bind_allowed_general() {
  tcp_bind_rc "--allow-network-sockets --allow-bind-tcp"
  rc=$?
  check "tcp bind allowed with --allow-bind-tcp" 0 "$rc"
}

# Socket families: these exercise the seccomp filter against the real kernel,
# not just its pseudo code. The expected errno is 13 (EACCES) throughout. That
# matters: outside the cage SOCK_RAW and AF_PACKET fail with EPERM (1), so a
# 13 here can only come from the filter.

# AF_PACKET is outside the family allowlist, so it is denied either way
test_af_packet_is_denied() {
  out=$(socket_probe "" "socket.socket(socket.AF_PACKET, socket.SOCK_RAW)")
  check "AF_PACKET is denied" 13 "$out"
  out=$(socket_probe "--allow-network-sockets --allow-unix-sockets" \
        "socket.socket(socket.AF_PACKET, socket.SOCK_RAW)")
  check "AF_PACKET stays denied with every family allowed" 13 "$out"
}

# the raw rule is only observable once the family itself is released
test_sock_raw_is_denied() {
  out=$(socket_probe "--allow-network-sockets" \
        "socket.socket(socket.AF_INET, socket.SOCK_RAW)")
  check "SOCK_RAW is denied even with --allow-network-sockets" 13 "$out"
  out=$(socket_probe "--allow-network-sockets" \
        "socket.socket(socket.AF_INET6, socket.SOCK_RAW)")
  check "AF_INET6 SOCK_RAW is denied" 13 "$out"
  # control: a non-raw socket in the same family is created
  out=$(socket_probe "--allow-network-sockets" \
        "socket.socket(socket.AF_INET, socket.SOCK_STREAM)")
  check "TCP socket is created once the family is allowed" created "$out"
}

# SOCK_CLOEXEC lives in the high bits of the type argument, so a plain
# equality check would let it through; the mask is what makes this pass
test_sock_raw_cloexec_is_denied() {
  out=$(socket_probe "--allow-network-sockets" \
        "socket.socket(socket.AF_INET, socket.SOCK_RAW | socket.SOCK_CLOEXEC)")
  check "SOCK_RAW|SOCK_CLOEXEC is denied" 13 "$out"
}

# UDP is denied by the family rule, not by the Landlock port rules (which only
# govern TCP)
test_udp_socket_is_denied() {
  out=$(socket_probe "" "socket.socket(socket.AF_INET, socket.SOCK_DGRAM)")
  check "UDP is denied by default" 13 "$out"
  out=$(socket_probe "--allow-network-sockets" \
        "socket.socket(socket.AF_INET, socket.SOCK_DGRAM)")
  check "UDP is created with --allow-network-sockets" created "$out"
}

# NETLINK_USERSOCK is an IPC channel and is always denied; other netlink
# protocols must survive, or getifaddrs()/if_nameindex() break
test_netlink_usersock_is_denied() {
  out=$(socket_probe "--allow-network-sockets" \
        "socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 2)")
  check "NETLINK_USERSOCK is denied" 13 "$out"
  out=$(socket_probe "--allow-network-sockets" \
        "socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)")
  check "NETLINK_ROUTE is still created" created "$out"
}

test_unix_socket_is_denied() {
  out=$(socket_probe "" "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)")
  check "AF_UNIX is denied by default" 13 "$out"
  out=$(socket_probe "--allow-unix-sockets" \
        "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)")
  check "AF_UNIX is created with --allow-unix-sockets" created "$out"
}

# the catch-all rule: a family number above this build's AF_MAX fails with
# EACCES, not with the kernel's EAFNOSUPPORT (97)
test_family_above_af_max_is_denied() {
  out=$(socket_probe "--allow-network-sockets --allow-unix-sockets" \
        "socket.socket(999, socket.SOCK_STREAM)")
  check "family above AF_MAX is denied" 13 "$out"
}

# the practical claim from RISKS.md: the daemon outside the cage is not
# reachable from inside it
test_docker_sock_is_unreachable() {
  if [ ! -S /run/docker.sock ]; then
    ok "docker.sock is unreachable (skipped: no /run/docker.sock)"
    return
  fi
  out=$(socket_probe "" \
        "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect('/run/docker.sock')")
  check "docker.sock is unreachable from the cage" 13 "$out"
}

test_sysv_ipc_denied() {
  $CAGED $RO -- ipcmk -M 1024 >/dev/null 2>&1
  check_ne "sysv IPC denied by default" 0 $?
}

test_sysv_ipc_allowed_with_flag() {
  out=$(LC_ALL=C $CAGED $RO --allow-sysv-ipc -- ipcmk -M 1024 2>/dev/null)
  rc=$?
  check "sysv IPC allowed with --allow-sysv-ipc" 0 "$rc"
  # ipcmk reports the new segment as the last field of its output
  id=$(printf '%s\n' "$out" | sed -n 's/.*: *//p')
  if [ -n "$id" ]; then
    ipcrm -m "$id" 2>/dev/null
    ok "sysv IPC segment was created"
  else
    bad "sysv IPC segment was created (output: '$out')"
  fi
}

# a descriptor inherited from outside the sandbox is closed before exec
test_inherited_fd_is_closed() {
  $CAGED $RO 9</dev/null -- sh -c 'cat <&9' >/dev/null 2>&1
  check_ne "inherited fd is closed" 0 $?
}

# core dumps would write process memory wherever the confined process points
# its cwd
test_core_dump_disabled() {
  out=$($CAGED $RO -- sh -c 'ulimit -c' 2>/dev/null)
  check "core dump disabled" 0 "$out"
}

# --max-procs is passed through as RLIMIT_NPROC (dash has no `ulimit -u`)
test_max_procs_set() {
  out=$($CAGED $RO_PY --max-procs 32 -- "$PYTHON" -c \
        'import resource; print(resource.getrlimit(resource.RLIMIT_NPROC)[0])' 2>/dev/null)
  check "--max-procs is applied" 32 "$out"
}

# ptrace/io_uring need the same uid or no privilege at all, so seccomp is the
# layer that has to stop them. Both answer ENOSYS, the "not implemented"
# error, and the helpers below print "<ret> <errno>".
test_ptrace_is_denied() {
  out=$($CAGED $RO_PY -- "$PYTHON" -c "
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p,
                        ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long
r = libc.ptrace(0, 0, None, None)
print(r, ctypes.get_errno())
" 2>/dev/null)
  check "ptrace denied with ENOSYS" "-1 38" "$out"
}

# 425 is io_uring_setup on every architecture with unified numbering
test_io_uring_is_denied() {
  out=$($CAGED $RO_PY -- "$PYTHON" -c "
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
params = ctypes.create_string_buffer(120)
r = libc.syscall(425, 2, params)
print(r, ctypes.get_errno())
" 2>/dev/null)
  check "io_uring_setup denied with ENOSYS" "-1 38" "$out"
}

# the filter is a denylist of syscalls, not a "deny everything": ordinary
# syscalls still work
test_ordinary_syscalls_still_work() {
  out=$($CAGED $RO_PY -- "$PYTHON" -c "import os; print(os.getpid() > 0)" 2>/dev/null)
  check "ordinary syscalls still work" True "$out"
}

# The environment is cleared by default: a caller's secrets do not reach the
# command, while PATH/HOME/LANG and the LC_* categories survive. The `env`
# binary is used instead of python, which injects LC_CTYPE into os.environ.
test_env_is_cleared_by_default() {
  out=$(FOO=secret SSH_AUTH_SOCK=/run/user/1000/agent \
        CAGED_DISABLE_WARNINGS=1 $CAGED $RO -- env 2>/dev/null |
        grep -c '^\(FOO\|SSH_AUTH_SOCK\)=')
  check "secrets are not inherited by default" 0 "$out"
}

test_env_keeps_path_and_locale() {
  out=$(PATH=/usr/bin:/bin LANG=pt_BR.UTF-8 LC_ALL=pt_BR.UTF-8 \
        CAGED_DISABLE_WARNINGS=1 $CAGED $RO -- env 2>/dev/null |
        grep '^\(PATH\|LANG\|LC_ALL\)=' | sort | tr '\n' ' ')
  check "PATH and the locale survive by default" \
        "LANG=pt_BR.UTF-8 LC_ALL=pt_BR.UTF-8 PATH=/usr/bin:/bin " "$out"
}

test_keep_env_inherits_all() {
  out=$(FOO=secret CAGED_DISABLE_WARNINGS=1 $CAGED $RO --keep-env -- env 2>/dev/null |
        grep '^FOO=')
  check "--keep-env inherits the caller's environment" "FOO=secret" "$out"
}

test_env_flag_sets_variable() {
  out=$(FOO=old CAGED_DISABLE_WARNINGS=1 $CAGED $RO --env FOO=new -- env 2>/dev/null |
        grep '^FOO=')
  check "--env sets the variable" "FOO=new" "$out"
}

test_env_flag_overrides_without_duplicating() {
  out=$(FOO=old CAGED_DISABLE_WARNINGS=1 \
        $CAGED $RO --keep-env --env FOO=new -- env 2>/dev/null | grep -c '^FOO=')
  check "--env overrides without duplicating" 1 "$out"
}

# restrict-self flags ar for abi >= 7. On my system it is abi 6, so what I
# test here is that the flags don't break the caged run. Warnings will show
# the user what is not enabled due to kernel version.
test_restrict_flags_accepted() {
  $CAGED $RO --log-same-exec-off --log-new-exec-on --log-subdomains-off --tsync \
    -- true 2>/dev/null
  check "restrict-self flags are accepted" 0 $?
}

# --tsync reaches the seccomp layer too: the filter is loaded with the TSYNC
# attribute, and if the kernel refused it the setup would fail with exit 1.
test_tsync_applies_seccomp() {
  out=$(socket_probe "--tsync" "socket.socket(socket.AF_INET, socket.SOCK_DGRAM)")
  check "--tsync keeps the seccomp filter in force" 13 "$out"
}

# on an old kernel stderr carries the warnings; on a recent enough kernel
# there is simply nothing to warn about (both are fine)
test_warnings_printed_by_default() {
  err=$($CAGED $RO -- true 2>&1 >/dev/null)
  case "$err" in
  "") ok "no ABI warnings on a recent kernel" ;;
  *"caged: warning"*) ok "unsupported features are warned about by default" ;;
  *) bad "unexpected warning output '$err'" ;;
  esac
}

test_warnings_disabled_by_env() {
  base=$($CAGED $RO -- true 2>&1 >/dev/null)
  err=$(CAGED_DISABLE_WARNINGS=1 $CAGED $RO -- true 2>&1 >/dev/null)
  check "CAGED_DISABLE_WARNINGS=1 silences the warnings" "" "$err"
  if [ -n "$base" ]; then
    ok "warnings were present by default and got suppressed"
  fi
}

# --require-abi turns the ABI warning into a hard failure: a floor the kernel
# cannot meet must fail before the sandbox is built.
test_require_abi_unmet_exits_1() {
  err=$(CAGED_DISABLE_WARNINGS=1 $CAGED $RO --require-abi 99 -- true 2>&1 >/dev/null)
  check "--require-abi above the kernel ABI exits 1" 1 $?
  case "$err" in
  *"Landlock ABI"*"required"*) ok "--require-abi reports both numbers" ;;
  *) bad "--require-abi reports both numbers ('$err')" ;;
  esac
}

test_require_abi_met_runs() {
  $CAGED $RO --require-abi 1 -- true 2>/dev/null
  check "--require-abi 1 is satisfied by any kernel" 0 $?
}

test_help_long() {
  out=$($CAGED --help 2>/dev/null)
  check "--help exits 0" 0 $?
  case "$out" in
  "usage: caged"*) ok "--help prints the usage line" ;;
  *) bad "--help prints the usage line" ;;
  esac
}

test_help_short() {
  out=$($CAGED -h 2>/dev/null)
  check "-h exits 0" 0 $?
  case "$out" in
  "usage: caged"*) ok "-h prints the usage line" ;;
  *) bad "-h prints the usage line" ;;
  esac
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

  test_net_connect_denied_by_default
  test_net_connect_allowed_by_port
  test_net_connect_allowed_general
  test_net_bind_denied_by_default
  test_net_bind_allowed_by_port
  test_net_bind_allowed_general

  test_af_packet_is_denied
  test_sock_raw_is_denied
  test_sock_raw_cloexec_is_denied
  test_udp_socket_is_denied
  test_netlink_usersock_is_denied
  test_unix_socket_is_denied
  test_family_above_af_max_is_denied
  test_docker_sock_is_unreachable

  test_sysv_ipc_denied
  test_sysv_ipc_allowed_with_flag

  test_inherited_fd_is_closed
  test_core_dump_disabled
  test_max_procs_set

  test_ptrace_is_denied
  test_io_uring_is_denied
  test_ordinary_syscalls_still_work

  test_env_is_cleared_by_default
  test_env_keeps_path_and_locale
  test_keep_env_inherits_all
  test_env_flag_sets_variable
  test_env_flag_overrides_without_duplicating

  test_restrict_flags_accepted
  test_tsync_applies_seccomp

  test_warnings_printed_by_default
  test_require_abi_unmet_exits_1
  test_require_abi_met_runs
  test_warnings_disabled_by_env

  test_help_long
  test_help_short

  printf '\n%d passed, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

main
