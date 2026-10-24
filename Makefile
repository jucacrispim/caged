CC          := gcc
CFLAGS      := -Wall -Wextra -g
# libseccomp ships no headers outside the default include path, so there is
# nothing for pkg-config to discover beyond the library name itself.
LDLIBS      := -lseccomp
TEST_CFLAGS := $(CFLAGS) -O0 -U_FORTIFY_SOURCE -fno-builtin
WRAP        := -Wl,--wrap=syscall -Wl,--wrap=open -Wl,--wrap=fstat -Wl,--wrap=close -Wl,--wrap=prctl -Wl,--wrap=realloc -Wl,--wrap=strndup \
               -Wl,--wrap=setrlimit -Wl,--wrap=close_range
SECCOMP_WRAP := -Wl,--wrap=seccomp_init -Wl,--wrap=seccomp_rule_add_exact \
                -Wl,--wrap=seccomp_attr_set \
                -Wl,--wrap=seccomp_load -Wl,--wrap=seccomp_release \
                -Wl,--wrap=seccomp_syscall_resolve_name
WRAP_FULL   := $(WRAP) $(SECCOMP_WRAP)
BUILD_DIR   := build
UNIT        := tests/unit
COV_DIR     := $(BUILD_DIR)/cov
COV_CFLAGS  := $(TEST_CFLAGS) --coverage -fcondition-coverage
SAN_DIR     := $(BUILD_DIR)/san
SAN_CFLAGS  := $(TEST_CFLAGS) -fsanitize=address,undefined \
               -fno-sanitize-recover=all -fno-omit-frame-pointer
VALGRIND    ?= valgrind
# --error-exitcode turns a report into a build failure (without it valgrind
# exits with the program's own status and CI passes regardless).
# --errors-for-leak-kinds is explicit so the "possible" leaks the glibc
# environment machinery produces do not fail the run.
VG_FLAGS    := --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
               --errors-for-leak-kinds=definite,indirect --track-origins=yes
DOCS_DIR    := docs
DOCS_VENV   := $(HOME)/.virtualenvs/caged-docs

UNIT_TESTS  := test_abi test_allow_access test_parse_cmd_line test_setup test_net test_help test_seccomp_pfc test_env
UNIT_BINS   := $(addprefix $(BUILD_DIR)/,$(UNIT_TESTS))
COV_BINS    := $(addprefix $(COV_DIR)/,$(UNIT_TESTS))
SAN_BINS    := $(addprefix $(SAN_DIR)/,$(UNIT_TESTS))

# The library (caged.c) and the command-line front end (cli.c) are measured
# separately: most test binaries include one, the parsing/help/env ones
# include both.
COV_SOURCES := --filter 'caged\.c$$' --filter 'cli\.c$$'

# The library form: caged.o is the sandbox and only that (no parser, no main),
# so a consumer that wants to embed the sandbox links libcaged.a and includes
# caged.h. The command-line front end is not part of it; a consumer that also
# wants parse_cmd_line / warn_unsupported_features compiles cli.c as well.
LIB         := $(BUILD_DIR)/libcaged.a

.PHONY: all build lib unit test functional check coverage valgrind sanitize clean docs docs-env seccomp-dep

all: build lib

build: seccomp-dep $(BUILD_DIR)/caged

lib: seccomp-dep $(LIB)

$(BUILD_DIR)/caged.o: caged.c caged.h
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ caged.c

$(LIB): $(BUILD_DIR)/caged.o
	$(AR) rcs $@ $<

# Fails early with an actionable message instead of a linker error.  Checks
# what actually matters: that the compiler can see <seccomp.h>.
seccomp-dep:
	@printf '#include <seccomp.h>\nint main(void){return 0;}\n' | \
	  $(CC) -x c -fsyntax-only - 2>/dev/null || \
	  { echo "libseccomp headers not found: sudo apt install libseccomp-dev" >&2; exit 1; }

$(BUILD_DIR)/caged: caged.c cli.c main.c caged.h cli.h
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ caged.c cli.c main.c $(LDLIBS)

unit: $(UNIT_BINS)
	@set -e; for t in $(UNIT_BINS); do echo "== $$t"; $$t; done

$(BUILD_DIR)/test_%: $(UNIT)/test_%.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c caged.h cli.c cli.h
	mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) $(WRAP_FULL) -o $@ $< $(UNIT)/fake_syscalls.c $(LDLIBS)

# The pseudo-filter-code test uses the real libseccomp on purpose (it checks
# the generated rules): no mocks, no fake_syscalls, and no cli.c either.
$(BUILD_DIR)/test_seccomp_pfc: $(UNIT)/test_seccomp_pfc.c caged.c caged.h
	mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) -o $@ $< $(LDLIBS)

test: unit functional

functional: build
	CAGED=$(BUILD_DIR)/caged sh tests/functional/run.sh

check: seccomp-dep unit coverage functional

coverage: $(COV_BINS)
	@set -e; for t in $(COV_BINS); do $$t; done
	mkdir -p $(COV_DIR)/report
	gcovr --root . $(COV_SOURCES) \
	      --txt --txt-summary \
	      --html-details $(COV_DIR)/report/index.html \
	      --decision \
	      --fail-under-line 100 \
	      --fail-under-branch 100 \
	      --fail-under-decision 100 \
	      --fail-under-function 100 \
	      $(COV_DIR)

$(COV_DIR)/test_%: $(UNIT)/test_%.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c caged.h cli.c cli.h
	mkdir -p $(@D)
	$(CC) $(COV_CFLAGS) $(WRAP_FULL) -o $@ $< $(UNIT)/fake_syscalls.c $(LDLIBS)

$(COV_DIR)/test_seccomp_pfc: $(UNIT)/test_seccomp_pfc.c caged.c caged.h
	mkdir -p $(@D)
	$(CC) $(COV_CFLAGS) -o $@ $< $(LDLIBS)

# Memcheck over the unit binaries. The production binary is deliberately out of
# scope: it ends in execve, where valgrind does no leak check at all, or in exit
# with the option arrays still on main's stack — every report would be "still
# reachable" and would pressure the code into pointless frees on error paths.
# The unit binaries drive the whole heap surface instead, 100% of the paths
# included, and they catch what coverage cannot see: uninitialised reads (a
# fstat fake that leaves fields of struct stat unset, for instance).
#
# --log-file, never --log-fd: capture_warnings() redirects stderr into a pipe
# and asserts that it reads nothing back, so a report on fd 2 would fail the
# test it is trying to check. A log file per binary also keeps the reports
# readable in CI.
valgrind: $(UNIT_BINS)
	@set -e; for t in $(UNIT_BINS); do \
	  echo "== valgrind $$t"; \
	  $(VALGRIND) $(VG_FLAGS) \
	    --log-file=$(BUILD_DIR)/valgrind.$$(basename $$t).log $$t; \
	done
	@echo "valgrind: no errors"

# The same tests under the compilers' own instrumentation. It overlaps with
# memcheck but is not a replacement: it catches undefined behaviour memcheck
# does not model (signed overflow in the capacity arithmetic, for instance) and
# runs an order of magnitude faster. -fno-sanitize-recover makes every finding
# fatal, so the target fails instead of printing and carrying on.
sanitize: $(SAN_BINS)
	@set -e; for t in $(SAN_BINS); do echo "== $$t"; $$t; done

$(SAN_DIR)/test_%: $(UNIT)/test_%.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c caged.h cli.c cli.h
	mkdir -p $(@D)
	$(CC) $(SAN_CFLAGS) $(WRAP_FULL) -o $@ $< $(UNIT)/fake_syscalls.c $(LDLIBS)

$(SAN_DIR)/test_seccomp_pfc: $(UNIT)/test_seccomp_pfc.c caged.c caged.h
	mkdir -p $(@D)
	$(CC) $(SAN_CFLAGS) -o $@ $< $(LDLIBS)

docs:
	$(MAKE) -C $(DOCS_DIR) html

docs-env:
	python3 -m venv $(DOCS_VENV)
	$(DOCS_VENV)/bin/pip install -r $(DOCS_DIR)/requirements.txt

clean:
	rm -rf $(BUILD_DIR)
