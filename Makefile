CC          := gcc
CFLAGS      := -Wall -Wextra -g
# libseccomp ships no headers outside the default include path, so there is
# nothing for pkg-config to discover beyond the library name itself.
LDLIBS      := -lseccomp
TEST_CFLAGS := $(CFLAGS) -O0 -U_FORTIFY_SOURCE -fno-builtin
WRAP        := -Wl,--wrap=syscall -Wl,--wrap=open -Wl,--wrap=fstat -Wl,--wrap=close -Wl,--wrap=prctl -Wl,--wrap=realloc \
               -Wl,--wrap=setrlimit -Wl,--wrap=close_range
SECCOMP_WRAP := -Wl,--wrap=seccomp_init -Wl,--wrap=seccomp_rule_add_exact \
                -Wl,--wrap=seccomp_load -Wl,--wrap=seccomp_release \
                -Wl,--wrap=seccomp_syscall_resolve_name
WRAP_FULL   := $(WRAP) $(SECCOMP_WRAP)
BUILD_DIR   := build
UNIT        := tests/unit
COV_DIR     := $(BUILD_DIR)/cov
COV_CFLAGS  := $(TEST_CFLAGS) --coverage -fcondition-coverage
DOCS_DIR    := docs
DOCS_VENV   := $(HOME)/.virtualenvs/caged-docs

UNIT_TESTS  := test_abi test_allow_access test_parse_cmd_line test_setup test_net test_help test_seccomp_pfc
UNIT_BINS   := $(addprefix $(BUILD_DIR)/,$(UNIT_TESTS))
COV_BINS    := $(addprefix $(COV_DIR)/,$(UNIT_TESTS))

.PHONY: all build unit test functional check coverage clean docs docs-env seccomp-dep

all: build

build: seccomp-dep $(BUILD_DIR)/caged

# Fails early with an actionable message instead of a linker error.  Checks
# what actually matters: that the compiler can see <seccomp.h>.
seccomp-dep:
	@printf '#include <seccomp.h>\nint main(void){return 0;}\n' | \
	  $(CC) -x c -fsyntax-only - 2>/dev/null || \
	  { echo "libseccomp headers not found: sudo apt install libseccomp-dev" >&2; exit 1; }

$(BUILD_DIR)/caged: caged.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

unit: $(UNIT_BINS)
	@set -e; for t in $(UNIT_BINS); do echo "== $$t"; $$t; done

$(BUILD_DIR)/test_%: $(UNIT)/test_%.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) $(WRAP_FULL) -o $@ $< $(UNIT)/fake_syscalls.c $(LDLIBS)

# The pseudo-filter-code test uses the real libseccomp on purpose (it checks
# the generated rules): no mocks, no fake_syscalls.
$(BUILD_DIR)/test_seccomp_pfc: $(UNIT)/test_seccomp_pfc.c caged.c
	mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) -o $@ $< $(LDLIBS)

test: unit functional

functional: build
	CAGED=$(BUILD_DIR)/caged sh tests/functional/run.sh

check: seccomp-dep unit coverage functional

coverage: $(COV_BINS)
	@set -e; for t in $(COV_BINS); do $$t; done
	mkdir -p $(COV_DIR)/report
	gcovr --root . --filter 'caged\.c$$' \
	      --txt --txt-summary \
	      --html-details $(COV_DIR)/report/index.html \
	      --decision \
	      --fail-under-line 100 \
	      --fail-under-branch 100 \
	      --fail-under-decision 100 \
	      --fail-under-function 100 \
	      $(COV_DIR)

$(COV_DIR)/test_%: $(UNIT)/test_%.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(COV_CFLAGS) $(WRAP_FULL) -o $@ $< $(UNIT)/fake_syscalls.c $(LDLIBS)

$(COV_DIR)/test_seccomp_pfc: $(UNIT)/test_seccomp_pfc.c caged.c
	mkdir -p $(@D)
	$(CC) $(COV_CFLAGS) -o $@ $< $(LDLIBS)

docs:
	$(MAKE) -C $(DOCS_DIR) html

docs-env:
	python3 -m venv $(DOCS_VENV)
	$(DOCS_VENV)/bin/pip install -r $(DOCS_DIR)/requirements.txt

clean:
	rm -rf $(BUILD_DIR)
