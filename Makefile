CC          := gcc
CFLAGS      := -Wall -Wextra -g
TEST_CFLAGS := $(CFLAGS) -O0 -U_FORTIFY_SOURCE -fno-builtin
WRAP        := -Wl,--wrap=syscall -Wl,--wrap=open -Wl,--wrap=fstat -Wl,--wrap=close -Wl,--wrap=prctl -Wl,--wrap=realloc
BUILD_DIR   := build
UNIT        := tests/unit
COV_DIR    := $(BUILD_DIR)/cov
COV_CFLAGS := $(TEST_CFLAGS) --coverage -fcondition-coverage
DOCS_DIR   := docs
DOCS_VENV  := $(HOME)/.virtualenvs/caged-docs

.PHONY: all build unit test functional check coverage clean docs docs-env

all: build

build: $(BUILD_DIR)/caged

$(BUILD_DIR)/caged: caged.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $<

unit: $(BUILD_DIR)/test_abi $(BUILD_DIR)/test_allow_access $(BUILD_DIR)/test_parse_cmd_line $(BUILD_DIR)/test_setup $(BUILD_DIR)/test_net $(BUILD_DIR)/test_help
	$(BUILD_DIR)/test_abi
	$(BUILD_DIR)/test_allow_access
	$(BUILD_DIR)/test_parse_cmd_line
	$(BUILD_DIR)/test_setup
	$(BUILD_DIR)/test_net
	$(BUILD_DIR)/test_help

$(BUILD_DIR)/test_abi: $(UNIT)/test_abi.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) $(WRAP) -o $@ $(UNIT)/test_abi.c $(UNIT)/fake_syscalls.c

$(BUILD_DIR)/test_allow_access: $(UNIT)/test_allow_access.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) $(WRAP) -o $@ $(UNIT)/test_allow_access.c $(UNIT)/fake_syscalls.c

$(BUILD_DIR)/test_parse_cmd_line: $(UNIT)/test_parse_cmd_line.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) $(WRAP) -o $@ $(UNIT)/test_parse_cmd_line.c $(UNIT)/fake_syscalls.c

$(BUILD_DIR)/test_setup: $(UNIT)/test_setup.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) $(WRAP) -o $@ $(UNIT)/test_setup.c $(UNIT)/fake_syscalls.c

$(BUILD_DIR)/test_net: $(UNIT)/test_net.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) $(WRAP) -o $@ $(UNIT)/test_net.c $(UNIT)/fake_syscalls.c

$(BUILD_DIR)/test_help: $(UNIT)/test_help.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) $(WRAP) -o $@ $(UNIT)/test_help.c $(UNIT)/fake_syscalls.c

test: unit functional

functional: build
	CAGED=$(BUILD_DIR)/caged sh tests/functional/run.sh

check: unit coverage functional

coverage: $(COV_DIR)/test_abi $(COV_DIR)/test_allow_access $(COV_DIR)/test_parse_cmd_line $(COV_DIR)/test_setup $(COV_DIR)/test_net $(COV_DIR)/test_help
	$(COV_DIR)/test_abi
	$(COV_DIR)/test_allow_access
	$(COV_DIR)/test_parse_cmd_line
	$(COV_DIR)/test_setup
	$(COV_DIR)/test_net
	$(COV_DIR)/test_help
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

$(COV_DIR)/test_abi: $(UNIT)/test_abi.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(COV_CFLAGS) $(WRAP) -o $@ $(UNIT)/test_abi.c $(UNIT)/fake_syscalls.c

$(COV_DIR)/test_allow_access: $(UNIT)/test_allow_access.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(COV_CFLAGS) $(WRAP) -o $@ $(UNIT)/test_allow_access.c $(UNIT)/fake_syscalls.c

$(COV_DIR)/test_parse_cmd_line: $(UNIT)/test_parse_cmd_line.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(COV_CFLAGS) $(WRAP) -o $@ $(UNIT)/test_parse_cmd_line.c $(UNIT)/fake_syscalls.c

$(COV_DIR)/test_setup: $(UNIT)/test_setup.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(COV_CFLAGS) $(WRAP) -o $@ $(UNIT)/test_setup.c $(UNIT)/fake_syscalls.c

$(COV_DIR)/test_net: $(UNIT)/test_net.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(COV_CFLAGS) $(WRAP) -o $@ $(UNIT)/test_net.c $(UNIT)/fake_syscalls.c

$(COV_DIR)/test_help: $(UNIT)/test_help.c $(UNIT)/fake_syscalls.c $(UNIT)/fake_syscalls.h caged.c
	mkdir -p $(@D)
	$(CC) $(COV_CFLAGS) $(WRAP) -o $@ $(UNIT)/test_help.c $(UNIT)/fake_syscalls.c

docs:
	$(MAKE) -C $(DOCS_DIR) html

docs-env:
	python3 -m venv $(DOCS_VENV)
	$(DOCS_VENV)/bin/pip install -r $(DOCS_DIR)/requirements.txt

clean:
	rm -rf $(BUILD_DIR)
