# Caged

A small process sandbox for Linux built on the
[Landlock](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html)
LSM. It locks a process (and its children) into a ruleset, denying everything
by default and granting only what is explicitly allowed.

```
caged [OPTIONS] -- CMD [ARGS...]
```

`--` separates caged's options from the command to run (via `execvp`).

## Features

- **Filesystem** — deny-by-default; grant read (`--ro`) or read+write (`--rw`)
  on a directory *or a single file*.
- **Network** — deny-by-default TCP connect/bind; grant per port
  (`--allow-connect-port` / `--allow-bind-port`, port `0` = ephemeral range)
  or a whole direction (`--allow-connect-tcp` / `--allow-bind-tcp`).
- **IPC scopes** — signalling and abstract unix sockets are restricted by
  default; release them with `--allow-scoped-signal` /
  `--allow-scoped-abstract-unix`.
- **ABI awareness** — every right/feature is gated on the kernel's Landlock
  ABI; unsupported ones are dropped and a warning is printed. Silence the
  warning with `CAGED_DISABLE_WARNINGS=1`.


## Build

To compile, the following dependencies are needed: a C compiler,
`make`, and Linux kernel headers providing `linux/landlock.h`.

Then run:

```sh
$ make
```

This is going to build the ``caged`` binary in ``build/caged``.

## Usage

Caged denies everything by default and only grants what you ask for, so the
examples below show exactly what each command is allowed to reach.

Read a single file:

```sh
./build/caged --ro /usr/bin/cat --ro /usr/lib --ro /etc/hostname -- cat /etc/hostname
```

The command itself and the shared libraries it needs must be reachable too.
With only `/etc/hostname` granted, `cat` would fail to start. Also note that
`--ro /etc/hostname` grants that single file: every other file under `/etc`
stays unreadable.

A minimal interactive shell — the system trees holding programs and their
shared libraries are read-only:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib -- sh
```

Add a writable scratch directory when the shell needs to write:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib --rw /tmp -- sh
```

Fetch a page over HTTPS — the network is denied unless a port (or a whole
direction) is allowed:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib --ro /etc \
      --allow-connect-port 443 -- curl https://example.com
```

Serve a directory on a fixed local port:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib --ro "$PWD" \
      --allow-bind-port 8080 -- python3 -m http.server 8080
```

Print the available options:

```sh
./build/caged --help
```

## Testing

To run the test suite the following dependencies are needed: `gcovr` and `python3`.

```sh
make unit       # compile and run the unit tests
make functional # run the integration tests (real kernel) against build/caged
make test       # unit + functional
make check      # unit + coverage + functional (full gate)
make coverage   # gcovr report (fails below 100%)
make clean      # rm -rf build/
```

100% line/branch/decision/function coverage over `caged.c`, enforced by
`make check`. Unit tests use linker `--wrap` mocks; functional tests exercise
the real binary against the kernel.
