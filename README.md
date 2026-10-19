# Caged

Caged is a small process sandbox for Linux built on top of
[Landlock](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html)
and [seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html).
It locks a process (and its children) denying everything by
default and granting only what is explicitly allowed.

```
caged [OPTIONS] -- CMD [ARGS...]
```

`--` separates caged's options from the command to run (via `execvp`).

## Features

- **Filesystem**: denied by default. grant read (`--ro`) or read+write (`--rw`)
  on a directory *or a single file*.
- **Network**: denied by default; grant per port
  (`--allow-connect-port` / `--allow-bind-port`, port `0` = ephemeral range)
  or a whole direction (`--allow-connect-tcp` / `--allow-bind-tcp`). A TCP
  connection also needs its socket family, so pair these with
  `--allow-network-sockets`.
- **IPC scopes**: signalling and abstract unix sockets are restricted by
  default; release them with `--allow-scoped-signal` /
  `--allow-scoped-abstract-unix`.
- **System V IPC**: denied by default (shared memory, message queues and
  semaphores fail with `ENOSYS`); release it with `--allow-sysv-ipc`.
- **Limits and descriptors**: core dumps are disabled and inherited file
  descriptors above stderr are closed before the command runs; `--max-procs
  N` caps `RLIMIT_NPROC`.
- **Socket families**: every family except `AF_INET`, `AF_INET6` and
  `AF_NETLINK` is denied, including `AF_UNIX`; release them with
  `--allow-network-sockets` / `--allow-unix-sockets`. Raw sockets
  are always denied.


## Build

To compile, the following dependencies are needed: a C compiler, `make`, the
`libseccomp` development files (`libseccomp-dev`) and Linux kernel headers
providing `linux/landlock.h`.

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

Fetch a page over HTTPS — the network is denied unless the socket family and
the port are allowed:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib --ro /etc \
      --allow-network-sockets --allow-connect-port 443 -- curl https://example.com
```

Serve a directory on a fixed local port:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib --ro "$PWD" \
      --allow-network-sockets --allow-bind-port 8080 -- python3 -m http.server 8080
```

Talk to a local service over a unix socket — unix sockets are denied by
default:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib --allow-unix-sockets \
      -- curl --unix-socket /run/myapp.sock http://localhost/health
```

Print the available options:

```sh
./build/caged --help
```

## Documentation

Full documentation can be found at https://docs.poraodojuca.dev/caged
