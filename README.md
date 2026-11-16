# Caged

Caged is a small process sandbox for Linux built on top of
[Landlock](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html),
[seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
and  [namespaces](https://www.man7.org/linux/man-pages/man7/namespaces.7.html).
It locks a process (and its children) denying everything by
default and granting only what is explicitly allowed.

```
caged [OPTIONS] -- CMD [ARGS...]
```

`--` separates caged's options from the command to run (via `execvp`).


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

A minimal interactive shell:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib -- sh
```

Add a writable scratch directory when the shell needs to write:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib --rw /tmp -- sh
```

Or give it a `/tmp` of its own, a fresh tmpfs, to avoid writing on the global
`/tmp` directory:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib --private-tmp --rw /tmp -- sh
```

`--private-shm` does the same for `/dev/shm`:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib --private-shm --rw /dev/shm -- sh
```

Fetch a page over HTTPS:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib --ro /etc \
      --allow-network-sockets --allow-connect-port 443 -- curl https://example.com
```

Serve a directory on a fixed local port:

```sh
./build/caged --ro /usr --ro /bin --ro /usr/lib --ro "$PWD" \
      --allow-network-sockets --allow-bind-port 8080 -- python3 -m http.server 8080
```

Talk to a local service over a unix socket:

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
