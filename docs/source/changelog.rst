Changelog
=========

Unreleased
----------

Library split and documentation updates.

- The single translation unit is now five files, along a library /
  command-line boundary: ``caged.h`` (public interface — ``enum caged_return``,
  ``struct cmd_opts``, the diagnostics globals and the ``caged_setup`` /
  ``caged_strreturn`` / ``cmd_opts_free`` declarations), ``caged.c`` (the
  sandbox logic, nothing else), ``cli.h`` / ``cli.c`` (argument parsing, usage
  text, ABI warnings and the command environment) and ``main.c`` (the ``die``
  and ``main`` front end).
- ``caged_setup``, ``caged_strreturn`` and ``cmd_opts_free`` are the library
  API; ``parse_cmd_line``, ``print_help``, ``build_env`` and
  ``warn_unsupported_features`` are declared in ``cli.h``. The diagnostics
  globals (``seccomp_detail``, ``seccomp_failed_family``,
  ``seccomp_failed_syscall``, ``abi_found``) are ``extern`` and declared in
  ``caged.h``. All other helpers stay ``static``.
- The library no longer writes to ``stderr``: the ABI warnings moved out of
  ``caged_setup`` and are printed by ``main``, which is the only piece that
  knows about the terminal. The wording and the ``CAGED_DISABLE_WARNINGS``
  switch are unchanged.
- The ``LANDLOCK_*`` fallback macros moved to ``caged.h``, since both
  ``caged.c`` and ``cli.c`` need them.
- The environment moved into the library: ``build_env`` and ``BASE_ENV`` live
  in ``caged.c``, and ``caged_setup`` gained a ``char ***env`` out-parameter.
  On success it also replaces the process environment (anything outside the
  base set, ``--keep-env`` and ``--env`` is unset), so a child started with
  ``execvp`` inherits the filtered set. New return code
  ``CAGED_ERR_ENV`` when the array cannot be allocated.
- ``CAGED_DISABLE_WARNINGS`` is read before the environment is replaced and
  kept in ``caged_warnings_disabled``, so the switch still works.
- The unit tests still include ``caged.c`` (and ``cli.c`` where needed) to
  reach the ``static`` helpers. Coverage stays at 100%
  line/branch/decision/function, now measured over ``caged.c`` and ``cli.c``.

v0.2.0
------

Second release. Adds a seccomp layer, hardening of the process itself and a
fail-closed ABI floor.

Seccomp layer
~~~~~~~~~~~~~

- New build dependency: libseccomp (``libseccomp-dev``), linked with
  ``-lseccomp``. ``make`` fails early with an actionable message when
  ``<seccomp.h>`` is missing.
- Every socket family except ``AF_INET``, ``AF_INET6``, ``AF_NETLINK`` and
  ``AF_UNIX`` is denied with ``EACCES``, including family numbers above this
  build's ``AF_MAX`` — a newer kernel cannot open a family the filter does not
  know about.
- ``--allow-network-sockets`` and ``--allow-unix-sockets`` release
  ``AF_INET``/``AF_INET6``/``AF_NETLINK`` and ``AF_UNIX``.
- Raw sockets (``AF_INET``/``AF_INET6`` with ``SOCK_RAW``, compared through a
  mask so ``SOCK_CLOEXEC`` does not slip through) and ``NETLINK_USERSOCK`` are
  always denied.
- System V IPC — the ``msg*``, ``sem*`` and ``shm*`` entries, twelve syscalls —
  is denied with ``ENOSYS``; ``--allow-sysv-ipc`` releases it.
- Dangerous syscalls are always denied with ``ENOSYS``: ``ptrace``,
  ``process_vm_readv``, ``process_vm_writev``, ``pidfd_getfd``,
  ``process_madvise``, ``kcmp``, ``keyctl``, ``add_key``, ``request_key``,
  ``io_uring_setup``, ``bpf``, ``perf_event_open`` and ``userfaultfd``.
  ``io_uring_setup`` closes the bypass where ``IORING_OP_SOCKET`` and
  ``IORING_OP_CONNECT`` never appear as syscalls.
- A failed rule names the offending socket family or syscall, and libseccomp's
  negative return code is turned back into ``errno``.

Process hardening
~~~~~~~~~~~~~~~~~

- Inherited file descriptors above stderr are closed
  (``close_range(3, ~0U, 0)``) before the command runs: neither Landlock nor
  seccomp can revoke a descriptor that already exists.
- ``RLIMIT_CORE`` is set to 0, soft and hard, so a crash cannot dump process
  memory into a path the command chooses.
- ``--max-procs N`` sets ``RLIMIT_NPROC``. It is opt-in because the limit is
  counted per real uid over the whole system.

Environment
~~~~~~~~~~~

- The command's environment is cleared by default. Only ``PATH``, ``HOME``,
  ``LANG``, ``LANGUAGE``, ``LC_ALL`` and the twelve remaining ``LC_*``
  categories from ``locale.h`` are inherited.
- ``--keep-env`` inherits everything.
- ``--env NAME=VALUE`` sets one variable, may be repeated, and overrides an
  inherited variable by name.
- ``execvp`` was replaced with ``execvpe``.

ABI
~~~

- ``--require-abi N`` turns the "your kernel is older than this feature"
  warning into ``CAGED_ERR_ABI_TOO_OLD``. It is checked right after the probe,
  before any ruleset exists. Without the option caged still warns and runs.

Breaking changes
~~~~~~~~~~~~~~~~

- The command no longer inherits the caller's environment; use ``--keep-env``
  or ``--env``.
- Inherited file descriptors are closed. A caller that used to hand one over
  must use a pipe or a file instead.
- Exit status 1 now also covers an unmet ABI floor, a resource limit that could
  not be set, a failure closing descriptors and a seccomp failure.

Tests and documentation
~~~~~~~~~~~~~~~~~~~~~~~

- The functional suite grew from 24 to 74 cases, covering socket families,
  ``SOCK_RAW`` with and without ``SOCK_CLOEXEC``, UDP, ``NETLINK_USERSOCK``,
  ``AF_UNIX``, SysV IPC, inherited descriptors, core dumps, ``--max-procs``,
  ``ptrace``, ``io_uring_setup``, the environment and ``--require-abi``.
- New ``test_env`` unit suite plus golden tests over ``seccomp_export_pfc``;
  mocks added for ``setrlimit``, ``close_range`` and
  ``seccomp_syscall_resolve_name``.
- Functional tests derive the ``python3`` prefix instead of assuming ``/usr``.
- Documentation gained sections on the seccomp layer, limits and descriptors,
  the command environment and the ABI floor.
- Coverage stays at 100% line/branch/decision/function over ``caged.c``,
  enforced by ``make check``.

v0.1.0
------

Initial release.

- Filesystem sandbox with ``--ro`` / ``--rw`` on directories and single files.
- Network sandbox (TCP connect/bind) gated on Landlock ABI 4.
- IPC scopes (signal, abstract unix sockets) gated on ABI 6.
- ``landlock_restrict_self`` log and ``TSYNC`` flags gated on ABI 7/8.
- ``LANDLOCK_ACCESS_FS_RESOLVE_UNIX`` gated on ABI 9.
- ABI compatibility warnings, silenced with ``CAGED_DISABLE_WARNINGS=1``.
- ``--help`` / ``-h``; help printed on stderr when run with no arguments.
- Dynamic (unbounded) path and port lists.
- Unit test suite with linker ``--wrap`` mocks plus functional tests against
  the real kernel; 100% line/branch/decision/function coverage over
  ``caged.c``.
