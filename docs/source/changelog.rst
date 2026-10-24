Changelog
=========

v0.4.0
------

Fourth release. Gives caged's own failures their own exit status, so a caller
that wraps it can tell a broken sandbox from a command that exited with the
same code. No command-line option changed and no policy changed.

Exit status
~~~~~~~~~~~

- A setup or ``exec`` failure now exits with **125** instead of 1, freeing 1
  for the command. ``2`` stays the usage error and every other status is the
  command's, so a wrapper can tell a broken invocation, a broken sandbox and a
  command that exited with the same number apart. 125 is the convention for
  "the wrapper failed", as used by ``sh``, ``sudo`` and ``docker run``.

Tests
~~~~~

- New ``make valgrind`` target: memcheck (``--error-exitcode=1``) over every
  unit binary, one log per binary, so an uninitialised read or a leak fails
  the build. Out of scope on purpose: the production binary, which ends in
  ``execve`` or in ``exit`` with the options still on the stack.
- New ``make sanitize`` target: the same tests under
  ``-fsanitize=address,undefined`` with ``-fno-sanitize-recover``, catching
  undefined behaviour memcheck does not model.
- Both run in CI as their own steps, outside ``make check``.

Upgrading
~~~~~~~~~

- Scripts that checked ``$? = 1`` for a setup or ``exec`` failure must check
  ``125``. A command that exits with 1 is now distinguishable from caged
  failing.

v0.3.0
------

Third release. Splits the single translation unit into a library and a
command-line front end, so caged can be embedded in another program to wrap a
whole client process at launch. No command-line option changed and the exit
codes are the same: 2 for a usage error, 1 for a setup or exec failure.

Library
~~~~~~~

- ``caged.h`` is the public interface: ``enum caged_return``,
  ``struct cmd_opts``, the diagnostics globals (``seccomp_detail``,
  ``seccomp_failed_family``, ``seccomp_failed_syscall``, ``abi_found``), the
  ``caged_setup`` / ``caged_strreturn`` / ``cmd_opts_free`` declarations and
  the ``LANDLOCK_*`` fallback macros an older system's headers lack.
- ``caged.c`` holds the sandbox and only that: it parses no arguments and
  never writes to ``stderr``, so it links into another program cleanly. Every
  helper outside the API stays ``static``.
- ``cli.h`` / ``cli.c`` take the front end — ``parse_cmd_line``,
  ``print_help`` and ``warn_unsupported_features`` — while ``main.c`` holds
  ``die`` and ``main``.
- ``make lib`` builds ``build/libcaged.a`` from ``caged.o``; plain ``make``
  now produces the archive together with the binary, and ``make build`` /
  ``make lib`` still select a single one.
- The ABI warnings left ``caged_setup``: the library records the ABI in
  ``abi_found`` and the front end decides whether, when and in which format to
  report the gap. The wording and ``CAGED_DISABLE_WARNINGS=1`` are unchanged.

Environment
~~~~~~~~~~~

- ``build_env`` and ``BASE_ENV`` moved from the front end into the library, so
  an embedder also filters the environment of whatever it execs.
- ``caged_setup`` gained a ``char ***env`` out-parameter and now replaces the
  process environment itself as its last step (``clearenv`` plus a ``setenv``
  per allowed entry). A ``NULL`` out-parameter still replaces ``environ``, it
  just does not hand the array back; the caller owns the array and frees it.
- New return code ``CAGED_ERR_ENV`` when the array cannot be allocated.
- ``CAGED_DISABLE_WARNINGS`` is not part of the inherited base set, so it is
  read before the replacement and recorded in ``caged_warnings_disabled``;
  ``warn_unsupported_features`` checks that flag instead of ``getenv``, and the
  switch keeps working after the setup.

Seccomp
~~~~~~~

- ``--tsync`` now reaches both layers. Besides the Landlock restrict-self bit
  (ABI 8), ``apply_seccomp`` sets ``SCMP_FLTATR_CTL_TSYNC``, so the filter is
  applied to every thread of the thread group instead of only to the calling
  thread and its children. The attribute has no Landlock ABI gate — it needs
  libseccomp API level 2 / kernel 3.17 — so it works even on kernels too old
  for the restrict-self bit.
- New return code ``CAGED_ERR_SECCOMP_TSYNC`` when the attribute cannot be
  set: the setup fails rather than installing a one-thread filter in silence.
- The ``seccomp_load`` result is checked against zero instead of ``-1``,
  because a failed synchronization returns the tid of the offending thread, a
  positive value.

Tests and documentation
~~~~~~~~~~~~~~~~~~~~~~~

- The unit tests keep including ``caged.c`` (and ``cli.c`` where needed) to
  reach the ``static`` helpers. Coverage stays at 100%
  line/branch/decision/function, now measured over ``caged.c`` and ``cli.c``.
- New unit tests for the environment replacement, the ``NULL``
  out-parameter, ``CAGED_ERR_ENV`` and the warning switch; ``strndup`` is
  wrapped so the copy failure can be exercised.
- New unit tests for the seccomp TSYNC attribute: set only with ``--tsync``,
  what happens when it cannot be set, and the positive tid a failed
  synchronization returns.
- The functional suite gained a ``--tsync`` case, 75 cases now, checking that
  the socket filter is still in force with the flag.
- New :doc:`library` page on embedding caged: the API, the command-line option
  each ``struct cmd_opts`` field mirrors, the one-way side effects of
  ``caged_setup``, the environment out-parameter, ``TSYNC`` for multi-threaded
  callers and the diagnostics globals.

Upgrading
~~~~~~~~~

- ``caged_setup`` now takes a second argument, the optional ``char ***env``
  out-parameter, and replaces ``environ`` instead of leaving it alone.
- A run with ``--tsync`` fails on a kernel or libseccomp too old to
  synchronize the seccomp filter, where it used to confine only the calling
  thread (through the Landlock bit alone, when the ABI had it).

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
