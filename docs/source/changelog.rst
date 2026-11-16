Changelog
=========

Unreleased
----------

Four changes are pending: three new options that build namespaces for the
command (a private ``/tmp``, a private ``/dev/shm`` and a private network), and
a closed seccomp denylist.

``--private-tmp``
~~~~~~~~~~~~~~~~~

New option: the sandbox builds a **mount namespace** for the command and
mounts something else over ``/tmp`` in it — a fresh, 1 GiB, ``nosuid``/``nodev``
tmpfs, or the directory given as an argument, bind-mounted there. The host's
``/tmp`` stops being reachable from inside, and what the sandbox writes there
dies with it (or lands in the bind source, when one was given).

The point is the pairing with ``--rw /tmp``: the filesystem ruleset is built
after the mount, so that grant covers the private directory instead of the
world-writable one every process of the session shares. The option itself
grants nothing. See :ref:`private-tmp` in the usage guide.

Like ``--loopback-only`` it needs an unprivileged user namespace and it is
fail-closed, and it shares the same single-threaded requirement (so no
``--tsync``). It does not touch ``/dev/shm`` — that is ``--private-shm``.

``--private-shm``
~~~~~~~~~~~~~~~~~

New option: a fresh 1 GiB, ``nosuid``/``nodev``, ``1777`` tmpfs mounted over
``/dev/shm`` in the same mount namespace ``--private-tmp`` uses, so the two
compose into a single ``unshare(CLONE_NEWNS)``. The host's shared memory stops
being reachable from inside and the sandbox's stops being reachable from
outside, which is what makes ``--rw /dev/shm`` mean the sandbox's own scratch
space instead of a world-writable directory the whole session shares. There is
no bind form on purpose — a ``/dev/shm`` shared with the host is what
``--private-tmp PATH`` is for.

It grants nothing on its own, and it has the same requirements as
``--private-tmp`` (unprivileged user namespace, usable ``/proc`` during the
setup, single-threaded). ``CAGED_ERR_MOUNT`` covers a failed mount of either
directory, so its message was generalised to ``error setting up a private
mount``.

``--loopback-only``
~~~~~~~~~~~~~~~~~~~

New option: the sandbox builds a **user and a network namespace** for the
command, brings loopback up inside it, drops every capability and only then
installs Landlock and seccomp. The command runs in a network stack where
nothing but ``127.0.0.1`` exists, so "reach the host's localhost", "reach the
LAN" and "send a UDP datagram out" stop being policy questions and become
routing facts: they fail with ``ENETUNREACH``, not ``EACCES``.

It had to be a namespace because no other layer can express an address. A
Landlock ``NET_PORT`` rule has no address field, and seccomp cannot
dereference ``connect()``'s ``sockaddr``. Topology is the one mechanism that
can say "loopback only", and it is also the only one that closes UDP while the
``AF_INET`` family is released. See :ref:`loopback-only` in the usage guide.

The option is orthogonal to ``--allow-network-sockets`` on purpose, and it is
fail-closed: if the user namespace cannot be created or the id maps cannot be
written (running inside another sandbox that denies ``/proc``, for instance),
the setup fails instead of running without the namespace. ``unshare`` requires
a single-threaded process, so ``--loopback-only`` and ``--tsync`` cannot be
combined.

Breaking changes
~~~~~~~~~~~~~~~~

- ``enum caged_return`` gained ``CAGED_ERR_USERNS_UNAVAILABLE``,
  ``CAGED_ERR_USERNS_MAP``, ``CAGED_ERR_NETNS``, ``CAGED_ERR_CAPABILITIES``
  and (for ``--private-tmp`` and ``--private-shm``) ``CAGED_ERR_MOUNT``. They
  were appended **after** ``CAGED_ERR_REPORT_FD``, so no existing code shifts;
  an embedder that switches on the enum has five new cases to handle, and
  ``-Wswitch`` says so.
- ``struct caged_opts`` gained ``private_tmp`` and ``private_tmp_src``, next to
  ``loopback_only``, and ``private_shm`` right after them. They are therefore
  in the middle of the struct, and the fields declared after them
  (``max_procs`` onwards) move. Designated initializers — the supported way,
  and what the examples use — are unaffected; an embedder that filled the
  struct positionally has to be recompiled.
- Landlock is no longer the only kernel feature the setup can fail on: on a
  host without unprivileged user namespaces ``--loopback-only`` fails at the
  ``unshare``, before any ruleset exists. Nothing changes for runs that do not
  use the option.

Seccomp denylist
~~~~~~~~~~~~~~~~

The seccomp denylist was closed: the calls that escape the sandbox through a
namespace, a mount, a module load or a kernel interface are now denied. No
option changes and no granted behaviour changes; what changes is what the
sandbox refuses.

Breaking changes
................

- ``enum caged_return`` gained ``CAGED_ERR_SECCOMP_CLONE_NS``, inserted after
  ``CAGED_ERR_SECCOMP_NETWORK`` to keep the pipeline order. Every code after
  it shifts by one. An embedder that compares the enum symbolically (the
  supported way, and what ``caged_strreturn`` does) is unaffected; one that
  stored or compared the numbers is not. Fix: recompile.
- New rules in the filter mean a host whose libseccomp cannot resolve one of
  the new names now fails the setup instead of installing a partial filter.
  The names in question are old (``unshare``, ``mount``, ``clone3``, …), so
  the practical floor moves to libseccomp 2.5.4 for ``mount_setattr``.

Policy changes
..............

- ``deny_dangerous_syscalls`` covers three more groups:
  ``process_mrelease``; ``init_module``/``finit_module``/``delete_module``,
  ``kexec_load``/``kexec_file_load``, ``reboot``, ``swapon``/``swapoff``,
  ``acct``, ``quotactl``, ``iopl``/``ioperm``, ``modify_ldt`` and
  ``open_by_handle_at``; and ``unshare``, ``setns``, ``mount``, ``umount2``,
  ``pivot_root``, ``chroot``, ``move_mount``, ``open_tree``, ``fsopen``,
  ``fsconfig``, ``fsmount``, ``fspick`` and ``mount_setattr``.
- New ``deny_clone_namespaces``: ``clone`` with any ``CLONE_NEW*`` flag is
  denied, one masked comparison per flag, so a call asking for several at once
  is caught. ``clone3`` is denied whole — its flags sit behind a pointer
  seccomp does not dereference — which makes callers fall back to ``clone``.
- Why: a new mount namespace can overmount what Landlock granted, and a new
  user namespace hands out ``CAP_SYS_ADMIN`` inside it. Before this, a
  command inside the sandbox could open a user namespace at all; now it
  cannot. ``fork()`` and thread creation are unaffected (they ask for no
  namespace flag), and neither is the fallback path inside libc, which is
  tested.

Internal
~~~~~~~~

- ``setup_namespaces`` no longer takes ``struct caged_opts``: it takes the four
  fields it reads (``private_tmp``, ``private_tmp_src``, ``private_shm``,
  ``loopback_only``), the way ``apply_seccomp`` takes the three flags it uses.
  The function is static, so no embedder sees this; what it buys is that the
  call graph says which options a step depends on instead of handing every step
  the whole struct.

v0.7.0
------

Seventh release. No behaviour change: same command-line options, same policy,
same fields. It is the naming pass that lines the public interface up with
itself.

Breaking changes
~~~~~~~~~~~~~~~~

- ``struct cmd_opts`` is now ``struct caged_opts``, and ``cmd_opts_free`` is
  now ``caged_opts_free``. An embedder updates the type name and the call and
  recompiles; a wrapper that only runs the ``caged`` binary is unaffected.
  The fields, their meaning and the ``caged_setup`` / ``caged_strreturn`` /
  ``enum caged_return`` interface are untouched.
- Why: the rest of the public surface already carries the ``caged_`` prefix
  (``caged_setup``, ``caged_strreturn``, ``caged_return``, ``caged.h``),
  while the options struct and its destructor carried a ``cmd_`` prefix that
  described the command-line front end and not the library. Two prefixes in
  one header invite the guess that ``cmd_`` marks a front-end-only type; it
  does not — ``parse_cmd_line`` fills the same struct the embedder fills by
  hand.
- ``struct caged_opts`` lost the ``cmd`` field. ``parse_cmd_line`` now takes
  the command as its last parameter, ``char ***cmd``: it receives a pointer to
  the NULL-terminated ``argv`` tail after ``--``, or stays ``NULL`` when the
  parse stops before a command (``--help``, or a usage error). Nothing is
  allocated, so nothing is freed. ``cmd`` was the only field ``caged_setup``
  never read — it existed for the ``main`` that ``execvpe``\s — and a field
  nothing in the library reads does not belong in the library's struct.

Upgrading
~~~~~~~~~

- Replace ``struct cmd_opts`` with ``struct caged_opts`` (declarations,
  definitions, pointers and casts) and ``cmd_opts_free`` with
  ``caged_opts_free``. The rename is mechanical: ``sed -i
  's/cmd_opts/caged_opts/g' your_sources`` covers it.
- Embedders are not affected by the ``cmd`` change unless they drive
  ``parse_cmd_line``: they never filled ``cmd`` (they keep their own array for
  ``exec``). A caller of ``parse_cmd_line`` adds the parameter —
  ``parse_cmd_line(argc, argv, &opts, &cmd)`` — or passes ``NULL`` when it only
  wants the options, as the unit tests mostly do. The front end in ``main.c``
  is the example to copy.

v0.6.0
------

Sixth release. No behaviour change: it is the type and consistency pass that
the new lint gate enforces. No command-line option changed and no policy
changed.

Types
~~~~~

- Every Landlock mask is now ``unsigned long long``, the width the API uses
  (``__u64`` fields, ``1ULL`` constants): ``get_handled_access_fs``,
  ``get_perms_read_write``, ``get_handled_scopes``, ``get_handled_access_net``
  and ``get_supported_restrict_flags``, plus the ``restrict_self`` and
  ``add_net_rule`` parameters. The narrower locals compiled cleanly only while
  every right fit in 32 bits; the day the kernel adds a right past bit 31 they
  would have truncated the mask in silence, leaving the ruleset governing less
  than intended.
- The three raw ``syscall()`` wrappers (``create_ruleset``, ``add_rule``,
  ``restrict_self``) return ``long``, the actual ``syscall(3)`` result, and the
  ``allow_*`` helpers propagate it. The ruleset descriptor is narrowed to
  ``int`` once, after the error check.
- ``SCMP_A0`` receives the socket family as ``scmp_datum_t``, the comparison
  type, instead of narrowing it to ``int``.

Internal naming
~~~~~~~~~~~~~~~

- ``get_supported_scopes`` became ``get_handled_scopes``, matching
  ``get_handled_access_fs`` and ``get_handled_access_net``.

Lint
~~~~

- New ``make lint`` target: ``gcc -fsyntax-only -Wconversion
  -Wsign-conversion -Werror`` over ``caged.c``, ``cli.c`` and ``main.c``, run as
  the first step of the CI build. ``-Wall -Wextra`` had let every implicit
  narrowing above through.

Documentation
~~~~~~~~~~~~~

- The internals pages follow the new names and types: ``abi.rst`` (the gating
  snippet and why the masks are 64-bit wide), ``architecture.rst`` (the
  ``struct cmd_opts`` listing) and ``rules.rst``.

Upgrading
~~~~~~~~~

- ``struct cmd_opts`` grew: ``released_scopes``, ``released_net`` and
  ``restrict_flags`` are ``unsigned long long`` instead of ``unsigned long``.
  An embedder that fills them from the ``1ULL`` macros needs no change; one
  that keeps them in an ``unsigned long`` of its own sees a conversion warning
  on a 32-bit build.

v0.5.0
------

Fifth release. Adds an out-of-band channel for caged's own failures, so a
wrapper never has to guess from the exit status whether the sandbox applied.
No policy changed.

Reporting
~~~~~~~~~

- New ``--report-fd N``: every diagnostic caged prints about itself (usage
  error, setup failure, command that could not be executed) is also written to
  descriptor ``N`` (``N >= 3``), and nothing is written there when the setup
  succeeded. The descriptor is marked ``FD_CLOEXEC`` and it is the only one
  that survives the final ``close_range``; the command never inherits it.
- The exit status stays what it was — ``2`` for a usage error, ``125`` for a
  setup or ``exec`` failure — but it is documented as a hint, not a proof: the
  command shares the status space with caged and can exit with either number.
  ``--report-fd`` is what removes the ambiguity.

Tests
~~~~~

- Functional tests for the descriptor: empty on success and when the command
  exits with ``2`` or ``125``, carrying the diagnostic for a usage error (with
  ``--report-fd`` before *or* after the offending option) and for a setup
  failure, and not inherited by the command.
- Unit tests for the split ``close_range`` sweep and for a report descriptor
  that cannot be claimed (``CAGED_ERR_REPORT_FD``).

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
