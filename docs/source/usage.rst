Usage
=====

Synopsis
--------

.. code-block:: text

   caged [OPTIONS] -- CMD [ARGS...]

``caged`` builds the sandbox and then ``execvp``\s into ``CMD``. Everything
after ``--`` is the command and its arguments.

Options
-------

Filesystem
~~~~~~~~~~

``--ro PATH``
    Allow reading ``PATH``. ``PATH`` can be a directory (read and traverse the
    whole tree) or a single regular file. A file you can only read cannot be
    written, removed or replaced.

``--rw PATH``
    Allow reading and writing ``PATH`` (a directory or a single file). On top
    of ``--ro`` this adds create, remove, rename, truncate and the unix socket
    lookup right.

``--private-tmp [PATH]``
    Give the command a ``/tmp`` of its own. Without ``PATH`` you get a new
    tmpfs (1 GiB, mode 1777). With ``PATH``, ``PATH`` is bind mounted over
    ``/tmp``. See `Private /tmp`_.

``--private-shm``
    Give the command a ``/dev/shm`` of its own: a new tmpfs (1 GiB, mode
    1777), in the same mount namespace ``--private-tmp`` uses. See
    `Private /tmp`_.

.. _private-tmp:

Private /tmp
~~~~~~~~~~~~

``/tmp`` is mode ``1777`` and shared with every other process of your user.
With ``--rw /tmp`` the command reads whatever the host left there, and
whatever it writes there survives it.

``--private-tmp`` mounts another directory over ``/tmp`` inside a new mount
namespace:

``--private-tmp``
    A new tmpfs. Nothing from the host's ``/tmp`` is visible, and nothing the
    command writes survives it. The size is capped at 1 GiB; without a limit
    tmpfs can grow to half of the RAM, which is more than a sandbox should be
    able to use. Mode ``1777``, ``nosuid`` and ``nodev``.

``--private-tmp PATH``
    A bind mount of ``PATH`` over ``/tmp``. Use it when you still have to
    exchange files with the command: ``/tmp`` inside and ``PATH`` outside are
    the same directory. The flags are applied with a second ``mount()``,
    because a bind mount inherits the source's flags.

The filesystem rules are created after the mount, so ``--rw /tmp`` names the
private ``/tmp``:

.. code-block:: sh

   ./build/caged --ro /usr --private-tmp --rw /tmp -- sh

``--private-shm`` does the same for ``/dev/shm``, in the same mount namespace:
a new tmpfs, 1 GiB, ``nosuid``, ``nodev``, ``1777``. That is where
``multiprocessing`` and joblib leave their segments, so ``--rw /dev/shm`` then
names the sandbox's own shared memory. There is no bind form: use
``--private-tmp PATH`` when the host has to share a directory.

.. note::

   Neither option grants anything. Without ``--rw /tmp`` the command still
   gets ``EACCES`` when it writes there; the option only changes which
   directory a grant names. The same holds for ``--private-shm`` and
   ``--rw /dev/shm``. You can use one without the other: without
   ``--private-shm``, ``/dev/shm`` stays shared.

.. note::

   Both options need an unprivileged **user namespace**.
   ``unshare(CLONE_NEWNS)`` and ``mount()`` check ``CAP_SYS_ADMIN``, which only
   a new user namespace grants to an unprivileged process. They fail closed: if
   the namespace cannot be built, caged exits instead of running the command
   against the shared ``/tmp``. Two consequences. The id maps are written
   through ``/proc``, so running caged inside a sandbox that denies ``/proc``
   fails with ``error writing the user namespace id maps``. And ``unshare``
   needs a single-threaded process, so ``--tsync`` cannot be combined with
   them. Both flags share one mount namespace when used together.

Network
~~~~~~~

TCP connect and bind are denied by default.

``--allow-connect-port PORT``
    Allow TCP ``connect`` to ``PORT``. ``PORT`` is the destination port.

``--allow-bind-port PORT``
    Allow TCP ``bind`` to ``PORT``. Port ``0`` allows binding to any ephemeral
    port, which is useful for a server that does not care about the number.

``--allow-connect-tcp``
    Allow TCP ``connect`` to any port. Conflicts with
    ``--allow-connect-port``.

``--allow-bind-tcp``
    Allow TCP ``bind`` to any port. Conflicts with ``--allow-bind-port``.

.. code-block:: sh

   ./build/caged --ro /usr --ro /etc --allow-network-sockets \
         --allow-connect-port 443 -- curl https://example.com

.. note::

   A rule is per *port*, not per IP. If you allow port 443, you allow it on
   any host.

.. note::

   Port ``0`` is only meaningful for ``bind``. For ``connect`` the rule port is
   the destination port, so ``--allow-connect-port 0`` is accepted and matches
   no connection.

.. note::

   Landlock governs **TCP** only. A connection also needs its socket family, so
   pair these options with ``--allow-network-sockets``. UDP, ICMP and raw
   traffic are not governed by Landlock at all; the socket family filter
   handles them, and ``--loopback-only`` keeps the command away from the
   network entirely.

.. _loopback-only:

Loopback-only network namespace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``--loopback-only``
    Run the command in a network namespace of its own, holding nothing but a
    working loopback interface.

Every other network control looks at a name. Landlock looks at the TCP port,
seccomp looks at the socket family. Neither of them can look at the address: a
Landlock ``NET_PORT`` rule has no address field, and seccomp sees the
``sockaddr`` of ``connect()`` as a pointer it cannot follow. So "do not talk to
the host's localhost" cannot be written as a rule. It can be written as
topology. Give the command a stack in which no other address exists, and
``1.1.1.1`` is not denied, it is unreachable: the call fails with
``ENETUNREACH`` before a packet is built.

What changes:

- The sandbox gets its **own** loopback. The host's ``127.0.0.1`` and another
  sandbox's are not reachable. Neither are the command's listeners from the
  outside, so a server inside the cage can bind port 80 without colliding with
  anything.
- Everything outside is gone: TCP, UDP, ICMP and raw alike. This is the only
  layer that closes **UDP** while the family is released, because the Landlock
  port rules govern TCP only.
- DNS stops working: the query has nowhere to go. The error is
  ``ENETUNREACH`` ("no route"), not the ``EACCES`` of a rule.

``--loopback-only`` does not imply ``--allow-network-sockets``. The namespace
decides where the command can reach, the socket filter decides which families
it may create, and with ``--loopback-only`` alone the command cannot create even
an ``AF_INET`` socket. The combination that makes loopback usable is:

.. code-block:: sh

   ./build/caged --loopback-only --allow-network-sockets \
         --allow-bind-tcp --allow-connect-tcp -- ...

.. note::

   Building the namespace needs the same unprivileged user namespace as
   `Private /tmp`_. It is what grants the ``CAP_SYS_ADMIN`` and
   ``CAP_NET_ADMIN`` that the network namespace and the interface ioctls check.
   The capabilities are given up again before the sandbox is installed: they
   are zeroed in every set and removed from the bounding set. And seccomp
   refuses ``unshare``, ``setns`` and ``clone`` with any ``CLONE_NEW*`` flag,
   so the command cannot build a namespace of its own to undo this.

.. note::

   On a host where unprivileged user namespaces are disabled
   (``kernel.unprivileged_userns_clone=0``, or the AppArmor restriction of
   Ubuntu 23.10 and later) the setup fails with ``error creating the user
   namespace``.

IPC scopes
~~~~~~~~~~

Signalling processes outside the sandbox and connecting to abstract unix
sockets are restricted by default.

``--allow-scoped-signal``
    Release the signal scope: the sandboxed process may signal processes
    outside its domain.

``--allow-scoped-abstract-unix``
    Release the abstract unix socket scope: the sandboxed process may connect
    to abstract unix sockets outside its domain.

.. note::

   Scopes cover abstract unix sockets only. *Pathname* unix sockets are a
   filesystem right, granted through ``--rw`` (ABI 9 and later).

Socket families
~~~~~~~~~~~~~~~

Landlock has no right that governs creating a socket, so ``caged`` also
installs a **seccomp** filter. It denies ``socket()`` for every address family
except ``AF_INET``, ``AF_INET6``, ``AF_NETLINK`` and ``AF_UNIX``, and for
families numbered above the build kernel's ``AF_MAX``. That allowlist is the
floor. The families below are denied on top of it and you have to release them.

``--allow-unix-sockets``
    Allow ``AF_UNIX`` sockets. Without it, ``socket(AF_UNIX, ...)`` fails with
    ``EACCES``.

``--allow-network-sockets``
    Allow the ``AF_INET``, ``AF_INET6`` and ``AF_NETLINK`` families. Without
    it, every socket in those families fails with ``EACCES``, including UDP, so
    the port rules above cannot be used either.

.. note::

   The denial is per **family**, not per socket type. Blocking ``AF_INET``
   blocks UDP (``SOCK_DGRAM``) and ICMP together with TCP. There is no option
   to allow one and deny the other.

.. note::

   **Raw sockets are always denied**: ``socket(AF_INET, SOCK_RAW)`` and
   ``socket(AF_INET6, SOCK_RAW)`` fail with ``EACCES`` whatever the options
   are, because a raw socket can craft packets by hand and bypass the Landlock
   port rules. The comparison masks the type, so ``SOCK_RAW`` is caught with or
   without ``SOCK_CLOEXEC``. ``NETLINK_USERSOCK`` is denied as well, since it
   is an IPC channel.

.. note::

   The filter is installed after Landlock's ``restrict_self``, is inherited
   across ``execve`` and cannot be removed. Like Landlock, it does not revoke
   file descriptors that are already open.

System V IPC
~~~~~~~~~~~~

System V IPC objects (shared memory, message queues and semaphores) have no
name Landlock could govern: no path, no port, no scope. seccomp denies them and
every entry point fails with ``ENOSYS``. Callers then take their "this kernel
has no SysV IPC" fallback instead of failing hard.

The denied syscalls are ``msgget``, ``msgsnd``, ``msgrcv``, ``msgctl``,
``semget``, ``semop``, ``semtimedop``, ``semctl``, ``shmget``, ``shmat``,
``shmdt`` and ``shmctl``.

``--allow-sysv-ipc``
    Allow System V IPC. Without it, every call above fails with ``ENOSYS``.

.. note::

   POSIX IPC (``shm_open``, ``mq_open`` and ``sem_open``) is another mechanism:
   it is backed by files under ``/dev/shm`` and ``/dev/mqueue``, so the
   filesystem rules (``--ro`` / ``--rw``) govern it, not this filter.

Dangerous syscalls
~~~~~~~~~~~~~~~~~~

Some syscalls give a process authority over other processes, over the caller's
keyrings or over the kernel. Landlock has no right for any of them, so seccomp
denies them all with ``ENOSYS``. That error makes libraries fall back to
another path instead of failing hard.

``ptrace``, ``process_vm_readv``, ``process_vm_writev``, ``pidfd_getfd``,
``process_madvise``, ``process_mrelease``, ``kcmp``
    Reading or writing another process's memory, or taking one of its file
    descriptors, needs only the same uid (subject to Yama). Nothing in Landlock
    covers it, and a descriptor taken from a process outside the sandbox
    bypasses the whole policy.

``keyctl``, ``add_key``, ``request_key``
    The kernel keyring is indexed by uid, so a confined process can read the
    keys of the same user.

``bpf``, ``perf_event_open``, ``userfaultfd``
    Kernel attack surface. They need a capability or a relaxed sysctl today.
    Denying them covers a sysctl change.

``io_uring_setup``
    An io_uring ring submits operations through shared memory, executed by
    ``io_uring_enter``. The operations themselves (``IORING_OP_SOCKET``,
    ``IORING_OP_CONNECT``, …) are never syscalls, so they would bypass every
    socket family rule. Denying the setup call makes ``liburing`` fall back to
    normal synchronous I/O.

``init_module``, ``finit_module``, ``delete_module``, ``kexec_load``,
``kexec_file_load``, ``reboot``, ``swapon``, ``swapoff``, ``acct``,
``quotactl``, ``iopl``, ``ioperm``, ``modify_ldt``, ``open_by_handle_at``
    Loading code into the kernel, taking the machine down, and the legacy
    hardware and accounting interfaces. All of them already need a privilege
    the sandbox does not have. Denying them covers a relaxed sysctl or a
    capability leak.

``unshare``, ``setns``, ``mount``, ``umount2``, ``pivot_root``, ``chroot``,
``move_mount``, ``open_tree``, ``fsopen``, ``fsconfig``, ``fsmount``,
``fspick``, ``mount_setattr``
    Mounting and namespaces. A new mount namespace is a new view of the
    filesystem, so a bind mount or an overmount there undoes the filesystem
    policy from the inside. That makes this the way around everything above.
    The descriptor-based API does the same without ``mount()``.

``clone`` with any namespace flag, ``clone3``
    ``clone`` is filtered by flag, one masked comparison per namespace
    (``CLONE_NEWNS``, ``CLONE_NEWCGROUP``, ``CLONE_NEWUTS``, ``CLONE_NEWIPC``,
    ``CLONE_NEWUSER``, ``CLONE_NEWPID``, ``CLONE_NEWNET``, ``CLONE_NEWTIME``),
    so a call asking for several of them at once is still caught. ``clone3``
    takes its flags behind a pointer, which seccomp does not follow, so the
    whole syscall is denied; callers fall back to ``clone``, where the flags
    are visible. Ordinary ``fork()`` and thread creation are unaffected: they
    ask for none of these.

.. note::

   There is no option to release these. ``gdb``, ``strace`` and LeakSanitizer
   do not work *inside* the sandbox; debug from outside. A nested ``bwrap``, a
   container runtime or a ``chroot`` inside the sandbox is not possible either.

Logging
~~~~~~~

``--log-same-exec-off``
    Disable the audit log for denials from the calling thread (and its
    children) while it runs the same executable, i.e. without an ``execve`` in
    between. Added in ABI 7.

``--log-new-exec-on``
    Enable the audit log for denials after an ``execve``. Added in ABI 7.

``--log-subdomains-off``
    Disable the audit log for denials coming from nested Landlock domains.
    Added in ABI 7.

Thread sync
~~~~~~~~~~~

``--tsync``
    Apply the sandbox to *all* threads of the process, not just the calling
    one. Added in ABI 8; required for correctness if the process is
    multi-threaded.

    The flag governs both layers: the Landlock restrict-self bit (ABI 8) and
    the seccomp ``SCMP_FLTATR_CTL_TSYNC`` attribute, which needs only
    libseccomp API level 2 / kernel 3.17 and is therefore applied even on a
    kernel too old for the Landlock bit. Without it, seccomp reaches only the
    calling thread and whatever it goes on to create; threads that already
    existed in the thread group stay unfiltered.

    Note that this is *thread* synchronization: a process forked from another
    branch (another thread group) cannot be confined after the fact. Apply the
    sandbox before forking instead; ``caged`` itself does the setup before
    ``execvp``.

File descriptors and resource limits
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before running the command, caged closes every inherited file descriptor above
stderr (``close_range(3, ~0U, 0)``). Landlock and seccomp only govern what is
opened *inside* the domain, so a descriptor handed to caged would otherwise
stay usable whatever the policy says. A socket already connected to a service
outside the sandbox is the example.

.. warning::

   caged keeps only ``stdin``, ``stdout`` and ``stderr``, plus the single
   ``--report-fd`` descriptor described below. Anything else has to travel
   through a pipe or a file.

``--report-fd N``
    Report caged's own failures on descriptor ``N`` (``N >= 3``), in addition
    to stderr. A usage error, a setup failure and a command that could not be
    executed all write there, and **nothing** is written when the setup
    succeeded. The descriptor is marked close-on-exec, so the command never
    inherits it.

    This is the only unambiguous way for a wrapper to tell "caged failed" from
    "the command exited with that status". The exit status cannot carry it:
    caged replaces itself with the command, so the two share one status space
    and no value can be reserved for the wrapper, not even ``125``, which a
    command may return by itself. With ``--report-fd`` an empty descriptor
    means the command ran, whatever status it exited with::

        caged --ro /usr --report-fd 3 -- sh -c 'exit 125' 3>report
        # exit status 125, and "report" is empty: that was the command

        caged --ro /no/such/path --report-fd 3 -- true 3>report
        # exit status 125, and "report" carries the setup error

Core dumps are always disabled (``RLIMIT_CORE = 0``). A core writes process
memory, secrets included, to a path the confined process picks through its
working directory. The soft **and** the hard limit are set, so the command
cannot raise them back.

``--max-procs N``
    Set ``RLIMIT_NPROC`` to ``N``, soft and hard. Without it the limit is left
    as inherited. ``RLIMIT_NPROC`` is counted per **real uid** over the whole
    system, not per process tree, so ``N`` has to be larger than the number of
    processes the user already has.

Landlock ABI
~~~~~~~~~~~~

By default, a kernel whose Landlock ABI lacks a feature prints a **warning** on
stderr and caged runs anyway, with whatever the ABI supports. The sandbox still
works, but it is fail-open: on an ABI 6 kernel you can believe you have
``RESOLVE_UNIX`` while the kernel is not enforcing it.

``--require-abi N``
    Refuse to run unless the kernel's Landlock ABI is at least ``N``. The check
    happens right after the probe and before any ruleset is created, so nothing
    is applied on failure. The error reports both numbers::

        caged: Landlock ABI 6, 9 required
        Landlock ABI too old: Operation not supported

    Omit the option to have no requirement. ``0`` is rejected as a value: it is
    not a floor, and omitting the option already means "no requirement".

.. tip::

   ABI 4 adds TCP rules, 5 ``IOCTL_DEV``, 6 IPC scopes, 7 restrict-self log
   flags, 8 ``TSYNC`` and 9 ``RESOLVE_UNIX``. Use ``--require-abi 9`` when you
   need the whole policy enforced.

Command environment
~~~~~~~~~~~~~~~~~~~

The command runs with a cleared environment by default. Only a base is
inherited: ``PATH``, ``HOME``, ``LANG``, ``LANGUAGE`` and the ``LC_*``
categories defined by ``locale.h``. Credentials and session pointers (API keys,
``SSH_AUTH_SOCK``, ``DBUS_SESSION_BUS_ADDRESS``, ``DISPLAY``, ``XAUTHORITY``,
…) do not reach the command. Nothing is fabricated: what is inherited comes
from caged's own environment.

An empty environment breaks commands in ways that are hard to see. Without
``PATH`` a child falls back to the libc's ``/bin:/usr/bin`` and loses venvs and
``~/.local/bin``. Without the locale it runs in ``C``, sorting bytes instead of
following the collation rules.

``--keep-env``
    Inherit the whole environment instead of the base.

``--env NAME=VALUE``
    Set ``NAME`` for the command. It overrides an inherited variable of the
    same name. The comparison is by name, so ``--env FOO=new`` drops an
    inherited ``FOO=old`` and leaves ``FOOBAR`` alone. May be repeated.

.. note::

   The program itself is looked up with the **caller's** ``PATH``, not with the
   command's environment, so ``caged -- sh`` still finds ``sh`` even though the
   command's ``PATH`` is cleared.

Misc
~~~~

``-h``, ``--help``
    Print the usage on stdout and exit.

Environment
-----------

``CAGED_DISABLE_WARNINGS=1``
    Silence the kernel-ABI compatibility warnings printed on stderr. Only the
    literal value ``1`` disables them. This variable is read from caged's own
    environment, before the command's environment is built, so it works
    whether or not ``--keep-env`` is given.

Exit status
-----------

- **0**: the command ran. ``caged`` replaces itself with the command, so the
  exit status is the command's.
- **2**: usage error (unknown option, missing value, conflicting options,
  missing ``-- cmd``, or run with no arguments, which prints the help on
  stderr).
- **125**: ``caged`` itself failed. Either the setup failed (Landlock
  unavailable, the ABI is below ``--require-abi``, ruleset error, a path could
  not be opened, a limit could not be set, the seccomp filter could not be
  installed) or the command could not be executed.

Any other status is the command's. The split between **2**, **125** and the
command's own status separates a broken invocation, a broken sandbox and a
command that exited with the same number. ``125`` is the convention for "the
wrapper failed" used by ``sh``, ``sudo`` and ``docker run``.

The status is a hint, not a proof. The command shares it, because caged
``execvp``\s into it, so a command that exits with ``2`` or ``125`` looks
exactly like a caged failure. If you need certainty, pass ``--report-fd`` and
trust the descriptor instead: empty means the command ran, non-empty carries
the diagnostic.

Examples
--------

Read a single file. Only that file becomes reachable, not the rest of its
directory. The command itself and the shared libraries it needs must be
reachable too, otherwise it cannot start:

.. code-block:: sh

   ./build/caged --ro /usr/bin/cat --ro /usr/lib --ro /etc/hostname \
         -- cat /etc/hostname

A minimal interactive shell, with the trees holding programs and their shared
libraries read-only:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib -- sh

Add a writable scratch directory when the shell needs to write:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib --rw /tmp -- sh

Give the shell a ``/tmp`` of its own, so that grant covers a private tmpfs
instead of the world-writable one the whole session shares:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib \
         --private-tmp --rw /tmp -- sh

Share a directory with the sandbox under the name ``/tmp``. The same files, seen
from both sides:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib \
         --private-tmp "$PWD/.sandbox-tmp" --rw /tmp -- sh

The same for shared memory, which is where ``multiprocessing`` and joblib put
their segments:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib \
         --private-shm --rw /dev/shm -- sh

Fetch a page over HTTPS. The network is denied unless both the socket family
and the port are allowed:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib --ro /etc \
         --allow-network-sockets --allow-connect-port 443 \
         -- curl https://example.com

Serve a directory on a fixed local port:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib --ro "$PWD" \
         --allow-network-sockets --allow-bind-port 8080 \
         -- python3 -m http.server 8080

Serve a port that nothing outside the sandbox can reach. The namespace has its
own loopback and no route, so the listener and whatever the command talks to on
``127.0.0.1`` are private to the cage:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib --ro "$PWD" \
         --loopback-only --allow-network-sockets \
         --allow-bind-tcp --allow-connect-tcp \
         -- python3 -m http.server 8000

Talk to a local service over a unix socket. The ``AF_UNIX`` family is denied by
default:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib \
         --allow-unix-sockets -- curl --unix-socket /run/myapp.sock \
         http://localhost/health

Print the available options:

.. code-block:: sh

   ./build/caged --help
