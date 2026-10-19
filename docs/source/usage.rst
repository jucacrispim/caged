Usage
=====

Synopsis
--------

.. code-block:: text

   caged [OPTIONS] -- CMD [ARGS...]

``caged`` builds the sandbox, then ``execvp``\s into ``CMD``. Everything after
``--`` is the command and its arguments.

Options
-------

Filesystem
~~~~~~~~~~

``--ro PATH``
    Allow reading ``PATH``. ``PATH`` may be a directory (read + traverse the
    whole tree) or a single regular file. Files that are only readable cannot
    be written, removed or replaced.

``--rw PATH``
    Allow reading and writing ``PATH`` (directory or single file). Adds
    creating, removing, renaming, truncating and the unix-socket lookup right
    on top of ``--ro``.

Network
~~~~~~~

TCP connect and bind are denied by default.

``--allow-connect-port PORT``
    Allow TCP ``connect`` to ``PORT``. Port ``0`` allows connecting from the
    ephemeral port range (i.e. letting the kernel choose the local port).

``--allow-bind-port PORT``
    Allow TCP ``bind`` to ``PORT``. Port ``0`` allows binding to an ephemeral
    port — useful for a server that does not care about the exact number.

``--allow-connect-tcp``
    Allow TCP ``connect`` to any port (releases the whole direction; conflicts
    with ``--allow-connect-port``).

``--allow-bind-tcp``
    Allow TCP ``bind`` to any port (conflicts with ``--allow-bind-port``).

.. note::

   A rule is per *port*, not per IP: allowing port 443 means any host on that
   port.

.. note::

   These rules are enforced by Landlock and only govern **TCP**. A TCP
   connection also needs its socket family, so pair any of the options above
   with ``--allow-network-sockets``. UDP, ICMP and raw traffic are not
   governed by Landlock at all; they are handled by the socket-family filter
   described below.

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
installs a **seccomp** filter that denies ``socket()`` for every address
family except ``AF_INET``, ``AF_INET6``, ``AF_NETLINK`` and ``AF_UNIX``
(families numbered above the build kernel's ``AF_MAX`` are denied too). That
allowlist is the floor; the families below are still denied on top of it and
must be released explicitly.

``--allow-unix-sockets``
    Allow ``AF_UNIX`` sockets. Without it, ``socket(AF_UNIX, ...)`` fails with
    ``EACCES``.

``--allow-network-sockets``
    Allow the ``AF_INET``, ``AF_INET6`` and ``AF_NETLINK`` families. Without
    it, every socket in those families fails with ``EACCES`` — including UDP,
    so the port rules above cannot be used either.

.. note::

   The denial is per **family**, not per socket type. Blocking ``AF_INET``
   blocks UDP (``SOCK_DGRAM``) and ICMP together with TCP; there is no option
   to allow one and deny the other.

.. note::

   **Raw sockets are always denied**: ``socket(AF_INET, SOCK_RAW)`` and
   ``socket(AF_INET6, SOCK_RAW)`` fail with ``EACCES`` regardless of the
   options — a raw socket can craft packets by hand and bypass the Landlock
   port rules. The comparison masks the type, so ``SOCK_RAW`` is caught with
   or without ``SOCK_CLOEXEC``. ``NETLINK_USERSOCK`` is likewise always
   denied, since it is an IPC channel.

.. note::

   The filter is installed after Landlock's ``restrict_self``, is inherited
   across ``execve`` and cannot be removed. Like Landlock, it does not revoke
   file descriptors that are already open.

System V IPC
~~~~~~~~~~~~

System V IPC objects (shared memory, message queues and semaphores) have no
name Landlock could govern: no path, no port, no scope. They are therefore
denied by seccomp, which fails every entry point with ``ENOSYS`` — the callers
then take their "this kernel has no SysV IPC" fallback instead of failing hard.

The denied syscalls are ``msgget``, ``msgsnd``, ``msgrcv``, ``msgctl``,
``semget``, ``semop``, ``semtimedop``, ``semctl``, ``shmget``, ``shmat``,
``shmdt`` and ``shmctl``.

``--allow-sysv-ipc``
    Allow System V IPC. Without it, every call above fails with ``ENOSYS``.

.. note::

   POSIX IPC (``shm_open``, ``mq_open`` and ``sem_open``) is a different
   mechanism: it is backed by files under ``/dev/shm`` and ``/dev/mqueue``, so
   it is governed by the filesystem rules (``--ro`` / ``--rw``) rather than by
   this filter.

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

Misc
~~~~

``-h``, ``--help``
    Print the usage on stdout and exit.

Environment
-----------

``CAGED_DISABLE_WARNINGS=1``
    Silence the kernel-ABI compatibility warnings printed on stderr. Only the
    literal value ``1`` disables them.

Exit status
-----------

- **0** — the command ran (``caged`` replaces itself with the command, so the
  exit status is the command's).
- **1** — setup failed (Landlock unavailable, ruleset error, a path could not
  be opened, the seccomp filter could not be installed) or the command could
  not be executed.
- **2** — usage error (unknown option, missing value, conflicting options,
  missing ``-- cmd``, or run with no arguments, which prints the help on
  stderr).

Examples
--------

Read a single file — only that file becomes reachable, not the rest of its
directory. The command itself and the shared libraries it needs must be
reachable too, otherwise it cannot start:

.. code-block:: sh

   ./build/caged --ro /usr/bin/cat --ro /usr/lib --ro /etc/hostname \
         -- cat /etc/hostname

A minimal interactive shell — the trees holding programs and their shared
libraries are read-only:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib -- sh

Add a writable scratch directory when the shell needs to write:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib --rw /tmp -- sh

Fetch a page over HTTPS — the network is denied unless both the socket family
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

Talk to a local service over a unix socket — the ``AF_UNIX`` family is denied
by default:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib \
         --allow-unix-sockets -- curl --unix-socket /run/myapp.sock \
         http://localhost/health

Print the available options:

.. code-block:: sh

   ./build/caged --help
