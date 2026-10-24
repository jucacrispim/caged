Rules and rights
================

This page explains the semantics behind each option — what the underlying
Landlock right actually governs. The command-line surface is in :doc:`/usage`.

The handled mask
----------------

A Landlock ruleset is defined by a *handled* mask: the set of access types the
domain governs. Anything in the mask is **denied by default**; a rule then
*grants* a specific access on a specific object. Landlock can only subtract
from what a process could do — it never adds capability.

That is why the masks in caged are "everything supported by the ABI", and every
option either removes a bit from the handled mask (an outright allow) or adds a
grant rule.

Filesystem
----------

``--ro PATH`` grants the read trio on ``PATH``:

.. code-block:: c

   #define PERMS_READ \
     (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | \
      LANDLOCK_ACCESS_FS_EXECUTE)

``EXECUTE`` is in there because, on a directory, it governs **traversal** —
being able to walk *through* the directory, not just list it. Without it you
cannot reach anything deeper.

``--rw PATH`` adds the mutating rights (write, remove, make, truncate) and the
unix-socket lookup right:

.. code-block:: c

   #define PERMS_READ_WRITE \
     (PERMS_READ | LANDLOCK_ACCESS_FS_WRITE_FILE | \
      LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
      LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG | \
      LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_RESOLVE_UNIX)

**File vs directory.** Some rights only make sense on a directory
(``READ_DIR``, ``REMOVE_DIR``, ``REMOVE_FILE``, ``MAKE_DIR``, ``MAKE_REG``).
The kernel rejects a ``PATH_BENEATH`` rule on a regular file whose mask
includes them (``EINVAL``). caged therefore defines ``PERMS_DIRS_ONLY`` and, in
``allow_access``, strips those bits when the path is not a directory. As a
result ``--ro FILE`` becomes ``READ_FILE | EXECUTE`` and ``--rw FILE`` becomes
``READ_FILE | WRITE_FILE | TRUNCATE`` — a rule on that single file, with no
access to its siblings or its directory.

Network
-------

``handled_access_net`` governs ``LANDLOCK_ACCESS_NET_BIND_TCP`` and
``LANDLOCK_ACCESS_NET_CONNECT_TCP`` (ABI 4). With both handled and no rule,
all TCP connect and bind is denied.

A ``NET_PORT`` rule grants one access on **one port**:

.. code-block:: c

   struct landlock_net_port_attr {
     __u64 allowed_access;  /* CONNECT_TCP and/or BIND_TCP */
     __u64 port;            /* host endianness */
   };

Port ``0`` is special: a rule with port ``0`` and ``BIND_TCP`` matches a
``bind`` to port 0, which the kernel translates to the ephemeral port range
(``/proc/sys/net/ipv4/ip_local_port_range``). It does **not** mean "all ports".
To allow every port in a direction there is no rule wildcard — instead the bit
is removed from the handled mask (``--allow-connect-tcp`` /
``--allow-bind-tcp``).

Rules are per port, not per IP: allowing 443 allows connecting to that port on
any host.

A connect()'s implicit local (ephemeral) port is chosen by the kernel and is
**not** mediated by ``BIND_TCP``; only an explicit ``bind(2)`` is. So a client
that just connects does not need any bind rule.

IPC scopes
----------

The ``scoped`` field of the ruleset restricts communication between Landlock
domains (ABI 6). caged restricts both scopes by default:

- ``LANDLOCK_SCOPE_SIGNAL`` — signalling processes outside the domain.
- ``LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`` — connecting to abstract unix
  sockets outside the domain.

Releasing a scope clears its bit from the ruleset's ``scoped`` mask
(``get_supported_scopes(abi) & ~opts->released_scopes``). Unlike filesystem and
network rights, scopes have **no per-object rule**: ``landlock_add_rule`` does
not support them. Below ABI 6 the mask is simply zero.

Restrict-self flags
-------------------

These are bits passed to ``landlock_restrict_self`` itself, not rules:

- The three **log** flags (ABI 7) tune which denials the kernel reports to the
  audit log, splitting by whether an ``execve`` happened (same-exec vs
  new-exec) and by whether the denial came from a nested subdomain.
- ``TSYNC`` (ABI 8) applies the whole configuration atomically to **all**
  threads of the process. Without it, the policy only applies to the calling
  thread and its children. For a single-threaded program like caged that is
  equivalent; a multi-threaded embedder needs it.

caged passes ``opts->restrict_flags & get_supported_restrict_flags(abi)``, so
flags a given ABI cannot support are dropped rather than failing the run.

``--tsync`` is not Landlock-only: it also sets ``SCMP_FLTATR_CTL_TSYNC`` on the
seccomp context, so both layers reach the same threads. What makes seccomp a
problem in the first place is that ``seccomp_load`` filters the calling thread,
and inheritance only goes downwards, so threads that already exist in the
thread group would keep running unfiltered. Two differences from Landlock are
worth knowing: the seccomp attribute has no ABI gate (it needs libseccomp API
level 2 / kernel 3.17, and if unavailable the setup fails with
``CAGED_ERR_SECCOMP_TSYNC``), and a failed synchronization makes
``seccomp_load`` return the tid of the offending thread — a *positive* value —
instead of ``-1``, which is why the load is checked against zero.

Neither layer can reach a sibling **process** (another thread group, from a
``fork``): a domain only descends the tree of descendants. Confining those is
the caller's job — apply the sandbox before forking, as ``caged`` itself does
in ``main``.


System V IPC
------------

Landlock has no right for System V IPC: shared memory segments, message queues
and semaphores are kernel objects identified by a key, not by a path, a port or
a domain scope. Nothing in the handled mask covers them, so a Landlock-only
sandbox leaves them wide open.

``--allow-sysv-ipc`` therefore belongs to the **seccomp** layer, not to
Landlock: without it, ``msgget``, ``semget``, ``shmget`` and every operation on
an existing object fail with ``ENOSYS``. The action is ``ENOSYS`` rather than
``EACCES`` on purpose — it is the error a program expects from a kernel built
without SysV IPC, so callers fall back gracefully instead of aborting.

Two related gaps stay open, and neither is seccomp's job:

- **POSIX IPC** (``shm_open``, ``sem_open``, ``mq_open``) is a filesystem
  interface: it lives in ``/dev/shm`` and ``/dev/mqueue``, so the ``--ro`` /
  ``--rw`` grants already cover it.
- **File descriptors already open** on a SysV object are not revoked by the
  filter; ``close_range`` is the other half, and it is not implemented yet.
