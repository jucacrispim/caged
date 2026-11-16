caged
=====

**caged** is a small process sandbox for Linux built on top of
`Landlock <https://www.kernel.org/doc/html/latest/userspace-api/landlock.html>`_,
`seccomp <https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html>`_
and `namespaces <https://www.man7.org/linux/man-pages/man7/namespaces.7.html>`_.
It locks a process and its children, denying everything by default and granting
only what you allow.

.. code-block:: text

   caged [OPTIONS] -- CMD [ARGS...]

``--`` separates caged's options from the command to run (via ``execvp``).

Features
--------

- **Filesystem**: denied by default. Grant read with ``--ro`` or read and write
  with ``--rw``, on a directory or on a single file.
- **Network**: TCP denied by default. Grant one port with
  ``--allow-connect-port`` / ``--allow-bind-port``, or a whole direction with
  ``--allow-connect-tcp`` / ``--allow-bind-tcp``. Port ``0`` means the
  ephemeral range, for ``bind`` only. A TCP connection also needs its socket
  family, so pair these with ``--allow-network-sockets``.
- **Socket families**: ``socket()`` is denied for every family, with
  ``AF_INET``, ``AF_INET6``, ``AF_NETLINK`` and ``AF_UNIX`` as the floor.
  ``--allow-network-sockets`` releases the first three and
  ``--allow-unix-sockets`` releases ``AF_UNIX``. Raw sockets and
  ``NETLINK_USERSOCK`` are always denied.
- **IPC scopes**: signalling processes and connecting to abstract unix sockets
  outside the domain are restricted by default. Release them with
  ``--allow-scoped-signal`` and ``--allow-scoped-abstract-unix``.
- **Other syscalls**: ``ptrace``, ``process_vm_*``, ``pidfd_getfd``,
  ``io_uring_setup``, ``bpf``, the keyring and SysV IPC fail with ``ENOSYS``.
  SysV IPC comes back with ``--allow-sysv-ipc``.
- **Namespaces, opt-in**: ``--loopback-only`` gives the command a network stack
  with nothing but loopback. ``--private-tmp`` and ``--private-shm`` give it a
  private ``/tmp`` and ``/dev/shm``. All three need an unprivileged user
  namespace.
- **Limits**: core dumps are disabled, inherited descriptors above stderr are
  closed, and ``--max-procs`` sets ``RLIMIT_NPROC``.
- **Environment**: cleared by default. Only ``PATH``, ``HOME``, ``LANG`` and
  the ``LC_*`` categories survive. Use ``--keep-env`` for the whole environment
  and ``--env NAME=VALUE`` for a single entry.
- **ABI awareness**: every right is gated on the kernel's Landlock ABI.
  Unsupported ones are dropped with a warning, and ``--require-abi N`` turns
  that into a failure.
- **Audit log and threads**: ``--log-same-exec-off``, ``--log-new-exec-on`` and
  ``--log-subdomains-off`` tune which denials reach the audit log. ``--tsync``
  applies the policy to every thread of the process.
- **Exit contract**: ``--report-fd N`` separates the two cases: caged failed, or
  the command exited with that status.

.. toctree::
   :maxdepth: 2

   installation
   usage
   library
   internals/index
   changelog

Indices and tables
------------------

* :ref:`genindex`
* :ref:`search`
