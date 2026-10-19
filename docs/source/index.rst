caged
=====

**caged** is a small process sandbox for Linux built on top of
`Landlock <https://www.kernel.org/doc/html/latest/userspace-api/landlock.html>`_
and `seccomp <https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html>`_.
It locks a process (and its children) denying everything by default and
granting only what is explicitly allowed.

.. code-block:: text

   caged [OPTIONS] -- CMD [ARGS...]

``--`` separates caged's options from the command to run (via ``execvp``).

Features
--------

- **Filesystem**: denied by default; grant read (``--ro``) or read+write
  (``--rw``) on a directory *or a single file*.
- **Network**: denied by default; grant per port
  (``--allow-connect-port`` / ``--allow-bind-port``, port ``0`` = ephemeral
  range) or a whole direction (``--allow-connect-tcp`` /
  ``--allow-bind-tcp``). A TCP connection also needs its socket family, so
  pair these with ``--allow-network-sockets``.
- **IPC scopes**: signalling and abstract unix sockets are restricted by
  default; release them with ``--allow-scoped-signal`` /
  ``--allow-scoped-abstract-unix``.
- **Socket families**: every family except ``AF_INET``, ``AF_INET6`` and
  ``AF_NETLINK`` is denied, including ``AF_UNIX``; release them with
  ``--allow-network-sockets`` / ``--allow-unix-sockets``. Raw sockets are
  always denied.
- **ABI awareness**: every right/feature is gated on the kernel's Landlock
  ABI; unsupported ones are dropped and a warning is printed.


.. toctree::
   :maxdepth: 2

   installation

.. toctree::
   :maxdepth: 2

   usage

.. toctree::
   :maxdepth: 2

   internals/index

.. toctree::
   :maxdepth: 2

   changelog

Indices and tables
------------------

* :ref:`genindex`
* :ref:`search`
