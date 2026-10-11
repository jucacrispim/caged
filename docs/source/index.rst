caged
=====

**caged** is a small sandbox written in C on top of **Landlock**, the Linux
Security Module (LSM) that lets an unprivileged process restrict *itself*
without root, containers or namespaces. It runs a command in a locked-down
ruleset: by default it denies everything and the resources/capabilities must
be explicity allowed.

Features
--------

- **Filesystem** — deny-by-default; grant read or read+write
  on a directory or a single file.
- **Network** — deny-by-default TCP connect/bind; grant per port
  or a whole direction (connect or bind).
- **IPC scopes** — signalling and abstract unix sockets are restricted by
  default;
- **ABI awareness** — every right/feature is gated on the kernel's Landlock
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
