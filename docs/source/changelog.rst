Changelog
=========

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
