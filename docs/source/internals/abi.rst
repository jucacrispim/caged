ABI compatibility
=================

Landlock grows over kernel versions. Each new kernel bumps the **ABI** number
and may add access rights, scopes or ``restrict_self`` flags. caged probes the
running kernel's ABI once (``check_abi``) and gates every feature on it, so the
same binary works on old and new kernels.

ABI history
-----------

The rights caged cares about were introduced across these ABIs:

======  =====================================================
ABI     Added
======  =====================================================
1       base filesystem rights (execute, read/write, make/remove ...)
2       ``LANDLOCK_ACCESS_FS_REFER`` (rename/link between dirs)
3       ``LANDLOCK_ACCESS_FS_TRUNCATE``
4       network (``LANDLOCK_ACCESS_NET_BIND_TCP`` / ``_CONNECT_TCP``)
5       ``LANDLOCK_ACCESS_FS_IOCTL_DEV`` (ioctl on device files)
6       IPC scopes (``LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET``,
        ``LANDLOCK_SCOPE_SIGNAL``)
7       ``restrict_self`` audit-log flags
8       ``LANDLOCK_RESTRICT_SELF_TSYNC``
9       ``LANDLOCK_ACCESS_FS_RESOLVE_UNIX``
======  =====================================================

The gating logic
----------------

Every feature mask starts as "everything the latest API offers" and then
**subtracts** what the running ABI does not have:

.. code-block:: c

   static int get_handled_access_fs(long abi) {
     int handled = FS_HANDLED;
     if (abi < 2) handled &= ~LANDLOCK_ACCESS_FS_REFER;
     if (abi < 3) handled &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
     if (abi < 5) handled &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
     if (abi < 9) handled &= ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
     return handled;
   }

This is deliberately **fail-closed**: if a new right is added to the "latest"
mask and someone forgets to gate it, ``create_ruleset`` returns ``EINVAL`` and
caged refuses to run — instead of silently governing less than intended. The
same subtract-by-ABI pattern is used by:

- ``get_perms_read_write`` — drops ``TRUNCATE`` (ABI < 3) and
  ``RESOLVE_UNIX`` (ABI < 9).
- ``get_supported_scopes`` — zero below ABI 6.
- ``get_handled_access_net`` — zero below ABI 4.
- ``get_supported_restrict_flags`` — drops the log flags below ABI 7 and
  ``TSYNC`` below ABI 8.

Requested flags that the ABI cannot support are masked out
(``opts->restrict_flags & get_supported_restrict_flags(abi)``), consistent
with how scopes behave on an old kernel.

Header fallbacks
----------------

Rights newer than the headers on the build machine are defined as fallbacks so
caged compiles against older ``linux/landlock.h``:

- ``LANDLOCK_ACCESS_FS_RESOLVE_UNIX`` (ABI 9) → ``1ULL << 16``.
- ``LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF`` / ``_LOG_NEW_EXEC_ON`` /
  ``_LOG_SUBDOMAINS_OFF`` (ABI 7) and ``LANDLOCK_RESTRICT_SELF_TSYNC``
  (ABI 8) → bits 0..3.

There are no fallbacks for the scopes or the network rights: they are ABI 4/6,
which is treated as the minimum the headers provide.

Runtime warnings
----------------

When the running kernel is older than some feature caged can use, caged prints
a warning on stderr listing each missing feature and the ABI it needs:

.. code-block:: text

   caged: warning: Landlock ABI 6 does not support some features; they are unavailable:
   caged: warning:   - restrict-self log flags (needs ABI 7)
   caged: warning:   - restrict-self TSYNC (needs ABI 8)
   caged: warning:   - UNIX socket name resolution (needs ABI 9)

The list comes from the ``FEATURES`` table in ``caged.c``; a kernel new enough
for everything prints nothing. Warnings are informational only — the program
still runs with the features it has. Setting ``CAGED_DISABLE_WARNINGS=1``
silences them.
