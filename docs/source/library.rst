Using caged as a library
========================

caged is split along a library / command-line boundary: ``caged.c`` is the
sandbox and ``caged.h`` its public interface, while ``cli.c`` / ``cli.h`` and
``main.c`` make the executable. A program can link the library and wrap
**its own process** in the sandbox at launch, which is the original reason for
the split — see :doc:`internals/architecture` for how the pieces fit and
:doc:`internals/rules` for what each right means.

Building
--------

.. code-block:: sh

   make lib

This produces the static archive ``build/libcaged.a``, built from ``caged.o``:
the sandbox alone, with no argument parser and no ``main``. A consumer adds
``caged.h`` to its include path and links the archive plus libseccomp:

.. code-block:: sh

   cc -I/path/to/caged my_program.c /path/to/caged/build/libcaged.a -lseccomp

Only a static archive is provided. There is no shared object and no install
target; :doc:`installation` explains that even the binary is copied to
``$PATH`` by hand.

A minimal embedder
------------------

Fill a ``struct cmd_opts``, call ``caged_setup``, treat anything other than
``CAGED_OK`` as fatal, and hand the returned environment to the ``exec``:

.. code-block:: c

   #define _GNU_SOURCE /* execvpe */

   #include <errno.h>
   #include <stdio.h>
   #include <unistd.h>

   #include "caged.h"

   int main(void) {
     const char *ro[] = {"/usr", "/bin", "/lib", "/lib64", "/etc"};
     unsigned short ports[] = {443};

     struct cmd_opts opts = {0};
     opts.r_dir = ro;
     opts.n_r = 5;
     opts.connect_ports = ports;
     opts.n_connect = 1;
     opts.released_net = LANDLOCK_ACCESS_NET_CONNECT_TCP;
     opts.allow_network_sockets = 1;
     opts.keep_env = 1;
     opts.restrict_flags = LANDLOCK_RESTRICT_SELF_TSYNC;

     char **envp = NULL;
     enum caged_return r = caged_setup(&opts, &envp);
     if (r != CAGED_OK) {
       if (seccomp_detail < -1) {
         errno = -seccomp_detail; /* libseccomp's code, for the message */
       }
       fprintf(stderr, "caged: %s\n", caged_strreturn(r));
       return 1;
     }

     char *cmd[] = {"sh", "-c", "curl -s https://example.com", NULL};
     execvpe(cmd[0], cmd, envp);
     perror("execvpe");
     return 1;
   }

Note that ``cmd`` and ``help`` are not used by the library; they exist for the
command-line front end.

What ``caged_setup`` changes
----------------------------

Everything it does is **one-way** and applies to the calling process. It
cannot be undone, and it cannot be applied twice — a second Landlock domain
would intersect with the first one. Call it as late as possible in your
startup, once the sandbox's own inputs are known, and:

- it sets ``no_new_privs`` and creates the Landlock domain (the calling thread
  only, unless ``TSYNC`` is requested);
- it installs a seccomp filter that is inherited across ``execve``;
- it sets ``RLIMIT_CORE = 0`` and, with ``max_procs``, ``RLIMIT_NPROC``;
- it **closes every descriptor above stderr**, so anything you want the
  confined process to have must be passed through a pipe or a file;
- it **replaces** ``environ`` with the allowed set.

Because of the last two, do it before opening anything you intend to keep and
before starting threads. A sibling **process** (a ``fork`` from another thread
group) is out of reach for both layers: the sandbox only descends the tree of
descendants. Confine each process at its own launch instead.

Filling ``struct cmd_opts``
---------------------------

Every field mirrors a command-line option; see :doc:`usage` for the semantics.

.. list-table::
   :header-rows: 1

   * - Field
     - Option
     - Meaning
   * - ``r_dir``, ``n_r``
     - ``--ro``
     - Read-only grants (a directory, or a single file).
   * - ``rw_dir``, ``n_rw``
     - ``--rw``
     - Read+write grants.
   * - ``connect_ports``, ``n_connect``
     - ``--allow-connect-port``
     - One ``NET_PORT`` connect rule per port (``0`` = ephemeral range).
   * - ``bind_ports``, ``n_bind``
     - ``--allow-bind-port``
     - One ``NET_PORT`` bind rule per port.
   * - ``released_net``
     - ``--allow-connect-tcp`` / ``--allow-bind-tcp``
     - Bits cleared from ``handled_access_net``: the whole direction, any port.
   * - ``released_scopes``
     - ``--allow-scoped-signal`` / ``--allow-scoped-abstract-unix``
     - Bits cleared from the ruleset's ``scoped`` mask.
   * - ``restrict_flags``
     - ``--tsync`` and the three ``--log-*``
     - Bits passed to ``landlock_restrict_self``, masked by the ABI.
   * - ``allow_unix_sockets``
     - ``--allow-unix-sockets``
     - Keeps the seccomp ``AF_UNIX`` denial out of the filter.
   * - ``allow_network_sockets``
     - ``--allow-network-sockets``
     - Keeps the ``AF_INET`` / ``AF_INET6`` / ``AF_NETLINK`` denials out. A
       TCP connection needs this **and** a port grant.
   * - ``allow_sysv_ipc``
     - ``--allow-sysv-ipc``
     - Keeps the SysV IPC denials out of the filter.
   * - ``max_procs``
     - ``--max-procs``
     - ``RLIMIT_NPROC``; ``0`` leaves the limit alone.
   * - ``require_abi``
     - ``--require-abi``
     - Minimum Landlock ABI, checked before any ruleset exists; ``0`` means no
       floor.
   * - ``keep_env``
     - ``--keep-env``
     - Inherit the whole environment instead of the base set.
   * - ``env``, ``n_env``
     - ``--env``
     - ``NAME=VALUE`` entries, applied last, compared by name.

The ``cap_*`` fields, ``cmd`` and ``help`` belong to the parser (``cli.c``) and
are ignored by ``caged_setup``.

.. warning::

   ``cmd_opts_free`` frees the arrays the **parser** allocated (``r_dir``,
   ``rw_dir``, ``connect_ports``, ``bind_ports``, ``env``). An embedder that
   fills the struct with its own static or stack arrays must not call it.

The environment
---------------

The last parameter of ``caged_setup`` is optional (``NULL`` is fine):

- the inherited variables kept by the opts (the base set, or everything with
  ``keep_env``) plus the ``env`` entries;
- anything else is removed from the calling process's ``environ``.

When it is not ``NULL``, ``*env`` receives the same set as a NULL-terminated
array — pass it to ``execvpe``; plain ``execvp`` uses the already-filtered
``environ``. The caller **owns** the array and frees it with ``free()``; it is
set to ``NULL`` if the setup fails. Note that ``execvpe`` searches for the
program with the *caller's* ``PATH``, not with the array it is given.

Multi-threaded callers
----------------------

Without flags the whole configuration applies to the calling thread and
whatever it goes on to create. A thread that already exists in the thread
group keeps running unfiltered, so a multi-threaded embedder must ask for
synchronization:

.. code-block:: c

   opts.restrict_flags |= LANDLOCK_RESTRICT_SELF_TSYNC;

That flag governs **both** layers: the Landlock restrict-self bit (ABI 8) and
the seccomp ``SCMP_FLTATR_CTL_TSYNC`` attribute, which needs only libseccomp
API level 2 / kernel 3.17. If the seccomp attribute cannot be set, the setup
fails with ``CAGED_ERR_SECCOMP_TSYNC`` instead of silently confining a single
thread. Synchronization also fails if another thread of the group diverged by
installing its own filter, which is one more reason to call the setup early.

Errors and diagnostics
----------------------

``caged_setup`` returns an ``enum caged_return``; ``caged_strreturn`` gives a
message for it. Its ``switch`` has no ``default``, so a new code is a compiler
warning rather than a silent fallthrough in your handler. The library's
diagnostics globals narrow the failure down:

``seccomp_detail``
    The libseccomp error code (negative). ``seccomp_detail < -1`` means it is a
    real error; assign ``-seccomp_detail`` to ``errno`` if you want
    ``strerror`` in your message.

``seccomp_failed_family``
    The socket family a rule could not be added for, ``-1`` when none is to
    blame.

``seccomp_failed_syscall``
    The syscall name a rule could not be added for, ``NULL`` when none.

``abi_found``
    The Landlock ABI the kernel reported, whether the setup succeeded or not.

The library never prints anything, so diagnosing and warning is the caller's
job. To warn about features the running kernel cannot support, link ``cli.c``
as well and call ``warn_unsupported_features(abi_found)`` after a successful
setup (it lives in ``cli.h`` because it is front-end code).
``caged_setup`` records the ``CAGED_DISABLE_WARNINGS`` switch in
``caged_warnings_disabled`` before it replaces the environment, so that helper
still honours it afterwards.

Limitations
-----------

The unit tests still ``#include "../../caged.c"`` to reach the ``static``
helpers, so the archive is a packaging of the production code rather than the
only consumer of it; giving the helpers external linkage and an internal
header is a separate change.
