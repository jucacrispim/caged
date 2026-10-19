Architecture
============

caged is a single translation unit, ``caged.c``. There is no library split yet:
everything lives in one file, and the unit tests include it directly (see
:doc:`testing`). This page describes how it is structured and how the setup
flow works. The semantics of the individual rights are in :doc:`rules`, and the
ABI gating in :doc:`abi`.

There are two enforcement layers. **Landlock** governs everything that has a
name: paths, TCP ports and IPC scopes. **seccomp** governs what Landlock cannot
express: creating a socket of a given address family. Setup builds the
Landlock ruleset first and installs the seccomp filter last.

One ruleset, built once
-----------------------

Landlock policies stack: calling ``restrict_self`` twice intersects the two
rulesets, so an empty second ruleset would deny everything. caged therefore
builds **a single ruleset** and adds every rule (filesystem, network) to it
before restricting itself once.

The setup is a one-way funnel:

1. **Probe the ABI** with ``check_abi()`` (``landlock_create_ruleset`` with
   ``attr == NULL`` and the version flag).
2. **Compute the handled masks** for this ABI (``get_handled_access_fs``,
   ``get_handled_access_net``, ``get_supported_scopes``) and fill
   ``struct landlock_ruleset_attr``.
3. **Create the ruleset** (``create_ruleset``).
4. **Add rules** — one ``PATH_BENEATH`` rule per path, one ``NET_PORT`` rule
   per port.
5. **Restrict self** (``restrict_self``): ``PR_SET_NO_NEW_PRIVS`` followed by
   ``landlock_restrict_self`` with the requested flags.
6. **Install the seccomp filter** (``apply_seccomp``): last, so it does not
   have to pre-declare the syscalls the setup itself makes, and so the
   ``no_new_privs`` flag set in step 5 is already there (it is what lets an
   unprivileged ``seccomp_load`` succeed).

The three Landlock syscalls have no glibc wrapper, so they are issued raw with
``syscall()``: ``SYS_landlock_create_ruleset``, ``SYS_landlock_add_rule`` and
``SYS_landlock_restrict_self``.

Main and the testable core
--------------------------

``main`` is intentionally thin:

.. code-block:: c

   int main(int argc, char *argv[]) {
     struct cmd_opts opts = {0};

     if (parse_cmd_line(argc, argv, &opts) < 0) {
       cmd_opts_free(&opts);
       return 2;
     }

     if (opts.help) {
       print_help(stdout);
       cmd_opts_free(&opts);
       return 0;
     }

     enum caged_return r = caged_setup(&opts);
     if (r != CAGED_OK) {
       if (seccomp_detail < -1) {
         errno = -seccomp_detail;
       }
       if (seccomp_failed_family >= 0) {
         fprintf(stderr, "caged: socket family %d\n", seccomp_failed_family);
       }
       die(caged_strreturn(r));
     }

     cmd_opts_free(&opts);
     if (execvp(opts.cmd[0], opts.cmd) < 0) {
       die("error execvp");
     }
     return 1;
   }

Everything that can be tested without a real kernel lives in ``caged_setup``
and the helpers it calls. Only ``execvp`` (which replaces the process image)
and the two ``die`` paths are excluded from coverage; they are exercised by the
functional tests instead.

``caged_setup`` returns an ``enum caged_return`` rather than an error string,
so the caller can ``switch`` on it and the library form (see below) can map it
to whatever it wants:

.. code-block:: c

   enum caged_return {
     CAGED_OK = 0,
     CAGED_ERR_NO_LANDLOCK,
     CAGED_ERR_CREATE_RULESET,
     CAGED_ERR_READ_ACCESS,
     CAGED_ERR_RW_ACCESS,
     CAGED_ERR_CONNECT_ACCESS,
     CAGED_ERR_BIND_ACCESS,
     CAGED_ERR_RESTRICT_SELF,
     CAGED_ERR_SECCOMP_INIT,
     CAGED_ERR_SECCOMP_FAMILIES,
     CAGED_ERR_SECCOMP_INET_RAW,
     CAGED_ERR_SECCOMP_NETLINK,
     CAGED_ERR_SECCOMP_UNIX,
     CAGED_ERR_SECCOMP_NETWORK,
     CAGED_ERR_SECCOMP_SYSVIPC,
     CAGED_ERR_SECCOMP_LOAD,
   };

``caged_strreturn`` turns a code into a human-readable message. Its ``switch``
has no ``default`` on purpose, so ``-Wswitch`` flags a return code that is
added but not handled.

Options and parsing
-------------------

All command-line state lives in ``struct cmd_opts``. The path and port lists
are dynamic and grow by doubling their capacity (``push_path`` / ``push_port``),
so there is no fixed upper bound:

.. code-block:: c

   struct cmd_opts {
     const char **r_dir;      int n_r;   int cap_r;
     const char **rw_dir;     int n_rw;  int cap_rw;
     unsigned long released_scopes;
     unsigned long released_net;
     unsigned long restrict_flags;
     unsigned short *connect_ports; int n_connect; int cap_connect;
     unsigned short *bind_ports;    int n_bind;    int cap_bind;
     int allow_unix_sockets;
     int allow_network_sockets;
     int allow_sysv_ipc;
     char **cmd;
     int help;
   };

``parse_cmd_line`` walks ``argv`` with ``strcmp`` and fills the struct. Usage
errors are reported with ``fatal`` (no ``errno``); runtime failures use
``die`` (which appends ``strerror(errno)``). Running with no arguments is the
one usage error that also prints the help, on stderr.

``struct cmd_opts.cmd`` note: ``cmd`` is ``char **`` (not
``const char **``) because it points into ``argv`` — converting away the const
would be a hole in the type system.

Filesystem rules
----------------

``allow_access`` opens the path with ``O_PATH | O_CLOEXEC`` and ``fstat``\s it.
The directory-only bits (``PERMS_DIRS_ONLY``) are stripped for a regular file,
because the kernel rejects them on a file. The open fd is used as
``parent_fd`` for the ``PATH_BENEATH`` rule and closed right after. Granting a
single file needs the rule on the file only — no need to also grant its
ancestors.

Network rules
-------------

``add_net_rule`` issues a ``NET_PORT`` rule with the given access and port.
``allow_net_connect_access`` and ``allow_net_bind_access`` are thin wrappers.

The seccomp layer
-----------------

Creating a socket is not governed by any Landlock right, so a Landlock-only
sandbox is open for address families nobody asked for. caged closes that with
a `libseccomp <https://github.com/seccomp/libseccomp>`_ filter, built and
installed by ``apply_seccomp``.

The default action is ``SCMP_ACT_ALLOW`` and every rule denies, so the filter
is an allowlist of address families, not of syscalls. Six helpers build it,
one per concern:

``deny_socket_families``
    The floor. Every family from ``0`` to ``AF_MAX``, except ``AF_INET``,
    ``AF_INET6``, ``AF_NETLINK`` and ``AF_UNIX``, is denied with ``EACCES``. A
    single ``SCMP_CMP_GE`` rule against ``AF_MAX`` catches values above this
    build's maximum, since a newer kernel may know them and seccomp runs before
    the kernel validates the argument.

``deny_inet_raw``
    ``AF_INET`` and ``AF_INET6`` with ``SOCK_RAW``. The type is compared with
    ``SCMP_CMP_MASKED_EQ`` against ``SOCK_TYPE_MASK`` (``0xf``), because
    ``SOCK_CLOEXEC`` and ``SOCK_NONBLOCK`` live in the high bits of the same
    argument. ``SOCK_TYPE_MASK`` is kernel-internal and not exported to
    userspace, so caged defines it locally, the same way it does for the
    Landlock bits newer than the host headers.

``deny_netlink_usersock``
    ``AF_NETLINK`` with protocol ``NETLINK_USERSOCK``, which is an IPC channel.
    The family is compared too: protocol ``2`` is also ``IPPROTO_IGMP``.

``deny_unix_sockets``
    The whole ``AF_UNIX`` family. Added only when ``--allow-unix-sockets`` is
    absent.

``deny_network_sockets``
    ``AF_INET``, ``AF_INET6`` and ``AF_NETLINK``. Added only when
    ``--allow-network-sockets`` is absent. It is denied per family, so UDP and
    ICMP go down together with TCP by design: there is no way to keep one and
    drop the other.

``deny_sysv_ipc``
    The System V IPC entry points, one rule per name in the
    ``SYSV_IPC_SYSCALLS`` table: ``msgget``/``msgsnd``/``msgrcv``/``msgctl``,
    ``semget``/``semop``/``semtimedop``/``semctl`` and
    ``shmget``/``shmat``/``shmdt``/``shmctl``. The action is
    ``SCMP_ACT_ERRNO(ENOSYS)`` rather than ``EACCES``, so a caller takes its
    "this kernel has no SysV IPC" fallback instead of failing hard. The names
    go through ``seccomp_syscall_resolve_name``; a name the library cannot
    resolve fails **closed** (``seccomp_detail = -ENOSYS``) instead of
    installing a filter with a hole in it. Added only when
    ``--allow-sysv-ipc`` is absent. The loop over the table keeps this at one
    branch in ``caged.c`` rather than twelve.

Each helper returns ``-1`` on a libseccomp failure, keeping the raw code in
``seccomp_detail`` and, in the family loop, the offending family in
``seccomp_failed_family``. ``apply_seccomp`` maps the failing step to its own
``enum caged_return`` code, and ``main`` turns ``seccomp_detail`` back into
``errno`` so ``die`` prints a real message. That pair of globals is the one
piece of hidden state in the program; it exists because libseccomp returns
``-EINVAL``, ``-EPERM``-style codes instead of ``-1`` plus ``errno``.

Two properties make the filter fit here: it is installed **after**
``restrict_self`` (no need to pre-declare the syscalls the setup makes, and
``no_new_privs`` is already set), and it is inherited across ``execve`` and
cannot be removed, which is why it can be installed in the setup and still
govern the command.

Going further
-------------

The declared end goal is to turn ``caged.c`` into a reusable library: split it
into ``caged.c`` (logic) + ``caged.h`` (the public API — ``enum caged_return``,
``caged_setup``, ``caged_strreturn``) + a ``main.c``, with the tests linking
against the object instead of including the source. The ``enum`` is already the
natural preparation for that. The original motivation is to embed caged in
another program to wrap a whole client process at launch.

Two cleanups belong to that split. ``apply_seccomp`` currently builds and
installs the filter in one go; separating a side-effect-free
``build_seccomp_ctx`` from an ``apply_seccomp`` that only calls
``seccomp_load`` would let a unit test export the generated filter as text
(``seccomp_export_pfc``) and compare it, and would give the two seccomp globals
a proper home instead of file scope.
