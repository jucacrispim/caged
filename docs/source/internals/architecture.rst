Architecture
============

caged is split in five files, along a library / command-line boundary:

``caged.h``
    The public interface. It holds ``enum caged_return``, ``struct cmd_opts``,
    the diagnostics globals (``seccomp_detail``, ``seccomp_failed_family``,
    ``seccomp_failed_syscall``, ``abi_found``), the declarations of
    ``caged_setup``, ``caged_strreturn`` and ``cmd_opts_free`` — the pieces a
    program embedding caged needs — and the ``LANDLOCK_*`` fallback macros the
    headers of an older system lack.

``caged.c``
    The sandbox logic, and only that: the ABI gating, the Landlock ruleset and
    rules, the seccomp filter and the resource limits. It parses no arguments
    and prints nothing for the user, which is what makes it linkable as a
    library. Everything that is not part of the public API stays ``static``
    here.

``cli.h`` / ``cli.c``
    The command-line front end proper: ``parse_cmd_line``, ``print_help`` and
    the ABI warnings, plus the ``push_*`` list helpers the parser uses. None
    of it is part of the sandbox.

``main.c``
    The executable: ``die`` and ``main``. It parses ``argv``, calls
    ``caged_setup``, prints the ABI warnings and ``execvpe``\\s the command.
    Keeping it separate is what makes ``caged.c`` linkable as a library.

The unit tests still include ``caged.c`` (and, where needed, ``cli.c``)
directly to reach the ``static`` helpers (see :doc:`testing`). This page
describes how the pieces are structured and how the setup flow works. The
semantics of the individual rights are in :doc:`rules`, and the ABI gating in
:doc:`abi`.

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

1. **Apply the resource limits** (``apply_rlimits``): ``RLIMIT_CORE = 0``
   always, plus ``RLIMIT_NPROC`` when ``--max-procs`` was given. First, so the
   setup itself runs with them.
2. **Probe the ABI** with ``check_abi()`` (``landlock_create_ruleset`` with
   ``attr == NULL`` and the version flag).
3. **Enforce the ABI floor** (``abi_satisfies``): when ``--require-abi N`` was
   given and the kernel reports a lower ABI, stop with
   ``CAGED_ERR_ABI_TOO_OLD`` before any ruleset exists. Without the option the
   floor is ``0`` and the step is a no-op, leaving only the warning.
4. **Compute the handled masks** for this ABI (``get_handled_access_fs``,
   ``get_handled_access_net``, ``get_supported_scopes``) and fill
   ``struct landlock_ruleset_attr``.
5. **Create the ruleset** (``create_ruleset``).
6. **Add rules** — one ``PATH_BENEATH`` rule per path, one ``NET_PORT`` rule
   per port.
7. **Restrict self** (``restrict_self``): ``PR_SET_NO_NEW_PRIVS`` followed by
   ``landlock_restrict_self`` with the requested flags.
8. **Install the seccomp filter** (``apply_seccomp``): last among the policy
   layers, so it does not have to model the syscalls the setup itself makes
   (``open``, ``fstat``, ``close``, ``prctl``, ``landlock_*``).
9. **Close the inherited descriptors** (``close_inherited_fds``):
   ``close_range(3, ~0U, 0)``. Truly last, after every step that could still
   need to report an error — ``stderr`` is fd 2 and stays open.

The three Landlock syscalls have no glibc wrapper, so they are issued raw with
``syscall()``: ``SYS_landlock_create_ruleset``, ``SYS_landlock_add_rule`` and
``SYS_landlock_restrict_self``.

Main and the testable core
--------------------------

``main`` (in ``main.c``) is intentionally thin:

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

     char **envp = NULL;
     enum caged_return r = caged_setup(&opts, &envp);
     if (r != CAGED_OK) {
       if (seccomp_detail < -1) {
         errno = -seccomp_detail;
       }
       if (seccomp_failed_family >= 0) {
         fprintf(stderr, "caged: socket family %d\n", seccomp_failed_family);
       }
       if (seccomp_failed_syscall != NULL) {
         fprintf(stderr, "caged: syscall %s\n", seccomp_failed_syscall);
       }
       if (r == CAGED_ERR_ABI_TOO_OLD) {
         fprintf(stderr, "caged: Landlock ABI %ld, %ld required\n", abi_found,
                 opts.require_abi);
       }
       die(caged_strreturn(r));
     }

     warn_unsupported_features(abi_found);
     cmd_opts_free(&opts);
     /* execvpe searches with the *caller's* PATH, not with envp. */
     if (execvpe(opts.cmd[0], opts.cmd, envp) < 0) {
       die("error execvpe");
     }
     return 1;
   }

Everything that can be tested without a real kernel lives in ``caged_setup``
and the helpers it calls. Only ``execvpe`` (which replaces the process image)
and the ``die`` paths, both in ``main.c``, are excluded from coverage; they are
exercised by the functional tests instead.

``caged_setup`` returns an ``enum caged_return`` rather than an error string,
so the caller can ``switch`` on it and the library form (see below) can map it
to whatever it wants:

.. code-block:: c

   enum caged_return {
     CAGED_OK = 0,
     CAGED_ERR_NO_LANDLOCK,
     CAGED_ERR_ABI_TOO_OLD,
     CAGED_ERR_CREATE_RULESET,
     CAGED_ERR_READ_ACCESS,
     CAGED_ERR_RW_ACCESS,
     CAGED_ERR_CONNECT_ACCESS,
     CAGED_ERR_BIND_ACCESS,
     CAGED_ERR_RESTRICT_SELF,
     CAGED_ERR_RLIMIT,
     CAGED_ERR_CLOSE_FDS,
     CAGED_ERR_SECCOMP_INIT,
     CAGED_ERR_SECCOMP_FAMILIES,
     CAGED_ERR_SECCOMP_INET_RAW,
     CAGED_ERR_SECCOMP_NETLINK,
     CAGED_ERR_SECCOMP_UNIX,
     CAGED_ERR_SECCOMP_NETWORK,
     CAGED_ERR_SECCOMP_SYSVIPC,
     CAGED_ERR_SECCOMP_SYSCALLS,
     CAGED_ERR_SECCOMP_LOAD,
   };

``caged_strreturn`` turns a code into a human-readable message. Its ``switch``
has no ``default`` on purpose, so ``-Wswitch`` flags a return code that is
added but not handled.

Options and parsing
-------------------

All command-line state lives in ``struct cmd_opts`` (declared in ``caged.h``
because ``caged_setup`` takes it, filled by ``cli.c``). The path and port lists
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
     long max_procs;
     long require_abi;
     int keep_env;
     char **env;              int n_env;  int cap_env;
     char **cmd;
     int help;
   };

``parse_cmd_line`` (in ``cli.c``) walks ``argv`` with ``strcmp`` and fills the
struct. Usage errors are reported with ``fatal`` (no ``errno``); runtime
failures use ``die`` (which appends ``strerror(errno)``, and lives in
``main.c``). Running with no arguments is the one usage error that also prints
the help, on stderr.

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

Limits and inherited descriptors
--------------------------------

``set_limit`` sets **both** the soft and the hard limit: a soft limit alone is
no barrier, because the confined process may raise it back up to the hard one.
``apply_rlimits`` then applies ``RLIMIT_CORE = 0`` unconditionally (a core
dump writes process memory, secrets included, to a path the confined process
chooses through its cwd) and ``RLIMIT_NPROC`` only when ``--max-procs`` was
given — it is counted per real uid over the whole system, so a fixed default
would make the first fork fail on a busy host.

``close_inherited_fds`` is the other half of the socket filter. seccomp cannot
revoke a descriptor, and Landlock cannot either, so a socket handed to caged
already connected to a service outside the sandbox would bypass both layers.
``close_range(3, ~0U, 0)`` removes it. Keeping fds 0–2 means ``die`` can still
write to stderr after the fact.

The command environment
----------------------

The environment is built by ``build_env`` and handed back through the last
parameter of ``caged_setup``, which also **replaces** the process environment
(``clearenv`` plus a ``setenv`` per allowed entry). From the end of the setup
on, ``environ`` itself holds only the allowed variables, so a child started
with ``execvp`` or with the returned array gets the same filtered set. A
caller that passes ``NULL`` still gets the replacement, it just does not get
the array.

The environment is computed from three pieces.

``BASE_ENV``
    The variables inherited by default: ``PATH``, ``HOME``, ``LANG``,
    ``LANGUAGE`` and the twelve ``LC_*`` categories from ``locale.h``. They
    are configuration and presentation, not authority — dropping ``PATH``
    sends a child to the libc's compiled fallback and loses venvs, and
    dropping the locale forces ``C``. The list is closed: no wildcard, so an
    unknown ``LC_*`` category stays out and is inherited only with
    ``--keep-env``.

``--keep-env``
    Take everything from ``environ`` instead of the base.

``--env NAME=VALUE``
    Applied last. An entry is compared **by name** against the inherited ones,
    so ``--env FOO=new`` replaces an inherited ``FOO=old`` and leaves
    ``FOOBAR`` untouched; the pushed entry is the only copy that survives.

Three details are easy to get wrong. The allowed entries point into the
inherited ``environ``, so the array must be built **before** ``clearenv()``
invalidates it — hence the environment is the last step of the setup. The
``CAGED_DISABLE_WARNINGS`` switch is read at that same moment, before the
replacement, and recorded in ``caged_warnings_disabled``; otherwise dropping
it would make the switch impossible to use. And ``environ`` is ``NULL`` after
``clearenv()`` (which the unit tests use), so the loop guards against it.
``execvpe``
searches for the program with the **caller's** ``PATH``, not with the array it
is handed — a cleared environment does not stop ``caged -- sh`` from finding
``sh``; what changes is the ``PATH`` the command itself sees.

The seccomp layer
-----------------

Creating a socket is not governed by any Landlock right, so a Landlock-only
sandbox is open for address families nobody asked for. caged closes that with
a `libseccomp <https://github.com/seccomp/libseccomp>`_ filter, built and
installed by ``apply_seccomp``.

The default action is ``SCMP_ACT_ALLOW`` and every rule denies, so the filter
is an allowlist of address families, not of syscalls. Seven helpers build it,
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
    "this kernel has no SysV IPC" fallback instead of failing hard. Added only
    when ``--allow-sysv-ipc`` is absent.

``deny_dangerous_syscalls``
    The ``DENY_SYSCALLS`` table, unconditional. Three groups: the
    process-inspection calls that only need the same uid (``ptrace``,
    ``process_vm_readv``/``process_vm_writev``, ``pidfd_getfd``,
    ``process_madvise``, ``kcmp``); the keyring calls that reach the caller's
    own keys (``keyctl``, ``add_key``, ``request_key``); and the kernel attack
    surface (``bpf``, ``perf_event_open``, ``userfaultfd``). Plus
    ``io_uring_setup``, the one that matters most: a ring's operations are
    submitted through shared memory and executed by ``io_uring_enter``, so
    ``IORING_OP_SOCKET``/``IORING_OP_CONNECT`` never appear as syscalls and
    would side-step every socket family rule above.

Both of them delegate to ``deny_syscall_list``, which resolves each name with
``seccomp_syscall_resolve_name`` and adds a zero-argument
``SCMP_ACT_ERRNO(ENOSYS)`` rule. A name the library cannot resolve fails
**closed** (``seccomp_detail = -ENOSYS``) instead of installing a filter with a
hole in it. Driving by table keeps each list at one branch in ``caged.c``
instead of one per name.

Each helper returns ``-1`` on a libseccomp failure, keeping the raw code in
``seccomp_detail``, the offending family in ``seccomp_failed_family`` and the
offending name in ``seccomp_failed_syscall``. ``apply_seccomp`` maps the failing
step to its own ``enum caged_return`` code, and ``main`` turns
``seccomp_detail`` back into ``errno`` so ``die`` prints a real message. Those
globals are the one piece of hidden state in the program; they exist because
libseccomp returns ``-EINVAL``, ``-EPERM``-style codes instead of ``-1`` plus
``errno``.

With ``--tsync`` ``apply_seccomp`` sets ``SCMP_FLTATR_CTL_TSYNC`` on the
context before loading it, mirroring the Landlock restrict-self flag: the
filter then covers every thread of the thread group instead of only the
calling thread and its descendants. The attribute has no ABI gate of its own
(it needs libseccomp API level 2 / kernel 3.17); when it cannot be set the setup
fails with ``CAGED_ERR_SECCOMP_TSYNC`` rather than silently installing a
one-thread filter. Because a partially failed synchronization makes
``seccomp_load`` return the tid of the offending thread, a *positive* value,
the load is checked against zero and not against ``-1``.

Two properties make the filter fit here: it is installed **after**
``restrict_self`` (no need to pre-declare the syscalls the setup makes, and
``no_new_privs`` is already set), and it is inherited across ``execve`` and
cannot be removed, which is why it can be installed in the setup and still
govern the command.

Going further
-------------

The library split is in place: ``caged.c`` (logic) + ``caged.h`` (the public
API) + ``cli.c`` / ``cli.h`` (the command-line front end) + ``main.c`` (the
executable). What is still missing to make caged a library in practice is the
other half of the split: the unit tests still ``#include "../../caged.c"`` to
reach the ``static`` helpers. Linking them against ``caged.o`` instead would
require giving the internal helpers external linkage and an internal header,
which is a separate change; until then, the production build is the only
consumer of ``caged.c`` as its own translation unit.

The original motivation for the split was to embed caged in another program to
wrap a whole client process at launch. ``caged_setup`` plus ``struct cmd_opts``
in ``caged.h`` is the interface for that: fill the struct, call
``caged_setup``, treat a non-``CAGED_OK`` return as fatal for the caller, and
hand the returned environment to the ``exec``.

Two cleanups also belong to this line of work. ``apply_seccomp`` currently
builds and installs the filter in one go; separating a side-effect-free
``build_seccomp_ctx`` from an ``apply_seccomp`` that only calls
``seccomp_load`` would let a unit test export the generated filter as text
(``seccomp_export_pfc``) and compare it. And the four diagnostics globals,
declared in ``caged.h`` and defined in ``caged.c``, are the remaining hidden
state: they exist because libseccomp returns ``-EINVAL``, ``-EPERM``-style
codes instead of ``-1`` plus ``errno``.
