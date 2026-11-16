Architecture
============

caged is split in eight files: six for the sandbox and two for the command-line
front end.

``caged.h``
    The public interface. It holds ``enum caged_return``, ``struct caged_opts``,
    the diagnostics globals (``seccomp_detail``, ``seccomp_failed_family``,
    ``seccomp_failed_syscall``, ``abi_found``), the declarations of
    ``caged_setup``, ``caged_strreturn`` and ``caged_opts_free``, which are the
    pieces a program embedding caged needs, and the ``LANDLOCK_*`` fallback
    macros the headers of an older system lack.

``caged_internal.h``
    What the sandbox files share between themselves: the Landlock masks, the
    tables of the seccomp layer and the declaration of every helper. It is not
    part of the library contract, and it carries the system headers those
    declarations depend on.

``caged.c``
    The setup: the order of the steps, the resource limits, the inherited
    descriptors and the return codes. It parses no arguments and prints
    nothing for the user, so it can be linked as a library.

``landlock.c``
    The ABI probe, the ruleset, the rules, and the getters that drop the bits a
    given ABI does not know.

``seccomp.c``
    The filter: the socket-family floor, the raw and netlink rules, the SysV
    IPC table, the clone flags and the denylist of dangerous syscalls.

``namespaces.c``
    The user namespace and its id maps, the mount namespace with the private
    directories, and the network namespace with loopback.

``env.c``
    What the command inherits by default, the ``--env`` overrides and the
    replacement of ``environ``.

``cli.h`` / ``cli.c``
    The command-line front end proper: ``parse_cmd_line``, ``print_help`` and
    the ABI warnings, plus the ``push_*`` list helpers the parser uses. None
    of it is part of the sandbox. ``cli_internal.h`` declares the helpers the
    unit tests drive directly.

``main.c``
    The executable: ``die`` and ``main``. It parses ``argv``, calls
    ``caged_setup``, prints the ABI warnings and ``execvpe``\\s the command.
    It holds no policy of its own, so another front end can replace it.

The unit tests link the objects and include ``caged_internal.h`` and
``cli_internal.h`` (see :doc:`testing`). This page describes how the pieces are
structured and how the setup flow works. The semantics of the individual rights
are in :doc:`rules`, and the ABI gating in :doc:`abi`.

There are two enforcement layers. **Landlock** governs everything that has a
name: paths, TCP ports and IPC scopes. **seccomp** governs what Landlock cannot
express: creating a socket of a given address family. Setup builds the
Landlock ruleset first and installs the seccomp filter last.

Neither of them can see an IP address, so there is a third, optional mechanism
for that: with ``--loopback-only`` the sandbox also builds a network namespace
for the command. It is not a policy layer: it changes the topology the policy
runs in (see `Namespaces of the sandbox itself`_). ``--private-tmp`` uses the
same mechanism for the filesystem: a mount namespace with a private ``/tmp``.

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
2. **Build the namespaces of the sandbox** (``setup_namespaces``), only with
   ``--loopback-only``, ``--private-tmp`` or ``--private-shm``: the user
   namespace and the id maps, the mount namespace with the private ``/tmp``
   and/or ``/dev/shm``, the network namespace
   with loopback up, and the capabilities dropped. It has to happen before the
   policy layers: it needs the capabilities only a fresh user namespace
   provides, the ``/proc`` entries Landlock would deny, and an ``unshare`` the
   seccomp filter denies. And ``--private-tmp`` has to be in place before the
   filesystem rules, so that a ``/tmp`` grant names the private directory (see
   `Namespaces of the sandbox itself`_).
3. **Probe the ABI** with ``check_abi()`` (``landlock_create_ruleset`` with
   ``attr == NULL`` and the version flag).
4. **Enforce the ABI floor** (``abi_satisfies``): when ``--require-abi N`` was
   given and the kernel reports a lower ABI, stop with
   ``CAGED_ERR_ABI_TOO_OLD`` before any ruleset exists. Without the option the
   floor is ``0`` and the step is a no-op, leaving only the warning.
5. **Compute the handled masks** for this ABI (``get_handled_access_fs``,
   ``get_handled_access_net``, ``get_handled_scopes``) and fill
   ``struct landlock_ruleset_attr``.
6. **Create the ruleset** (``create_ruleset``).
7. **Add rules**: one ``PATH_BENEATH`` rule per path, one ``NET_PORT`` rule
   per port.
8. **Restrict self** (``restrict_self``): ``PR_SET_NO_NEW_PRIVS`` followed by
   ``landlock_restrict_self`` with the requested flags.
9. **Install the seccomp filter** (``apply_seccomp``): last among the policy
   layers, so it does not have to model the syscalls the setup itself makes
   (``open``, ``fstat``, ``close``, ``prctl``, ``landlock_*``).
10. **Close the inherited descriptors** (``close_inherited_fds``):
    ``close_range(3, ~0U, 0)``. Truly last, after every step that could still
    need to report an error: ``stderr`` is fd 2 and stays open.

The three Landlock syscalls have no glibc wrapper, so they are issued raw with
``syscall()``: ``SYS_landlock_create_ruleset``, ``SYS_landlock_add_rule`` and
``SYS_landlock_restrict_self``.

Namespaces of the sandbox itself
--------------------------------

``--loopback-only``, ``--private-tmp`` and ``--private-shm`` add a layer that is
not a policy: ``setup_namespaces`` puts the process in a user namespace of its
own, builds the private ``/tmp`` and/or ``/dev/shm``
(``setup_private_tmp``/``setup_private_shm``) and/or the private network
(``setup_netns``), and drops every capability. It runs at step 2 of the funnel,
before Landlock and seccomp, because every piece of it would be refused
afterwards:

- ``unshare``, ``mount`` and ``setns`` are in ``DENY_SYSCALLS``;
- ``/proc/self/uid_map`` would be a plain ``open`` under the Landlock policy;
- the interface ioctls need capabilities that only the user namespace grants.

The sequence is::

  read euid/egid -> unshare(CLONE_NEWUSER) -> /proc/self/setgroups = "deny"
    -> /proc/self/uid_map -> /proc/self/gid_map
    -> [--private-tmp | --private-shm] unshare(CLONE_NEWNS)
         -> mount("/", MS_REC|MS_PRIVATE)
         -> [--private-tmp] mount(tmpfs | bind source, "/tmp")
         -> [--private-shm] mount(tmpfs, "/dev/shm")
    -> [--loopback-only] unshare(CLONE_NEWNET) -> lo up (SIOCSIFFLAGS)
    -> drop capabilities

The user namespace is built once, whichever options asked for a namespace, and
so is the mount namespace when both private directories are requested; the rest
are optional and independent, and the capabilities are dropped once at the end.
Four things in that order are load bearing.

**The ids are read first.** Until the map is written, ``geteuid()`` inside the
new namespace returns the overflow id (65534), so a late read would write a map
for the wrong id. They are also the *effective* ids, because that is what the
kernel records as the owner of the namespace and compares the map against.

**The map is 1:1.** An unprivileged process can only ever map its own id, but
the interesting part is that 1:1 is also the better choice: the internal uid is
not 0, so the privileged ``execve`` rule ("euid 0 means the permitted set is
refilled from the bounding set") never applies, and clearing the capability
sets is enough. ``"deny"`` in ``setgroups`` is a prerequisite for writing a gid
map at all, and it takes away a privilege the sandbox does not want anyway.

**The mount namespace comes before the mounts, and "/" is made recursively
private before anything is mounted.** ``CLONE_NEWNS`` copies the mount list but
not the propagation: without ``MS_REC|MS_PRIVATE`` on ``/`` the new mount would
show up in the host's peer groups. A bind source needs a second ``mount()``
(``MS_BIND|MS_REMOUNT``) because a bind inherits the source's flags.
The network namespace comes after the mounts; both check a capability against
the user namespace that owns them, so they can only succeed once the new user
namespace is legitimately ours.

**The capabilities are dropped last, and the bounding set goes first.**
``PR_CAPBSET_DROP`` needs ``CAP_SETPCAP`` effective, which ``capset(0)`` would
have removed, so the bounding set is emptied before the sets are zeroed;
``PR_CAP_AMBIENT`` clear comes between them. The ambient set is what would
otherwise hand a capability across ``execve``, and the bounding set is the
ceiling ``execve`` refills from, so emptying it makes the drop survive the exec
even when caged itself runs as root.

The filesystem policy is built **after** the mount, which is the reason
``--private-tmp`` and ``--private-shm`` are worth having: ``--rw /tmp`` (or
``--rw /dev/shm``) opens the private directory instead of the shared one. On
the host those grants would cover world-writable directories the whole session
can write to. The two flags share one mount namespace, so asking for both is
still a single ``unshare(CLONE_NEWNS)`` and a single ``mount("/", ...)``.

There is no ``fork`` anywhere: the namespaces are created in place, which is
what keeps ``caged_setup`` usable as a library (a pid namespace would need the
first child to be PID 1 and a re-exec). The two costs are that ``/proc`` has to
be usable during the setup (a ``caged`` running inside another sandbox that
denies it fails with ``CAGED_ERR_USERNS_MAP`` instead of degrading), and that
``unshare(CLONE_NEWUSER)`` fails with ``EINVAL`` in a multi-threaded process,
so ``--tsync`` cannot be combined with any of the three options.

All of it is fail-closed and each step has its own code
(``CAGED_ERR_USERNS_UNAVAILABLE``, ``CAGED_ERR_USERNS_MAP``,
``CAGED_ERR_MOUNT``, ``CAGED_ERR_NETNS``, ``CAGED_ERR_CAPABILITIES``), so a
wrapper can tell an AppArmor-restricted host from a broken ``/proc`` from a
failed ioctl. Nothing here can be released by an option: an unprivileged user
namespace hands out ``CAP_SYS_ADMIN`` inside it, which is a whole class of
kernel attack surface, and the command gets none of it.

Main and the testable core
--------------------------

``main`` (in ``main.c``) is intentionally thin:

.. code-block:: c

   int main(int argc, char *argv[]) {
     struct caged_opts opts = {0};
     char **cmd = NULL;

     if (parse_cmd_line(argc, argv, &opts, &cmd) < 0) {
       caged_opts_free(&opts);
       return 2;
     }

     if (opts.help) {
       print_help(stdout);
       caged_opts_free(&opts);
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
     caged_opts_free(&opts);
     /* execvpe searches with the *caller's* PATH, not with envp. */
     if (execvpe(cmd[0], cmd, envp) < 0) {
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
     CAGED_ERR_SECCOMP_CLONE_NS,
     CAGED_ERR_SECCOMP_SYSVIPC,
     CAGED_ERR_SECCOMP_SYSCALLS,
     CAGED_ERR_SECCOMP_LOAD,
     CAGED_ERR_SECCOMP_TSYNC,
     CAGED_ERR_ENV,
     CAGED_ERR_REPORT_FD,
     CAGED_ERR_USERNS_UNAVAILABLE,
     CAGED_ERR_USERNS_MAP,
     CAGED_ERR_NETNS,
     CAGED_ERR_CAPABILITIES,
   };

``caged_strreturn`` turns a code into a human-readable message. Its ``switch``
has no ``default``, so ``-Wswitch`` flags a return code that is added but not
handled.

Options and parsing
-------------------

All command-line state lives in ``struct caged_opts`` (declared in ``caged.h``
because ``caged_setup`` takes it, filled by ``cli.c``). The path and port lists
are dynamic and grow by doubling their capacity (``push_path`` / ``push_port``),
so there is no fixed upper bound:

.. code-block:: c

   struct caged_opts {
     const char **r_dir;      int n_r;   int cap_r;
     const char **rw_dir;     int n_rw;  int cap_rw;
     unsigned long long released_scopes;
     unsigned long long released_net;
     unsigned long long restrict_flags;
     unsigned short *connect_ports; int n_connect; int cap_connect;
     unsigned short *bind_ports;    int n_bind;    int cap_bind;
     int allow_unix_sockets;
     int allow_network_sockets;
     int allow_sysv_ipc;
     int loopback_only;
     long max_procs;
     long require_abi;
     int keep_env;
     char **env;              int n_env;  int cap_env;
     int report_fd;
     int help;
   };

``parse_cmd_line`` (in ``cli.c``) walks ``argv`` with ``strcmp`` and fills the
struct. Usage errors are reported with ``fatal`` (no ``errno``); runtime
failures use ``die`` (which appends ``strerror(errno)``, and lives in
``main.c``). Running with no arguments is the one usage error that also prints
the help, on stderr.

The command to run is **not** one of the fields: ``parse_cmd_line`` hands it
back through its last parameter (``char ***cmd``), pointing into ``argv``. It
stays ``NULL`` when the parse stops before a command (``--help``, or a usage
error), so the front end can tell "run this" from "nothing to run". Keeping it
out of ``caged_opts`` says the truth about who reads it: ``caged_setup`` never
does, only the ``main`` that ``execvpe``\s it.

``cmd`` is ``char **`` (not ``const char **``) because it points into
``argv``; converting away the const would be a hole in the type system.

Filesystem rules
----------------

``allow_access`` opens the path with ``O_PATH | O_CLOEXEC`` and ``fstat``\s it.
The directory-only bits (``PERMS_DIRS_ONLY``) are stripped for a regular file,
because the kernel rejects them on a file. The open fd is used as
``parent_fd`` for the ``PATH_BENEATH`` rule and closed right after. Granting a
single file needs the rule on the file only: there is no need to also grant its
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
given: it is counted per real uid over the whole system, so a fixed default
would make the first fork fail on a busy host.

``close_inherited_fds`` is the other half of the socket filter. seccomp cannot
revoke a descriptor, and Landlock cannot either, so a socket handed to caged
already connected to a service outside the sandbox would bypass both layers.
``close_range(3, ~0U, 0)`` removes it. Keeping fds 0–2 means ``die`` can still
write to stderr after the fact.

The command environment
-----------------------

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
    are configuration and presentation, not authority. Dropping ``PATH`` sends
    a child to the libc's compiled fallback and loses venvs, and dropping the
    locale forces ``C``. The list is closed: no wildcard, so an
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
invalidates it. That is why the environment is the last step of the setup. The
``CAGED_DISABLE_WARNINGS`` switch is read at that same moment, before the
replacement, and recorded in ``caged_warnings_disabled``; otherwise dropping
it would make the switch impossible to use. And ``environ`` is ``NULL`` after
``clearenv()`` (which the unit tests use), so the loop guards against it.
``execvpe``
searches for the program with the **caller's** ``PATH``, not with the array it
is handed: a cleared environment does not stop ``caged -- sh`` from finding
``sh``, and what changes is the ``PATH`` the command itself sees.

The seccomp layer
-----------------

Creating a socket is not governed by any Landlock right, so a Landlock-only
sandbox is open for address families nobody asked for. caged closes that with
a `libseccomp <https://github.com/seccomp/libseccomp>`_ filter, built and
installed by ``apply_seccomp``.

The default action is ``SCMP_ACT_ALLOW`` and every rule denies, so the filter
is an allowlist of address families, not of syscalls. Eight helpers build it,
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
    The ``DENY_SYSCALLS`` table, unconditional. Five groups: the
    process-inspection calls that only need the same uid (``ptrace``,
    ``process_vm_readv``/``process_vm_writev``, ``pidfd_getfd``,
    ``process_madvise``, ``process_mrelease``, ``kcmp``); the keyring calls
    that reach the caller's own keys (``keyctl``, ``add_key``,
    ``request_key``); the kernel attack surface (``bpf``, ``perf_event_open``,
    ``userfaultfd``); the calls that load code into the kernel or take the
    machine down (``init_module``/``finit_module``/``delete_module``,
    ``kexec_load``/``kexec_file_load``, ``reboot``, ``swapon``/``swapoff``,
    ``acct``, ``quotactl``, ``iopl``/``ioperm``, ``modify_ldt``,
    ``open_by_handle_at``); and mounting, namespaces and the descriptor-based
    mount API (``unshare``, ``setns``, ``mount``, ``umount2``,
    ``pivot_root``, ``chroot``, ``move_mount``, ``open_tree``, ``fsopen``,
    ``fsconfig``, ``fsmount``, ``fspick``, ``mount_setattr``). Plus
    ``io_uring_setup``, the one that matters most: a ring's operations are
    submitted through shared memory and executed by ``io_uring_enter``, so
    ``IORING_OP_SOCKET``/``IORING_OP_CONNECT`` never appear as syscalls and
    would side-step every socket family rule above. ``clone3`` is in this
    group too, for the reason given under ``deny_clone_namespaces``.

``deny_clone_namespaces``
    ``clone`` with any bit of ``CLONE_NS_FLAGS`` set, one
    ``SCMP_CMP_MASKED_EQ`` rule per flag: ``SCMP_A0`` compares the flag word,
    so a call asking for several namespaces at once matches the rule of each
    of them. A new namespace is a fresh view of the system and a way around
    everything above: a mount namespace can overmount the granted paths, and a
    user namespace hands out ``CAP_SYS_ADMIN`` inside it. All eight are denied.
    The list is the kernel's ``CLONE_NEW*`` set verbatim, including
    ``CLONE_NEWTIME``, even though ``clone`` rejects ``CLONE_NEWTIME`` on its
    own: completeness costs a rule and keeps the table from having to be
    reasoned about. ``clone3`` cannot be filtered the same way: its flags sit
    behind a pointer and seccomp does not dereference arguments, so the whole
    syscall is denied with ``ENOSYS`` and the caller (glibc, musl) falls back
    to ``clone``, where the per-flag rules do apply. Denying ``clone3`` is what
    makes the per-flag rules meaningful rather than decorative.

``deny_sysv_ipc`` and ``deny_dangerous_syscalls`` delegate to
``deny_syscall_list``, which resolves each name with
``seccomp_syscall_resolve_name`` and adds a zero-argument
``SCMP_ACT_ERRNO(ENOSYS)`` rule. A name the library cannot resolve fails
**closed** (``seccomp_detail = -ENOSYS``) instead of installing a filter with a
hole in it. Driving by table keeps each list at one branch in ``seccomp.c``
instead of one per name. ``deny_clone_namespaces`` adds its rules directly,
since its table holds flags and not syscall names.

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
cannot be removed, so it can be installed in the setup and still govern the
command.

Going further
-------------

Embedding caged in another program is documented in :doc:`../library`: ``make
lib`` builds ``build/libcaged.a`` from the five sandbox objects.

Two cleanups remain. ``apply_seccomp`` builds and installs the filter in one
go; separating a side-effect-free ``build_seccomp_ctx`` from an
``apply_seccomp`` that only calls ``seccomp_load`` would let a unit test export
the generated filter as text (``seccomp_export_pfc``) and compare it. And the
four diagnostics globals are the remaining hidden state: they exist because
libseccomp returns ``-EINVAL``, ``-EPERM``-style codes instead of ``-1`` plus
``errno``.
