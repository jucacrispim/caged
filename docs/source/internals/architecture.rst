Architecture
============

caged is a single translation unit, ``caged.c``. There is no library split yet:
everything lives in one file, and the unit tests include it directly (see
:doc:`testing`). This page describes how it is structured and how the setup
flow works. The semantics of the individual rights are in :doc:`rules`, and the
ABI gating in :doc:`abi`.

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

The three syscalls have no glibc wrapper, so they are issued raw with
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
     char **cmd;
     int help;
   };

``parse_cmd_line`` walks ``argv`` with ``strcmp`` and fills the struct. Usage
errors are reported with ``fatal`` (no ``errno``); runtime failures use
``die`` (which appends ``strerror(errno)``). Running with no arguments is the
one usage error that also prints the help, on stderr.

``struct landlock_path_beneath_attr.cmd`` note: ``cmd`` is ``char **`` (not
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

Going further
-------------

The declared end goal is to turn ``caged.c`` into a reusable library: split it
into ``caged.c`` (logic) + ``caged.h`` (the public API — ``enum caged_return``,
``caged_setup``, ``caged_strreturn``) + a ``main.c``, with the tests linking
against the object instead of including the source. The ``enum`` is already the
natural preparation for that. The original motivation is to embed caged in
another program to wrap a whole client process at launch.
