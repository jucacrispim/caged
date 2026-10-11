Testing
=======

The test suite is split in two layers: **unit** tests (fast, mocked, they are
what the coverage gate measures) and **functional** tests (the real binary
against the real kernel). They answer different questions, so both are needed:
coverage proves the code paths run; the functional layer proves the sandbox
actually behaves.

Layout
------

.. code-block:: text

   tests/
     unit/
       fake_syscalls.h / .c   mocks and spies (--wrap)
       test_abi.c             get_handled_access_* / get_supported_*
       test_allow_access.c    allow_access: dir vs file, errors
       test_parse_cmd_line.c  parsing, conflicts, OOM
       test_setup.c           caged_setup, caged_strreturn, warnings
       test_net.c             push_port, parse_port, net rules
       test_help.c            print_help, --help / -h, no-args
     functional/
       run.sh                 integration against the kernel

Unit technique: include the source and wrap the syscalls
--------------------------------------------------------

Each unit test includes the production source directly, which is what gives it
access to the ``static`` functions:

.. code-block:: c

   #define main caged_program_main
   #include "../../caged.c"
   #undef main

(``#undef main`` is required, otherwise the macro would rename the test's own
``main``.)

The kernel is replaced with the linker's ``--wrap`` facility: every call to a
wrapped symbol becomes a ``__wrap_*`` stub, and the real one stays available as
``__real_*``. caged wraps ``syscall``, ``open``, ``fstat``, ``close``, ``prctl``
and ``realloc``.

Because the compiler and libc like to rewrite calls to builtins, the tests
compile with ``-O0 -U_FORTIFY_SOURCE -fno-builtin`` — without these the wraps
miss their target.

The mocks (``fake_syscalls``)
-----------------------------

A single global ``struct fake_context fake`` holds both the **configuration**
(what each syscall returns — ``abi``, ``*_ret``, ``*_err``, ``fail_realloc``)
and the **spies** (``*_calls_count``, ``last_allowed_access``, ``last_scoped``,
``last_handled_net``, ``last_net_port``, ``last_restrict_flags`` ...).
``reset_fake`` zeroes everything through a compound literal, so there is a
single place to reset between cases.

Two subtleties the mocks handle:

- ``create_ruleset`` distinguishes the ABI **probe** (``attr == NULL`` and the
  version flag) from a real creation, and stores the requested ``scoped`` and
  ``handled_access_net`` in spies.
- ``add_rule`` reads all four varargs and branches on the rule type: a
  ``NET_PORT`` rule records port/access, a ``PATH_BENEATH`` rule records the
  parent fd and allowed access.

``open``, ``fstat`` and ``close`` are **partial** mocks: they only intercept
what caged uses (the ``O_PATH`` open; the fake fd for ``fstat``/``close``) and
delegate everything else to ``__real_*``. Mocking them globally would break the
coverage runtime, which writes its ``.gcda`` files through ``open``.

Errno is set by hand in the fake whenever it simulates a failure — there is no
real kernel to set it.

Coverage
--------

``make coverage`` compiles all the test binaries with ``--coverage`` and
``-fcondition-coverage``, runs them, and calls ``gcovr`` with a filter limited
to ``caged.c`` (each test includes the source, so without the filter gcovr
would sum the per-binary ``.gcda`` files and inflate the numbers). The gate
fails below **100%** on lines, branches, decisions and functions. Out-of-memory
paths (a failing ``realloc``) are covered by mocking, not excluded.

Only two regions carry ``GCOV_EXCL``: the body of ``die`` and ``main``. Both
are exercised by the functional tests instead.

``GCOV_EXCL`` is used only when explicitly requested; it is not a way to dodge a
hard-to-test branch.

Functional tests
----------------

``tests/functional/run.sh`` runs the production ``build/caged`` against the
real kernel. Each ``test_*`` case makes its own fixtures under ``mktemp -d``,
so cases are independent. It is the only layer that covers ``main``, ``die`` and
``execvp``, and it asserts the actual enforcement: reads/writes/removes inside
and outside the allowed trees, exit codes, network connect/bind, IPC scopes
(using ``python3`` for the unix-socket and TCP cases) and the ABI warnings.

The usual read-only base is ``--ro /usr --ro /bin --ro /lib`` (plus
``--ro /lib64 --ro /etc`` when ``python3`` is needed), which is the minimum to
run ordinary commands.

Targets
-------

.. code-block:: sh

   make unit        # compile and run the unit tests
   make functional  # run the integration tests against build/caged
   make test        # unit + functional
   make coverage    # gcovr report; fails below 100%
   make check       # unit + coverage + functional (the full gate)
