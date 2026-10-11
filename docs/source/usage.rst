Usage
=====

Synopsis
--------

.. code-block:: text

   caged [OPTIONS] -- CMD [ARGS...]

``caged`` builds the sandbox, then ``execvp``\s into ``CMD``. Everything after
``--`` is the command and its arguments.

Options
-------

Filesystem
~~~~~~~~~~

``--ro PATH``
    Allow reading ``PATH``. ``PATH`` may be a directory (read + traverse the
    whole tree) or a single regular file. Files that are only readable cannot
    be written, removed or replaced.

``--rw PATH``
    Allow reading and writing ``PATH`` (directory or single file). Adds
    creating, removing, renaming, truncating and the unix-socket lookup right
    on top of ``--ro``.

Network
~~~~~~~

TCP connect and bind are denied by default.

``--allow-connect-port PORT``
    Allow TCP ``connect`` to ``PORT``. Port ``0`` allows connecting from the
    ephemeral port range (i.e. letting the kernel choose the local port).

``--allow-bind-port PORT``
    Allow TCP ``bind`` to ``PORT``. Port ``0`` allows binding to an ephemeral
    port — useful for a server that does not care about the exact number.

``--allow-connect-tcp``
    Allow TCP ``connect`` to any port (releases the whole direction; conflicts
    with ``--allow-connect-port``).

``--allow-bind-tcp``
    Allow TCP ``bind`` to any port (conflicts with ``--allow-bind-port``).

.. note::

   A rule is per *port*, not per IP: allowing port 443 means any host on that
   port.

IPC scopes
~~~~~~~~~~

Signalling processes outside the sandbox and connecting to abstract unix
sockets are restricted by default.

``--allow-scoped-signal``
    Release the signal scope: the sandboxed process may signal processes
    outside its domain.

``--allow-scoped-abstract-unix``
    Release the abstract unix socket scope: the sandboxed process may connect
    to abstract unix sockets outside its domain.

Logging
~~~~~~~

``--log-same-exec-off``
    Disable the audit log for denials from the calling thread (and its
    children) while it runs the same executable, i.e. without an ``execve`` in
    between. Added in ABI 7.

``--log-new-exec-on``
    Enable the audit log for denials after an ``execve``. Added in ABI 7.

``--log-subdomains-off``
    Disable the audit log for denials coming from nested Landlock domains.
    Added in ABI 7.

Thread sync
~~~~~~~~~~~

``--tsync``
    Apply the sandbox to *all* threads of the process, not just the calling
    one. Added in ABI 8; required for correctness if the process is
    multi-threaded.

Misc
~~~~

``-h``, ``--help``
    Print the usage on stdout and exit.

Environment
-----------

``CAGED_DISABLE_WARNINGS=1``
    Silence the kernel-ABI compatibility warnings printed on stderr. Only the
    literal value ``1`` disables them.

Exit status
-----------

- **0** — the command ran (``caged`` replaces itself with the command, so the
  exit status is the command's).
- **1** — setup failed (Landlock unavailable, ruleset error, a path could not
  be opened) or the command could not be executed.
- **2** — usage error (unknown option, missing value, missing ``-- cmd``, or
  run with no arguments, which prints the help on stderr).

Examples
--------

Read a single file — only that file becomes reachable, not the rest of its
directory. The command itself and the shared libraries it needs must be
reachable too, otherwise it cannot start:

.. code-block:: sh

   ./build/caged --ro /usr/bin/cat --ro /usr/lib --ro /etc/hostname \
         -- cat /etc/hostname

A minimal interactive shell — the trees holding programs and their shared
libraries are read-only:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib -- sh

Add a writable scratch directory when the shell needs to write:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib --rw /tmp -- sh

Fetch a page over HTTPS — the network is denied unless a port (or a whole
direction) is allowed:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib --ro /etc \
         --allow-connect-port 443 -- curl https://example.com

Serve a directory on a fixed local port:

.. code-block:: sh

   ./build/caged --ro /usr --ro /bin --ro /usr/lib --ro "$PWD" \
         --allow-bind-port 8080 -- python3 -m http.server 8080

Print the available options:

.. code-block:: sh

   ./build/caged --help
