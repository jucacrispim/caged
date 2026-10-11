Build
=====

Building caged
--------------

To compile you need:

- a C compiler (``gcc`` or ``clang``);
- ``make``;
- Linux kernel headers providing ``linux/landlock.h``.

.. note::

   To compile, a kernel supporting at least abi version 6 is needed.


Then run:

.. code-block:: sh

   make

This builds the ``caged`` binary in ``build/caged``. There is no install step;
just copy the binary to your $PATH.


Building the documentation
--------------------------

The docs are built with `Sphinx <https://www.sphinx-doc.org/>`_.

From the project root:

.. code-block:: sh

   make docs-env   # create the venv and install the docs requirements
   make docs       # build the HTML into docs/build/html

The rendered documentation entry point is ``docs/build/html/index.html``.
