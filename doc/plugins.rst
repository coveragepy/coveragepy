.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to create the tabbed multi-syntax
   configuration examples.  If those are wrong, the quality checks will fail.
   Running "make prebuild" checks them and produces the output.

.. [[[cog
    from cog_helpers import show_configs
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _plugins:

========
Plug-ins
========

Coverage.py's behavior can be extended with third-party plug-ins.  A plug-in is
a separately installed Python class that you register in your .coveragerc.
Plugins can alter a number of aspects of coverage.py's behavior, including
implementing coverage measurement for non-Python files.

Information about using plug-ins is on this page.  To write a plug-in, see
:ref:`api_plugin`.

See :ref:`other` for available plug-ins.

.. versionadded:: 4.0


Using plug-ins
--------------

To use a coverage.py plug-in, you install it and configure it.  For this
example, let's say there's a Python package called ``something`` that provides
a coverage.py plug-in called ``something.plugin``.

#. Install the plug-in's package as you would any other Python package:

   .. code-block:: sh

    $ python3 -m pip install something

#. Configure coverage.py to use the plug-in.  You do this by editing (or
   creating) your .coveragerc file, as described in :ref:`config`.  The
   ``plugins`` setting indicates your plug-in.  It's a list of importable
   module names of plug-ins:

   .. [[[cog
        show_configs(
            ini=r"""
                [run]
                plugins =
                    something.plugin
                """,
            toml=r"""
                [tool.coverage.run]
                plugins = [ "something.plugin" ]
                """,
            )
   .. ]]]

   .. tabs::

       .. code-tab:: toml
           :caption: pyproject.toml

           [tool.coverage.run]
           plugins = [ "something.plugin" ]

       .. code-tab:: ini
           :caption: .coveragerc

           [run]
           plugins =
               something.plugin

       .. code-tab:: toml
           :caption: .coveragerc.toml

           # You can also use sections like [tool.coverage.run]
           [run]
           plugins = [ "something.plugin" ]

       .. code-tab:: ini
           :caption: setup.cfg or tox.ini

           [coverage:run]
           plugins =
               something.plugin

   .. [[[end]]] (sum: 7exEgyBxea)

#. If the plug-in needs its own configuration, you can add those settings in
   the .coveragerc file in a section named for the plug-in:

   .. [[[cog
        show_configs(
            ini=r"""
                [something.plugin]
                option1 = True
                option2 = abc.foo
                """,
            toml=r"""
                [tool.coverage.something.plugin]
                option1 = true
                option2 = "abc.foo"
                """,
            )
   .. ]]]

   .. tabs::

       .. code-tab:: toml
           :caption: pyproject.toml

           [tool.coverage.something.plugin]
           option1 = true
           option2 = "abc.foo"

       .. code-tab:: ini
           :caption: .coveragerc

           [something.plugin]
           option1 = True
           option2 = abc.foo

       .. code-tab:: toml
           :caption: .coveragerc.toml

           # You can also use sections like [tool.coverage.run]
           [something.plugin]
           option1 = true
           option2 = "abc.foo"

       .. code-tab:: ini
           :caption: setup.cfg or tox.ini

           [coverage:something.plugin]
           option1 = True
           option2 = abc.foo

   .. [[[end]]] (sum: xPc0F1izoA)

   Check the documentation for the plug-in for details on the options it takes.

#. Run your tests with coverage.py as you usually would.  If you get a message
   like "Plugin file tracers (something.plugin) aren't supported with
   PyTracer," then you don't have the :ref:`C extension <install_extension>`
   installed.  The C extension is needed for certain plug-ins.
