.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

===========
Coverage.py
===========

Coverage.py is a tool for measuring code coverage of Python programs. It
monitors your program, noting which parts of the code have been executed, then
analyzes the source to identify code that could have been executed but was not.

Coverage measurement is typically used to gauge the effectiveness of tests. It
can show which parts of your code are being exercised by tests, and which are
not.

The latest version is coverage.py |release|, released |release_date|.  It is
supported on:

.. PYVERSIONS

* Python 3.10 through 3.15 alpha, including free-threading.
* PyPy3 versions 3.10 and 3.11.

.. ifconfig:: prerelease

    **This is a pre-release build.  The usual warnings about possible bugs
    apply.** The latest stable version is coverage.py 7.12.0, `described here`_.

.. _described here: http://coverage.readthedocs.io/


For Enterprise
--------------

.. image:: media/Tidelift_Logos_RGB_Tidelift_Shorthand_On-White.png
   :width: 75
   :alt: Tidelift
   :align: left
   :class: tideliftlogo
   :target: https://tidelift.com/subscription/pkg/pypi-coverage?utm_source=pypi-coverage&utm_medium=referral&utm_campaign=readme

`Available as part of the Tidelift Subscription. <Tidelift Subscription_>`_ |br|
Coverage and thousands of other packages are working with
Tidelift to deliver one enterprise subscription that covers all of the open
source you use.  If you want the flexibility of open source and the confidence
of commercial-grade software, this is for you. `Learn more. <Tidelift
Subscription_>`_

.. _Tidelift Subscription: https://tidelift.com/subscription/pkg/pypi-coverage?utm_source=pypi-coverage&utm_medium=referral&utm_campaign=docs


Quick start
-----------

Getting started is easy:

#.  Install coverage.py::

        $ python3 -m pip install coverage

    For more details, see :ref:`install`.

#.  Use ``coverage run`` to run your test suite and gather data. However you
    normally run your test suite, you can use your test runner under coverage.

    .. tip::
        If your test runner command starts with "python", replace the initial
        "python" with "coverage run".

        ``python something.py`` becomes ``coverage run something.py``

        ``python -m amodule`` becomes ``coverage run -m amodule``

    Other instructions for specific test runners:

    .. tabs::

        .. tab:: pytest

            If you usually use::

                $ pytest arg1 arg2 arg3

            then you can run your tests under coverage with::

                $ coverage run -m pytest arg1 arg2 arg3

            Many people choose to use the `pytest-cov`_ plugin, but for most
            purposes, it is unnecessary.

        .. tab:: unittest

            Change your python command name to "coverage run", so this::

                $ python3 -m unittest discover

            becomes::

                $ coverage run -m unittest discover

        .. tab:: nosetest

            .. note:: Nose has been `unmaintained since at least 2015 <nose state_>`_.
                *You should seriously consider using a different test runner.*

            Change this::

                $ nosetests arg1 arg2

            to::

                $ coverage run -m nose arg1 arg2

    Coverage doesn't distinguish between tests and the code being tested.
    We `recommend that you include your tests in coverage measurement <include
    tests_>`_.

    To limit coverage measurement to code in the current directory, and also
    find files that weren't executed at all, add the ``--source=.`` argument to
    your coverage command line.  You can also :ref:`specify source files to
    measure <source>` or :ref:`exclude code from measurement <excluding>`.

#.  Use ``coverage report`` to report on the results::

        $ coverage report -m
        Name                      Stmts   Miss  Cover   Missing
        -------------------------------------------------------
        my_program.py                20      4    80%   33-35, 39
        my_other_module.py           56      6    89%   17-23
        -------------------------------------------------------
        TOTAL                        76     10    87%

#.  For a nicer presentation, use ``coverage html`` to get annotated HTML
    listings detailing missed lines::

        $ coverage html
        Wrote HTML report to htmlcov/index.html

    .. ifconfig:: not prerelease

        Then open `htmlcov/index.html <htmlreport_>`__ in your browser
        to see a `report like this <htmlreport_>`__.

    .. ifconfig:: prerelease

        Then open `htmlcov/index.html <betahtmlreport_>`__ in your browser
        to see a `report like this <betahtmlreport_>`__.


.. _htmlreport: https://nedbatchelder.com/files/sample_coverage_html/index.html
.. _betahtmlreport: https://nedbatchelder.com/files/sample_coverage_html_beta/index.html
.. _nose state: https://github.com/nose-devs/nose/commit/0f40fa995384afad77e191636c89eb7d5b8870ca
.. _include tests: https://nedbatchelder.com/blog/202008/you_should_include_your_tests_in_coverage.html



Capabilities
------------

Coverage.py can do a number of things:

- By default it will measure line (statement) coverage.

- It can also measure :ref:`branch coverage <branch>`.

- It can tell you :ref:`what tests ran which lines <dynamic_contexts>`.

- It can produce reports in a number of formats: :ref:`text <cmd_report>`,
  :ref:`HTML <cmd_html>`, :ref:`XML <cmd_xml>`, :ref:`LCOV <cmd_lcov>`,
  and :ref:`JSON <cmd_json>`.

- For advanced uses, there's an :ref:`API <api>`, and the result data is
  available in a :ref:`SQLite database <dbschema>`.


Using coverage.py
-----------------

There are a few different ways to use coverage.py.  The simplest is the
:ref:`command line <cmd>`, which lets you run your program and see the results.
If you need more control over how your project is measured, you can use the
:ref:`API <api>`.

Some test runners provide coverage integration to make it easy to use
coverage.py while running tests.  For example, `pytest`_ has the `pytest-cov`_
plugin.

You can fine-tune coverage.py's view of your code by directing it to ignore
parts that you know aren't interesting.  See :ref:`source` and :ref:`excluding`
for details.

.. _pytest: http://doc.pytest.org
.. _pytest-cov: https://pytest-cov.readthedocs.io/


.. _contact:

Getting help
------------

If the :ref:`FAQ <faq>` doesn't answer your question, you can discuss
coverage.py or get help using it on the `Python discussion forums`_ or in the
`Python Discord`_. If you ping me (``@nedbat``), there's a higher chance I'll
see the post.

.. _Python discussion forums: https://discuss.python.org/
.. _Python Discord: https://discord.com/channels/267624335836053506/1253355750684753950

Bug reports are gladly accepted at the `GitHub issue tracker`_.
GitHub also hosts the `code repository`_.

.. _GitHub issue tracker: https://github.com/coveragepy/coveragepy/issues
.. _code repository: https://github.com/coveragepy/coveragepy

Professional support for coverage.py is available as part of the `Tidelift
Subscription`_.

`I can be reached`_ in a number of ways. I'm happy to answer questions about
using coverage.py.

.. _I can be reached: https://nedbatchelder.com/site/aboutned.html

.. raw:: html

    <p>For news and other chatter, follow the project on Mastodon:
    <a rel="me" href="https://hachyderm.io/@coveragepy">@coveragepy@hachyderm.io</a>.</p>

More information
----------------

.. toctree::
    :maxdepth: 1

    install
    For enterprise <https://tidelift.com/subscription/pkg/pypi-coverage?utm_source=pypi-coverage&utm_medium=referral&utm_campaign=enterprise>
    commands/index
    config
    messages
    source
    excluding
    branch
    subprocess
    contexts
    api
    howitworks
    plugins
    other
    contributing
    trouble
    faq
    Change history <changes>
    migrating
    sleepy
