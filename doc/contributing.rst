.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. _contributing:

===========================
Contributing to coverage.py
===========================

.. highlight:: console

I welcome contributions to coverage.py.  Over the years, hundreds of people
have provided contributions of various sizes to add features, fix bugs, or just
help diagnose thorny issues.  This page should have all the information you
need to make a contribution.

One source of history or ideas are the `bug reports`_ against coverage.py.
There you can find ideas for requested features, or the remains of rejected
ideas.

.. _bug reports: https://github.com/coveragepy/coveragepy/issues


Before you begin
----------------

If you have an idea for coverage.py, run it by me before you begin writing
code.  This way, I can get you going in the right direction, or point you to
previous work in the area.  Things are not always as straightforward as they
seem, and having the benefit of lessons learned by those before you can save
you frustration.

If you find an issue to work on, check if there is already a pull request in
process to fix it. It's better to add to an existing pull request than to
duplicate the work.

We have a `#coverage channel in the Python Discord <discord_>`_ that can be a
good place to explore ideas, get help, or help people with coverage.py.
`Come there <discord_>`_ after `joining the Python Discord server <join_>`_.

Cooperation and communication are essential. If you make a pull request, I
might make comments. You need to respond. Be concise and helpful.

.. _discord: https://discord.com/channels/267624335836053506/1253355750684753950
.. _join: https://discord.com/invite/python


Getting the code
----------------

The coverage.py code is hosted on a GitHub repository at
https://github.com/coveragepy/coveragepy.  To get a working environment, follow
these steps:

#.  `Fork the repo`_ into your own GitHub account.  The coverage.py code will
    then be copied into a GitHub repository at
    ``https://github.com/GITHUB_USER/coveragepy`` where GITHUB_USER is your
    GitHub username.

#.  (Optional) Create a virtualenv to work in, and activate it.  There are a
    number of ways to do this.  Use the method you are comfortable with.
    Ideally, use Python |min-py| (the lowest version coverage.py currently
    supports).

#.  Clone the repository::

        $ git clone https://github.com/GITHUB_USER/coveragepy
        $ cd coveragepy

#.  Install the requirements with either of these commands::

        $ make install
        # ...or:
        $ pip install -r requirements/dev.txt

.. _fork the repo: https://docs.github.com/en/get-started/quickstart/fork-a-repo


Tests
-----

Most of the tests are for the Python code, but we also have JavaScript tests
for the JavaScript in the HTML reports.

Python tests
............

The Python tests are a mix of unittest-style tests and pytest-style tests. They
are run with pytest running under `tox`_. They will run automatically via
GitHub actions when you push your changes to GitHub, but it's also a good idea
to run them locally for faster feedback::

    $ tox -e py310

Tox runs the complete test suite a few times for each version of Python you
have installed.  The first run uses the C implementation of the trace function,
the second uses the Python implementation.  If `sys.monitoring`_ is available,
the suite will be run again with that core.

To limit tox to just a few versions of Python, use the ``-e`` switch::

    $ tox -e py38,py39

On the tox command line, options after ``--`` are passed to pytest.  To run
just a few tests, you can use `pytest test selectors`_::

    $ tox -- tests/test_misc.py
    $ tox -- tests/test_misc.py::HasherTest
    $ tox -- tests/test_misc.py::HasherTest::test_string_hashing

These commands run the tests in one file, one class, and just one test,
respectively.  The pytest ``-k`` option selects tests based on a word in their
name, which can be very convenient for ad-hoc test selection.  Of course you
can combine tox and pytest options::

    $ tox -q -e py310 -- -n 0 -vv -k hash

You can also affect the test runs with environment variables:

- ``COVERAGE_ONE_CORE=1`` will use only one tracing core for each Python
  version.  This isn't about CPU cores, it's about the central code that tracks
  execution.  This will use the preferred core for the Python version and
  implementation being tested.

- ``COVERAGE_TEST_CORES=...`` defines the cores to run tests on.  Three cores
  are available, specify them as a comma-separated string:

  - ``ctrace`` is a sys.settrace function implemented in C.
  - ``pytrace`` is a sys.settrace function implemented in Python.
  - ``sysmon`` is a `sys.monitoring`_ implementation.

- ``COVERAGE_AST_DUMP=1`` will dump the AST tree as it is being used during
  code parsing.

There are other environment variables that affect tests.  I use `set_env.py`_
as a simple terminal interface to see and set them.

Of course, run all the tests on every version of Python you have before
submitting a change.

JavaScript tests
................

The JavaScript tests for the HTML report are in tests/js.  To run them in a
headless browser::

    $ make test_js

You can also see them in a web browser by loading tests/js/index.html. These
tests are run in CI when the report JavaScript changes, but be sure to run them
yourself if you have changed any aspect of the HTML reports.

Coverage testing coverage.py
............................

Coverage.py can measure itself, but it's complicated.  The process has been
packaged up to make it easier::

    $ make metacov metahtml

Then look at htmlcov/index.html.  Note that due to the recursive nature of
coverage.py measuring itself, there are some parts of the code that will never
appear as covered, even though they are executed.

.. _pytest test selectors: https://doc.pytest.org/en/stable/usage.html#specifying-which-tests-to-run
.. _set_env.py: https://nedbatchelder.com/blog/201907/set_envpy.html
.. _sys.monitoring: https://docs.python.org/3/library/sys.monitoring.html
.. _tox: https://tox.readthedocs.io/


Quality checks
--------------

Keep the coverage.py source as clean as possible.  We use pylint to
alert me to possible problems::

    $ make lint

The source is pylint-clean, even if it's because there are pragmas quieting
some warnings.  Try to keep it that way, but don't let pylint warnings
keep you from sending patches.  I can clean them up.

Lines should be kept to a 100-character maximum length.  I recommend an
`editorconfig.org`_ plugin for your editor of choice, which will also help with
indentation, line endings and so on.  Source files are formatted with `ruff`_.

I use `pre-commit`_ to run checks and formatting when making commits, you
should also.

Other style questions are best answered by looking at the existing code.
Formatting of docstrings, comments, long lines, and so on, should match the
code that already exists.

.. _editorconfig.org: http://editorconfig.org
.. _ruff: https://pypi.org/project/ruff/
.. _pre-commit: https://pre-commit.com/


Documentation
-------------

User-visible changes should include updates to the documentation. Stay focused
on the users' perspective.

Changelog
.........

User-visible changes are described in CHANGES.rst, but don't edit that file.
Use `scriv`_ to create a changelog fragment as part of your pull request::

    $ scriv create

Describe your change briefly, using syntax and tone similar to entries in
CHANGES.rst. Provide links to the issue and pull request.

The fragment will be collected into CHANGES.rst when a release is made.

Cog
...

Parts of the documentation and GitHub actions are kept up-to-date with `cog`_.
There are checks to make sure that files are correct and not being incorrectly
edited.

If a check fails, it will show you what command to run to update the files.
If you edit parts of a file that should be generated, you will see a message
like::

    Output has been edited! Delete old checksum to unprotect.

Probably you should revert the edits and run the command to generate the
output.  The top of the file you edited will have instructions.

.. _scriv: https://scriv.readthedocs.io
.. _cog: https://cog.readthedocs.io


Continuous integration
----------------------

When you make a pull request, `GitHub actions`_ will run all of the Python
tests and quality checks on your changes.  If any fail, either fix them or ask
for help.

CI includes checks for things like missing coverage. There should be messages
explaining what went wrong.

.. _GitHub actions: https://github.com/coveragepy/coveragepy/actions


Dependencies
------------

Coverage.py has no direct runtime dependencies, and I would like to keep it
that way.

It has many development dependencies.  These are specified generically in the
``requirements/*.in`` files.  The .in files should have no versions specified
in them.  The specific versions to use are pinned in ``requirements/*.txt``
files.  These are created by running ``make upgrade``.

It's important to use Python |min-py| to run ``make upgrade`` so that the
pinned versions will work on all of the Python versions currently supported by
coverage.py.

If for some reason we need to constrain a version of a dependency, the
constraint should be specified in the ``requirements/pins.txt`` file, with a
detailed reason for the pin.


Contributing
------------

When you are ready to contribute a change, make a GitHub pull request. Be clear
about how you want to stay involved in finishing it and merging it.

Always include test, documentation, and a changelog fragment as appropriate.
