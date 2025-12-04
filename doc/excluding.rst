.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to create the tabbed multi-syntax
   configuration examples.  If those are wrong, the quality checks will fail.
   Running "make prebuild" checks them and produces the output.

.. [[[cog
    from cog_helpers import show_configs
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _excluding:

===============================
Excluding code from coverage.py
===============================

.. highlight:: python

You may have code in your project that you know won't be executed, and you want
to tell coverage.py to ignore it.  For example, you may have debugging-only
code that won't be executed during your unit tests. You can tell coverage.py to
exclude this code during reporting so that it doesn't clutter your reports with
noise about code that you don't need to hear about.

Coverage.py will look for comments marking clauses for exclusion.  In this
code, the "if debug" clause is excluded from reporting::

    a = my_function1()
    if debug:  # pragma: no cover
        msg = "blah blah"
        log_message(msg, a)
    b = my_function2()

By default, any line with a comment of ``pragma: no cover`` is excluded.  If
that line introduces a clause, for example, an ``if`` clause, or a function or
class definition, then the entire clause is also excluded.  Here the
``__repr__`` function is not reported as missing::

    class MyObject(object):
        def __init__(self):
            blah1()
            blah2()

        def __repr__(self):  # pragma: no cover
            return "<MyObject>"

Excluded code is executed as usual, and its execution is recorded in the
coverage data as usual. When producing reports though, coverage.py excludes it
from the list of missing code.


Branch coverage
---------------

When measuring :ref:`branch coverage <branch>`, a conditional will not be
counted as a branch if one of its choices is excluded::

    def only_one_choice(x):
        if x:
            blah1()
            blah2()
        else:  # pragma: no cover
            # x is always true.
            blah3()

Because the ``else`` clause is excluded, the ``if`` only has one possible next
line, so it isn't considered a branch at all.


Default exclusions
------------------

Coverage.py has a set of built-in exclusion patterns.  For line coverage, these
lines are automatically excluded:

- Any line with a comment like ``# pragma: no cover``.  Other slight
  differences in spacing and letter case are also recognized.

- Any line with only ``...`` in the code, for excluding placeholder function
  bodies.

For branch coverage, these kinds of branches are automatically excluded:

- A branch with a comment like ``# pragma: no branch``, including differences
  in spacing and letter case.

- Some branches that are known at compile time: ``if True:``, ``while True:``,
  and so on.

- A branch just for type checkers: ``if TYPE_CHECKING:``.

.. versionadded:: 7.10.0 the ``...`` and ``TYPE_CHECKING`` defaults.


Advanced exclusion
------------------

Coverage.py identifies exclusions by matching source code against a list of
regular expressions. Using :ref:`configuration files <config>` or the coverage
:ref:`API <api>`, you can add to that list. This is useful if you have
often-used constructs to exclude that can be matched with a regex. You can
exclude them all at once in your configuration without littering your code with
exclusion pragmas.

Before coverage.py 7.6.0, the regexes were matched against single lines of your
source code.  Now they can be multi-line regexes that find matches across
lines. See :ref:`multi_line_exclude`.

If a matched line introduces a block, the entire block is excluded from
reporting.  Matching a ``def`` line or decorator line will exclude an entire
function.

.. highlight:: ini

For example, you might decide that __repr__ functions are usually only used in
debugging code, and are uninteresting to test themselves.  You could exclude
all of them by adding a regex to the exclusion list:

.. [[[cog
    show_configs(
        ini=r"""
            [report]
            exclude_also =
                def __repr__
            """,
        toml=r"""
            [tool.coverage.report]
            exclude_also = [
                "def __repr__",
            ]
            """,
        )
.. ]]]

.. tabs::

    .. code-tab:: toml
        :caption: pyproject.toml

        [tool.coverage.report]
        exclude_also = [
            "def __repr__",
        ]

    .. code-tab:: ini
        :caption: .coveragerc

        [report]
        exclude_also =
            def __repr__

    .. code-tab:: toml
        :caption: .coveragerc.toml

        # You can also use sections like [tool.coverage.run]
        [report]
        exclude_also = [
            "def __repr__",
        ]

    .. code-tab:: ini
        :caption: setup.cfg or tox.ini

        [coverage:report]
        exclude_also =
            def __repr__

.. [[[end]]] (sum: pma7Vgh8a0)

For example, here's a list of exclusions I've used:

.. [[[cog
    show_configs(
        ini=r"""
            [report]
            exclude_also =
                def __repr__
                if self.debug:
                if settings.DEBUG
                raise AssertionError
                raise NotImplementedError
                if 0:
                if __name__ == .__main__.:
                if TYPE_CHECKING:
                class .*\bProtocol\):
                @(abc\.)?abstractmethod
            """,
        toml=r"""
            [tool.coverage.report]
            exclude_also = [
                'def __repr__',
                'if self.debug:',
                'if settings.DEBUG',
                'raise AssertionError',
                'raise NotImplementedError',
                'if 0:',
                'if __name__ == .__main__.:',
                'if TYPE_CHECKING:',
                'class .*\bProtocol\):',
                '@(abc\.)?abstractmethod',
            ]
            """,
        )
.. ]]]

.. tabs::

    .. code-tab:: toml
        :caption: pyproject.toml

        [tool.coverage.report]
        exclude_also = [
            'def __repr__',
            'if self.debug:',
            'if settings.DEBUG',
            'raise AssertionError',
            'raise NotImplementedError',
            'if 0:',
            'if __name__ == .__main__.:',
            'if TYPE_CHECKING:',
            'class .*\bProtocol\):',
            '@(abc\.)?abstractmethod',
        ]

    .. code-tab:: ini
        :caption: .coveragerc

        [report]
        exclude_also =
            def __repr__
            if self.debug:
            if settings.DEBUG
            raise AssertionError
            raise NotImplementedError
            if 0:
            if __name__ == .__main__.:
            if TYPE_CHECKING:
            class .*\bProtocol\):
            @(abc\.)?abstractmethod

    .. code-tab:: toml
        :caption: .coveragerc.toml

        # You can also use sections like [tool.coverage.run]
        [report]
        exclude_also = [
            'def __repr__',
            'if self.debug:',
            'if settings.DEBUG',
            'raise AssertionError',
            'raise NotImplementedError',
            'if 0:',
            'if __name__ == .__main__.:',
            'if TYPE_CHECKING:',
            'class .*\bProtocol\):',
            '@(abc\.)?abstractmethod',
        ]

    .. code-tab:: ini
        :caption: setup.cfg or tox.ini

        [coverage:report]
        exclude_also =
            def __repr__
            if self.debug:
            if settings.DEBUG
            raise AssertionError
            raise NotImplementedError
            if 0:
            if __name__ == .__main__.:
            if TYPE_CHECKING:
            class .*\bProtocol\):
            @(abc\.)?abstractmethod

.. [[[end]]] (sum: QV2NECVQ1X)

The :ref:`config_report_exclude_also` option adds regexes to the built-in
default list so that you can add your own exclusions.  The older
:ref:`config_report_exclude_lines` option completely overwrites the list of
regexes.

The regexes only have to match part of a line. Be careful not to over-match.
The regex ``...`` will match any line with more than three characters in it,
which is certainly not what you want to exclude.


.. _multi_line_exclude:

Multi-line exclusion regexes
----------------------------

.. versionadded:: 7.6.0

Exclusion regexes can match multi-line regions.  All of the lines in a matched
region will be excluded.  If part of the region introduces a block, the entire
block is excluded even if part of it is outside the matched region.

When writing regexes to match multiple lines, remember that ``"."`` won't match
a newline character, but ``"\n"`` or ``"(?s:.)"`` will.  The regexes in these
settings are combined, so you cannot use global flags like ``(?s)`` in
your regexes.  Use the scoped flag form instead: ``(?s:...)``

Here are some examples:

.. [[[cog
    show_configs(
        ini=r"""
            [report]
            exclude_also =
                ; 1. Exclude an except clause of a specific form:
                except ValueError:\n\s*assume\(False\)
                ; 2. Comments to turn coverage on and off:
                no cover: start(?s:.)*?no cover: stop
                ; 3. A pragma comment that excludes an entire file:
                \A(?s:.*# pragma: exclude file.*)\Z
            """,
        toml=r"""
            [tool.coverage.report]
            exclude_also = [
                # 1. Exclude an except clause of a specific form:
                'except ValueError:\n\s*assume\(False\)',
                # 2. Comments to turn coverage on and off:
                'no cover: start(?s:.)*?no cover: stop',
                # 3. A pragma comment that excludes an entire file:
                '\A(?s:.*# pragma: exclude file.*)\Z',
            ]
            """,
        )
.. ]]]

.. tabs::

    .. code-tab:: toml
        :caption: pyproject.toml

        [tool.coverage.report]
        exclude_also = [
            # 1. Exclude an except clause of a specific form:
            'except ValueError:\n\s*assume\(False\)',
            # 2. Comments to turn coverage on and off:
            'no cover: start(?s:.)*?no cover: stop',
            # 3. A pragma comment that excludes an entire file:
            '\A(?s:.*# pragma: exclude file.*)\Z',
        ]

    .. code-tab:: ini
        :caption: .coveragerc

        [report]
        exclude_also =
            ; 1. Exclude an except clause of a specific form:
            except ValueError:\n\s*assume\(False\)
            ; 2. Comments to turn coverage on and off:
            no cover: start(?s:.)*?no cover: stop
            ; 3. A pragma comment that excludes an entire file:
            \A(?s:.*# pragma: exclude file.*)\Z

    .. code-tab:: toml
        :caption: .coveragerc.toml

        # You can also use sections like [tool.coverage.run]
        [report]
        exclude_also = [
            # 1. Exclude an except clause of a specific form:
            'except ValueError:\n\s*assume\(False\)',
            # 2. Comments to turn coverage on and off:
            'no cover: start(?s:.)*?no cover: stop',
            # 3. A pragma comment that excludes an entire file:
            '\A(?s:.*# pragma: exclude file.*)\Z',
        ]

    .. code-tab:: ini
        :caption: setup.cfg or tox.ini

        [coverage:report]
        exclude_also =
            ; 1. Exclude an except clause of a specific form:
            except ValueError:\n\s*assume\(False\)
            ; 2. Comments to turn coverage on and off:
            no cover: start(?s:.)*?no cover: stop
            ; 3. A pragma comment that excludes an entire file:
            \A(?s:.*# pragma: exclude file.*)\Z

.. [[[end]]] (sum: LAn0Y4yP/X)

The first regex matches a specific except line followed by a specific function
call.  Both lines must be present for the exclusion to take effect. Note that
the regex uses ``"\n\s*"`` to match the newline and the indentation of the
second line.  Without these, the regex won't match.

The second regex creates a pair of comments that can be used to exclude
statements between them.   All lines between ``# no cover: start`` and ``# no
cover: stop`` will be excluded.  The regex doesn't start with ``#`` because
that's a comment in a .coveragerc file.  Be careful with wildcards: we've used
the non-greedy ``*?`` to match the fewest possible characters between the
comments.  If you used the greedy ``*`` instead, the star would match as many
as possible, and you could accidentally exclude large swaths of code.

The third regex matches the entire text of a file containing the comment ``#
pragma: exclude file``.  This lets you exclude files from coverage measurement
with an internal comment instead of naming them in a settings file.  This regex
uses the ``"(?s:...)"`` regex flag to let a dot match any character including a
newline.


Excluding source files
----------------------

See :ref:`source` for ways to limit what files coverage.py measures or reports
on.
