.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. _other:

===============
Other resources
===============

There are a number of projects that help integrate coverage.py into other
systems, provide help using it, offer assistance, and so on.

There's no guarantee these items are maintained or work well.  Some of them
seem to be quite old.  If you have suggestions for updates to this page, `open
a pull request`_ or `get in touch`_ some other way.

.. _open a pull request: https://github.com/coveragepy/coveragepy/blob/main/doc/other.rst
.. _get in touch: https://nedbatchelder.com/site/aboutned.html


Test runners
------------

Helpers for using coverage with specific test runners.

* `pytest-cov`__ is a pytest plugin to coordinate coverage.py usage.

  __ https://pypi.org/project/pytest-cov/

* `trialcoverage`__ is a plug-in for Twisted trial.

  __ https://pypi.org/project/trialcoverage/


Configuration helpers
---------------------

Tools to provide more control over how coverage is configured.

* `covdefaults`__ provides "sensible" default settings for coverage.

  __ https://github.com/asottile/covdefaults

* `coverage-conditional-plugin`__ lets you use conditions instead of simple "no
  cover" pragmas to control what lines are considered under different
  conditions.

  __ https://github.com/wemake-services/coverage-conditional-plugin

* `coverage-simple-excludes`__ defines new comment formats for excluding code
  based on Python versions and operating system.

  __ https://pypi.org/project/coverage-simple-excludes/


Language plugins
----------------

Coverage.py plugins to enable coverage measurement of other languages.

* `django-coverage-plugin`__ measures the coverage of Django templates.

  __ https://pypi.org/project/django-coverage-plugin/

* `Cython`__ provides a plugin for measuring Cythonized code.

  __ https://cython.readthedocs.io/en/latest/src/tutorial/profiling_tutorial.html#enabling-coverage-analysis

* `coverage-jinja-plugin`__ is an incomplete Jinja2 plugin.

  __ https://github.com/MrSenko/coverage-jinja-plugin

* `coverage-sh`__ measures code coverage of shell (sh or bash) scripts executed
  from Python with subprocess.

  __ https://github.com/lackhove/coverage-sh

* `hy-coverage`__ supports the Hy language.

  __ https://github.com/timmartin/hy-coverage

* `coverage-mako-plugin`__ measures coverage in Mako templates.
  Doesn't work yet, probably needs some changes in Mako itself.

  __ https://bitbucket-archive.softwareheritage.org/projects/ne/ned/coverage-mako-plugin.html


Reporting helpers
-----------------

Helpers for seeing the results.

* `python-coverage-comment-action`__ can publish a delta coverage report as a
  pull request comment, create a coverage badge, or a dashboard to display in
  your readme.

  __ https://github.com/py-cov-action/python-coverage-comment-action

* `diff-cover`__ reports on the coverage of lines changed in a pull request.

  __ https://pypi.org/project/diff-cover/

* `cuvner`__ offers alternate visualizations of coverage data, including ones
  for use in terminals.

  __ https://meejah.ca/projects/cuvner

* `emacs-python-coverage`__ is an experimental Emacs package to report code
  coverage output produced by Python's coverage package directly inside Emacs
  buffers.

  __ https://github.com/wbolster/emacs-python-coverage

* `python-genbadge`__ provides a set of command line utilities to generate
  badges for tools that do not provide one, including coverage badges.

  __ https://smarie.github.io/python-genbadge/


Other articles
--------------

Writings about ways to enhance your use of coverage.py.

* `How to Ditch Codecov for Python Projects`__: using GitHub Actions to manage
  coverage across versions and report on results.

  __ https://hynek.me/articles/ditch-codecov-python/

* `Making a coverage badge`__: using GitHub Actions to produce a colored badge.

  __ https://nedbatchelder.com/blog/202209/making_a_coverage_badge.html

* `Coverage goals`__: a sidecar tool for reporting on per-file coverage goals.

  __ https://nedbatchelder.com/blog/202111/coverage_goals.html
