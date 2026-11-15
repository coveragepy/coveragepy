.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

OSS Scanner
===========

These files enroll coverage.py in Anthropic's `OSS Scanner`_.  project.yaml is
a copy of the file in that repo; Dockerfile and threat_model.md are read from
here.

To check that the Dockerfile still works, build the image and run the tests in
it with no network, as the scanner will::

    $ source tests/oss-scanner/local_run.sh

This builds from the last commit, so commit your changes first.  Tests that
need the network or a non-root user are marked xfail.

.. _OSS Scanner: https://github.com/anthropics/oss-scanner
