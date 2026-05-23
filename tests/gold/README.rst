.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

Gold files
==========

These are files used in comparisons for some of the tests.  Code to support
these comparisons is in tests/goldtest.py.

If gold tests are failing, you may need to update the gold files by copying the
current output of the tests into the gold files. When a test fails, the actual
output is in the tests/actual directory. Those files are ignored by git.

There's a Makefile in the html directory for working with gold files and their
associated support files.

The gold files and the actual output files are not viewable as-is: they are
missing the support files (css etc) they need.  You can copy those support
files with::

    cd tests/gold/html
    make complete

If the new actual output is correct, you can use ``make update-gold`` to copy
the actual output as the new gold files.

If you have changed some of the supporting files (.css or .js), then ``make
update-support`` will copy the updated files to the tests/gold/html/support
directory for checking test output.

If you have added a gold test, you'll need to manually copy the tests/actual
files to tests/gold.

Once you've copied the actual results to the gold files, or to check your work
again, you can run just the failed tests again with::

    tox -e py39 -- -n 0 --lf

The saved HTML files in the html directories can't be viewed properly without
the supporting CSS and Javascript files. But we don't want to save copies of
those files in every subdirectory. The make target ``make complete`` in
tests/gold/html will copy the support files so you can open the HTML files to
see how they look.  When you are done checking the output, you can use ``make
clean`` to remove the support files from the gold directories.

If the output files are correct, you can update the gold files with ``make
update-gold``.  If there are version-specific gold files (for example,
bom/2/\*), you'll need to update them manually.
