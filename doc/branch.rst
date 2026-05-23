.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. _branch:

===========================
Branch coverage measurement
===========================

.. highlight:: python
   :linenothreshold: 5

In addition to the usual statement coverage, coverage.py also supports branch
coverage measurement. Where a line in your program could jump to more than one
next line, coverage.py tracks which of those destinations are actually visited,
and flags lines that haven't visited all of their possible destinations.

For example::

    def my_partial_fn(x):
        if x:
            y = 10
        return y

    my_partial_fn(1)

In this code, line 2 is an ``if`` statement which can go next to either line 3
or line 4. Statement coverage would show all lines of the function as executed.
But the ``if`` was never evaluated as false, so line 2 never jumps to line 4.

Branch coverage will flag this code as not fully covered because of the missing
jump from line 2 to line 4. This is known as a partial branch.

How to measure branch coverage
------------------------------

To measure branch coverage, run coverage.py with the ``--branch`` flag::

    coverage run --branch myprog.py

When you report on the results with ``coverage report`` or ``coverage html``,
the percentage of branch possibilities taken will be included in the percentage
covered total for each file.  The coverage percentage for a file is the actual
executions divided by the execution opportunities.  Each line in the file is an
execution opportunity, as is each branch destination.

The HTML report gives information about which lines had missing branches. Lines
that were missing some branches are shown in yellow, with an annotation at the
far right showing branch destination line numbers that were not exercised.

The XML and JSON reports produced by ``coverage xml`` and ``coverage json``
also include branch information, including separate statement and branch
coverage percentages.


How it works
------------

When measuring branches, coverage.py collects pairs of line numbers: a source
and destination for each transition from one line to another. Static analysis
of the source provides a list of possible transitions. Comparing the measured
to the possible indicates missing branches.

The idea of tracking how lines follow each other was from `Titus Brown`__.
Thanks, Titus!

__ http://ivory.idyll.org/blog


Excluding code
--------------

If you have :ref:`excluded code <excluding>`, a conditional will not be counted
as a branch if one of its choices is excluded::

    def only_one_choice(x):
        if x:
            blah1()
            blah2()
        else:  # pragma: no cover
            # x is always true.
            blah3()

Because the ``else`` clause is excluded, the ``if`` only has one possible next
line, so it isn't considered a branch at all.


Structurally partial branches
-----------------------------

Sometimes branching constructs are used in unusual ways that don't actually
branch.  For example::

    while True:
        if cond:
            break
        do_something()

Here the while loop will never exit normally, so it doesn't take both of its
"possible" branches.  For some of these constructs, such as "while True:" and
"if 0:", coverage.py understands what is going on.  In these cases, the line
will not be marked as a partial branch.

But there are many ways in your own code to write intentionally partial
branches, and you don't want coverage.py pestering you about them.  You can
tell coverage.py that you don't want them flagged by marking them with a
pragma::

    i = 0
    while i < 999999999:  # pragma: no branch
        if eventually():
            break

Here the while loop will never complete because the break will always be taken
at some point.  Coverage.py can't work that out on its own, but the "no branch"
pragma indicates that the branch is known to be partial, and the line is not
flagged.

Generator expressions
.....................

Generator expressions may also report partial branch coverage. Consider the
following example::

    value = next(i in range(1))

While we might expect this line of code to be reported as covered, the
generator did not iterate until ``StopIteration`` is raised, the indication
that the loop is complete. This is another case
where adding ``# pragma: no branch`` may be desirable.


.. _branch_explain:

Examples of missing branches
----------------------------

This section shows examples of missing branches in Python code and explains how
coverage.py reports them.


``for`` loop example
....................

Example::

    items = [1] # or empty, see the explanations
    for x in items:
        print(x)
        if x:
            print("x is true")
    print("done")

Here we have these possible branches:

* ``2 -> 3`` loop body executed
* ``2 -> 6`` loop exit
* ``4 -> 5`` if True
* ``4 -> 2`` if False, backward branch to top of loop


Case 1: ``items`` is empty::

    Missing:
    3-5

In this case, the loop body is never executed. Coverage reports the
loop body lines as missing, but does not report missing branches,
because the branching lines inside the loop are never executed.

Case 2: ``items = [1]``::

    Missing:
    4->2

Here, the loop body is executed, but the ``if`` statement on line 4 is always
true, so it always executes line 5. If the ``if`` condition were false, it
would jump from 4 to 2 to start the next iteration of the loop, but this never
happens, so coverage reports ``4->2`` as a missing branch.


``if / else`` example
.....................

Example::

    flag = True
    if flag:
        do_true()
    else:
        do_false()

Since ``flag`` is always true, the ``else`` branch is never taken.
This branch will be reported as missing: ``2->5``. Note that ``else`` itself
isn't an executable line, so it is not mentioned.


``while`` loop example
......................

Example::

    condition = True
    flag = True
    while condition:
        do_something = True
        if flag:
            condition = False
    print("done")

This code has these possible branches:

* ``3->4`` enter the body of the loop
* ``3->7`` exit the while loop
* ``5->6`` if True
* ``5->3`` if False, back to the top of the while loop.

The false branch of the ``if`` statement is
never taken, so coverage reports the missing branch as ``5->3``.
