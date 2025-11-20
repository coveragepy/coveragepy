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
But the if was never evaluated as false, so line 2 never jumps to line 4.

Branch coverage will flag this code as not fully covered because of the missing
jump from line 2 to line 4.  This is known as a partial branch.


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

When measuring branches, coverage.py collects pairs of line numbers, a source
and destination for each transition from one line to another.  Static analysis
of the source provides a list of possible transitions.  Comparing the measured
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
=====================

Generator expressions may also report partial branch coverage. Consider the
following example::

    value = next(i in range(1))

While we might expect this line of code to be reported as covered, the
generator did not iterate until ``StopIteration`` is raised, the indication
that the loop is complete. This is another case
where adding ``# pragma: no branch`` may be desirable.


Missing Branches in branch-coverage
-----------------------------------
symbol:(->)
When running Coverage.py with branch measurement enabled, you may see missing branches reported in the form:
12->10  , why is it backward? This indicates that the loop never repeated (or never ran), so the backward branch was not taken.

For example::
    
    10: for x in items:
    11:     print(x)
    12:     # end of loop body
    13: print("done")
    
Possible branches:

    10 -> 11 (enter loop body)
    12 -> 10 (loop-back,repeat the loop)
    10 -> 13 (skip loop entirely)

Case 1 — items is empty : 10 -> 13 (skip loop is executed)
Missing:
    10 -> 11
    12 -> 10

Case 2 — items = [1] : 10 -> 11 (entered loop body,exceuted once,not repeated)
Missing:
    12 -> 10 

Coverage.py will report:
    12->10 

For a full list of control-flow constructs 
(if/else, for loops, while loops, try/except) and 
their branch examples,see the :doc:`Command-line report <commands/cmd_report>`.


