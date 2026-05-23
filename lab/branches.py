# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

# Demonstrate some issues with coverage.py branch testing.


def my_function(x):
    """This isn't real code, just snippets..."""

    # An infinite loop is structurally still a branch: it can next execute the
    # first line of the loop, or the first line after the loop.  But
    # "while True" will never jump to the line after the loop, so the line
    # is shown as a partial branch:

    i = 0
    while True:
        print("In while True")
        if i > 0:
            break
        i += 1
    print("Left the True loop")

    # Notice that "while 1" also has this problem.  Even though the compiler
    # knows there's no computation at the top of the loop, it's still expressed
    # in bytecode as a branch with two possibilities.

    i = 0
    while 1:
        print("In while 1")
        if i > 0:
            break
        i += 1
    print("Left the 1 loop")

    # Coverage.py lets developers exclude lines that they know will not be
    # executed.  So far, the branch coverage doesn't use all that information
    # when deciding which lines are partially executed.
    #
    # Here, even though the else line is explicitly marked as never executed,
    # the if line complains that it never branched to the else:

    if x < 1000:
        # This branch is always taken
        print("x is reasonable")
    else:  # pragma: nocover
        print("this never happens")

    # try-except structures are complex branches.  An except clause with a
    # type is a three-way branch: there could be no exception, there could be
    # a matching exception, and there could be a non-matching exception.
    #
    # Here we run the code twice: once with no exception, and once with a
    # matching exception.  The "except" line is marked as partial because we
    # never executed its third case: a non-matching exception.

    for y in (1, 2):
        try:
            if y % 2:
                raise ValueError("y is odd!")
        except ValueError:
            print("y must have been odd")
        print("done with y")
    print("done with 1, 2")

    # Another except clause, but this time all three cases are executed.  No
    # partial lines are shown:

    for y in (0, 1, 2):
        try:
            if y % 2:
                raise ValueError("y is odd!")
            if y == 0:
                raise Exception("zero!")
        except ValueError:
            print("y must have been odd")
        except:
            print("y is something else")
        print("done with y")
    print("done with 0, 1, 2")


my_function(1)
