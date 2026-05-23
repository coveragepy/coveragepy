.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. _subprocess:
.. _processes:

==================
Managing processes
==================

For coverage measurement to work properly, coverage has to be involved at the
very beginning and very end of the Python process.  There a number of ways to
start processes and to stop them.  Each has their own technique for involving
coverage correctly.

The simplest case is running a Python program that executes to the end and
exits normally.  `coverage run` will start coverage before the program starts,
and will write the data file when the process exits.

Starting processes
------------------

If your system under test spawns Python subprocesses, you'll have to take extra
steps to measure coverage in those processes.  Your main program is measured
because you started it with coverage, but the subprocesses need to have
coverage started on them also.

subprocess
..........

The simplest way is to use the :ref:`patch = subprocess <config_run_patch>`
setting in your configuration file.  This will configure everything to collect
data in Python processes you created.  This should work for processes created
with :mod:`subprocess`, :func:`os.system`, or one of the :func:`execv
<python:os.execl>` or :func:`spawnv <python:os.spawnl>` family of functions.

You will also need the :ref:`parallel option <config_run_parallel>` to collect
separate data for each process, and the :ref:`coverage combine <cmd_combine>`
command to combine them together before reporting.

The patch setting should work for most cases, but if you have a more unusual
situation, you might need to coordinate the mechanisms yourself.  The
:ref:`manual_subprocesses` section below describes the details.


multiprocessing
...............

The :mod:`python:multiprocessing` module in the Python standard library
provides high-level tools for managing subprocesses.  If you use it, the
:ref:`concurrency = multiprocessing <config_run_concurrency>` and :ref:`sigterm
<config_run_sigterm>` settings will configure coverage to measure the
subprocesses.

Even with multiprocessing, you have to be careful that all subprocesses
terminate cleanly or they won't record their coverage measurements.  For
example, the correct way to use a Pool requires closing and joining the pool
before terminating::

    with multiprocessing.Pool() as pool:
        # ... use any of the pool methods ...
        pool.close()
        pool.join()


execv and spawnv
................

The :func:`execv <python:os.execl>` and :func:`spawnv <python:os.spawnl>`
families of functions start new execution, either replacing the current process
or starting a new subprocess.  The ``exec*e`` and ``spawn*e`` variants take a
new set of environment variables to use for the new program.  To start coverage
measurement, the ``COVERAGE_PROCESS_START`` value must be copied from the
current environment into the new environment or set. It should be the absolute
path to the coverage configuration file to use.


Ending processes
----------------

If coverage has been started and your process ends cleanly, it should write the
coverage data file with no intervention needed.  Other ways to end the process
wouldn't normally let coverage write the data file, but can be accommodated:

SIGTERM
.......

If your process ends because it received a SIGTERM signal, you can specify that
coverage should write data when the signal is sent with the
:ref:`config_run_sigterm` setting.

os._exit()
..........

If your program ends by calling :func:`python:os._exit` (or a library does),
you can patch that function with :ref:`patch = _exit <config_run_patch>` to
give coverage a chance to write data before the process exits.

execv
.....

If your program ends by calling one of the :func:`execv <python:os.execl>`
functions, using :ref:`patch = execv <config_run_patch>` will let coverage
write its data before the execution begins.


Long-running processes
......................

Some processes like servers normally never end.  You can get coverage data from
these processes using the ``--save-signal`` option on the ``coverage run``
command line.  You can send the process the signal to write the coverage data
file when you choose without ending the process.


.. _manual_subprocesses:

Manual sub-process coordination
-------------------------------

If none of the existing settings work for your situation, you can configure
Python to start coverage when it runs.  Coverage.py includes a function
designed to be invoked when Python starts: :func:`coverage.process_startup`.
It examines the ``COVERAGE_PROCESS_START`` environment variable, and if it is
set, begins coverage measurement. The environment variable's value will be used
as the name of the :ref:`configuration file <config>` to use.

To arrange all this, you have to do two things: set a value for the
``COVERAGE_PROCESS_START`` environment variable, and then configure Python to
invoke :func:`coverage.process_startup` when Python processes start.

How you set ``COVERAGE_PROCESS_START`` depends on the details of how you create
subprocesses.  As long as the environment variable is visible in your
subprocess, it will work.

You can configure your Python installation to invoke the ``process_startup``
function by creating a .pth file in your Python installation containing::

    import coverage; coverage.process_startup()

You can create the file with any name you like.  The file must be in a
system-defined directory, so you may need privileges to write it.


Explicit coverage
.................

Another option for running coverage on your subprocesses it to run coverage
explicitly as the command for your subprocess instead of using "python" as the
command.  This isn't recommended, since it requires running different code
when running coverage than when not, which can complicate your test
environment.
