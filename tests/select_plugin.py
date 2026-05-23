# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""
A pytest plugin to select tests by running an external command.

See lab/pick.py for how to use pick.py to subset test suites.

More about this: https://nedbatchelder.com/blog/202401/randomly_subsetting_test_suites.html

"""

import subprocess


def pytest_addoption(parser):
    """Add command-line options for controlling the plugin."""
    parser.addoption(
        "--select-cmd",
        metavar="CMD",
        action="store",
        default="",
        type=str,
        help="Command to run to get test names",
    )


def pytest_collection_modifyitems(config, items):  # pragma: debugging
    """Run an external command to get a list of tests to run."""
    select_cmd = config.getoption("--select-cmd")
    if select_cmd:
        output = subprocess.check_output(select_cmd, shell="True").decode("utf-8")
        test_nodeids = {nodeid: seq for seq, nodeid in enumerate(output.splitlines())}
        new_items = [item for item in items if item.nodeid in test_nodeids]
        items[:] = sorted(new_items, key=lambda item: test_nodeids[item.nodeid])
