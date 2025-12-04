# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Helper for building, testing, and linting coverage.py.

To get portability, all these operations are written in Python here instead
of in shell scripts, batch files, or Makefiles.

"""

import datetime
import glob
import inspect
import itertools
import os
import os.path
import platform
import pprint
import re
import subprocess
import sys
import sysconfig
import textwrap
import types
import zipfile

try:
    import pytest
except ImportError:
    # We want to be able to run this for some tasks that don't need pytest.
    pytest = None

# Constants derived the same as in coverage/env.py.  We can't import
# that file here, it would be evaluated too early and not get the
# settings we make in this file.

CPYTHON = platform.python_implementation() == "CPython"
PYPY = platform.python_implementation() == "PyPy"


# $set_env.py: COVERAGE_IGOR_VERBOSE - How much chatter from igor.py (default 1)
VERBOSITY = int(os.getenv("COVERAGE_IGOR_VERBOSE", "1"))

# Functions named do_* are executable from the command line: do_blah is run
# by "python igor.py blah".


def do_show_env():
    """Show the environment variables."""
    print("Environment:")
    for env in sorted(os.environ):
        print(f"  {env} = {os.environ[env]!r}")


def do_clean_for_core(core):
    """Remove the compiled C extension, no matter what its name."""

    if core == "ctrace":
        return

    so_patterns = """
        tracer.so
        tracer.*.so
        tracer.pyd
        tracer.*.pyd
        """.split()

    roots = [
        "coverage",
        "build/*/coverage",
        ".tox/*/[Ll]ib/*/site-packages/coverage",
        ".tox/*/[Ll]ib/site-packages/coverage",
    ]

    # On windows at least, we can't delete a loaded .pyd file. So move them
    # out of the way into the tmp/ directory.
    os.makedirs("tmp", exist_ok=True)
    for root, pattern in itertools.product(roots, so_patterns):
        pattern = os.path.join(root, pattern)
        if VERBOSITY > 1:
            print(f"Searching for {pattern} from {os.getcwd()}")
        for filename in glob.glob(pattern):
            if os.path.exists(filename):
                hidden = f"tmp/{os.path.basename(filename)}"
                if VERBOSITY > 1:
                    print(f"Moving {filename} to {hidden}")
                try:
                    if os.path.exists(hidden):
                        os.remove(hidden)
                except OSError as exc:
                    if VERBOSITY > 1:
                        print(f"Couldn't remove {hidden}: {exc}")
                else:
                    try:
                        os.rename(filename, hidden)
                    except OSError as exc:
                        if VERBOSITY > 1:
                            print(f"Couldn't rename: {exc}")


def label_for_core(core):
    """Get the label for these tests."""
    if core == "pytrace":
        return "with Python tracer"
    elif core == "ctrace":
        return "with C tracer"
    elif core == "sysmon":
        return "with sys.monitoring"
    else:
        raise ValueError(f"Bad core: {core!r}")


def should_skip(core, metacov):
    """Is there a reason to skip these tests?

    Return empty string to run tests, or a message about why we are skipping
    the tests.
    """
    skipper = ""

    if metacov and core == "sysmon" and ((3, 12) <= sys.version_info < (3, 14)):
        skipper = "sysmon can't measure branches in Python 3.12-3.13"

    # $set_env.py: COVERAGE_TEST_CORES - List of cores to run: ctrace, pytrace, sysmon
    test_cores = os.getenv("COVERAGE_TEST_CORES")
    if test_cores:
        if core not in test_cores:
            skipper = f"core {core} not in COVERAGE_TEST_CORES={test_cores}"
    else:
        # $set_env.py: COVERAGE_ONE_CORE - Only run tests for one core.
        only_one = os.getenv("COVERAGE_ONE_CORE")
        if only_one:
            if CPYTHON:
                if sys.version_info >= (3, 12):
                    if core != "sysmon":
                        skipper = f"Only one core: not running {core}"
                elif core != "ctrace":
                    skipper = f"Only one core: not running {core}"
            else:
                if core != "pytrace":
                    skipper = f"No C core for {platform.python_implementation()}"

    if skipper:
        what = "metacov" if metacov else "tests"
        return f"Skipping {what} {label_for_core(core)}: {skipper}"
    else:
        return ""


def make_env_id(core):
    """An environment id that will keep all the test runs distinct."""
    impl = platform.python_implementation().lower()
    version = "{}{}".format(*sys.version_info[:2])
    if PYPY:
        version += "_{}{}".format(*sys.pypy_version_info[:2])
    env_id = f"{impl}{version}_{core}"
    return env_id


def run_tests(core, *runner_args):
    """The actual running of tests."""
    if "COVERAGE_TESTING" not in os.environ:
        os.environ["COVERAGE_TESTING"] = "True"
    print_banner(label_for_core(core))
    return pytest.main(list(runner_args))


def run_tests_with_coverage(core, *runner_args):
    """Run tests, but with coverage."""
    # Need to define this early enough that the first import of env.py sees it.
    os.environ["COVERAGE_TESTING"] = "True"
    os.environ["COVERAGE_PROCESS_START"] = os.path.abspath("metacov.ini")
    os.environ["COVERAGE_HOME"] = os.getcwd()
    context = os.getenv("COVERAGE_CONTEXT")
    if context:
        if context[0] == "$":
            context = os.environ[context[1:]]
        os.environ["COVERAGE_CONTEXT"] = context + "." + core

    # Create the .pth file that will let us measure coverage in subprocesses.
    # The .pth file seems to have to be alphabetically after easy-install.pth
    # or the sys.path entries aren't created right?
    # There's an entry in "make clean" to get rid of this file.
    pth_dir = sysconfig.get_path("purelib")
    pth_path = os.path.join(pth_dir, "a0_metacov.pth")
    with open(pth_path, "w", encoding="utf-8") as pth_file:
        pth_file.write("import coverage; coverage.process_startup(slug='meta')\n")

    suffix = f"{make_env_id(core)}_{platform.platform()}"
    os.environ["COVERAGE_METAFILE"] = os.path.abspath(".metacov." + suffix)

    import coverage

    cov = coverage.Coverage(config_file="metacov.ini")
    cov._warn_unimported_source = False
    cov._warn_preimported_source = False
    cov._metacov = True
    cov.start()

    try:
        # Re-import coverage to get it coverage tested!  I don't understand all
        # the mechanics here, but if I don't carry over the imported modules
        # (in covmods), then things go haywire (os is None, eventually).
        covmods = {}
        covdir = os.path.split(coverage.__file__)[0]
        # We have to make a list since we'll be deleting in the loop.
        modules = list(sys.modules.items())
        for name, mod in modules:
            if name.startswith("coverage"):
                if getattr(mod, "__file__", "??").startswith(covdir):
                    covmods[name] = mod
                    del sys.modules[name]

        import coverage  # pylint: disable=reimported

        sys.modules.update(covmods)

        # Run tests, with the arguments from our command line.
        status = run_tests(core, *runner_args)

    finally:
        cov.stop()
        os.remove(pth_path)

    cov.save()
    return status


def do_combine_html():
    """Combine data from a meta-coverage run, and make the HTML report."""
    import coverage

    os.environ["COVERAGE_HOME"] = os.getcwd()
    cov = coverage.Coverage(config_file="metacov.ini")
    cov.load()
    cov.combine()
    cov.save()
    # A new Coverage to turn on messages. Better would be to have tighter
    # control over message verbosity...
    cov = coverage.Coverage(config_file="metacov.ini", messages=True)
    cov.load()
    show_contexts = bool(
        os.getenv("COVERAGE_DYNCTX") or os.getenv("COVERAGE_CONTEXT"),
    )
    total = cov.html_report(show_contexts=show_contexts)
    print(f"Total: {total:.3f}%")


def do_test_with_core(core, *runner_args):
    """Run tests with a particular core."""
    metacov = os.getenv("COVERAGE_COVERAGE", "no") == "yes"

    # If we should skip these tests, skip them.
    skip_msg = should_skip(core, metacov)
    if skip_msg:
        if VERBOSITY > 0:
            print(skip_msg)
        return None

    os.environ["COVERAGE_CORE"] = core
    if metacov:
        return run_tests_with_coverage(core, *runner_args)
    else:
        return run_tests(core, *runner_args)


def do_zip_mods():
    """Build the zip files needed for tests."""
    with zipfile.ZipFile("tests/zipmods.zip", "w") as zf:
        # Take some files from disk.
        zf.write("tests/covmodzip1.py", "covmodzip1.py")

        # The others will be various encodings.
        source = textwrap.dedent(
            """\
            # coding: {encoding}
            text = u"{text}"
            ords = {ords}
            assert [ord(c) for c in text] == ords
            print(u"All OK with {encoding}")
            encoding = "{encoding}"
            """,
        )
        # These encodings should match the list in tests/test_python.py
        details = [
            ("utf-8", "ⓗⓔⓛⓛⓞ, ⓦⓞⓡⓛⓓ"),
            ("gb2312", "你好，世界"),
            ("hebrew", "שלום, עולם"),
            ("shift_jis", "こんにちは世界"),
            ("cp1252", "“hi”"),
        ]
        for encoding, text in details:
            filename = f"encoded_{encoding}.py"
            ords = [ord(c) for c in text]
            source_text = source.format(encoding=encoding, text=text, ords=ords)
            zf.writestr(filename, source_text.encode(encoding))

    with zipfile.ZipFile("tests/zip1.zip", "w") as zf:
        zf.write("tests/zipsrc/zip1/__init__.py", "zip1/__init__.py")
        zf.write("tests/zipsrc/zip1/zip1.py", "zip1/zip1.py")

    with zipfile.ZipFile("tests/covmain.zip", "w") as zf:
        zf.write("coverage/__main__.py", "__main__.py")


def print_banner(label):
    """Print the version of Python."""
    impl = platform.python_implementation()
    version = platform.python_version()
    has_gil = getattr(sys, "_is_gil_enabled", lambda: True)()
    if not has_gil:
        version += "t"
    if PYPY:
        version += " (pypy %s)" % ".".join(str(v) for v in sys.pypy_version_info)
    version += f" ({' '.join(platform.python_build())})"
    version += " (gil)" if has_gil else " (nogil)"

    print(f"=== {impl} {version} {label} ({sys.base_prefix}) ===", flush=True)


def do_quietly(command):
    """Run a command in a shell, and suppress all output."""
    proc = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode


def get_release_facts():
    """Return an object with facts about the current release."""
    import coverage
    import coverage.version

    facts = types.SimpleNamespace()
    facts.ver = coverage.__version__
    mjr, mnr, mcr, rel, ser = facts.vi = coverage.version_info
    facts.dev = coverage.version._dev
    facts.shortver = f"{mjr}.{mnr}.{mcr}"
    facts.anchor = facts.shortver.replace(".", "-")
    if rel == "final":
        facts.next_vi = (mjr, mnr, mcr + 1, "alpha", 0)
    else:
        facts.anchor += f"{rel[0]}{ser}"
        facts.next_vi = (mjr, mnr, mcr, rel, ser + 1)

    facts.now = datetime.datetime.now()
    facts.branch = subprocess.getoutput("git rev-parse --abbrev-ref @")
    facts.sha = subprocess.getoutput("git rev-parse @")
    return facts


def update_file(fname, pattern, replacement):
    """Update the contents of a file, replacing pattern with replacement."""
    with open(fname, encoding="utf-8") as fobj:
        old_text = fobj.read()

    new_text = re.sub(pattern, replacement, old_text, count=1)

    if new_text != old_text:
        print(f"Updating {fname}")
        with open(fname, "w", encoding="utf-8") as fobj:
            fobj.write(new_text)


UNRELEASED = "Unreleased\n----------"
RELEASES_START = ".. start-releases\n\n"


def do_edit_for_release():
    """Edit a few files in preparation for a release."""
    facts = get_release_facts()

    if facts.dev:
        print(f"**\n** This is a dev release: {facts.ver}\n**\n\nNo edits")
        return

    # NOTICE.txt
    update_file(
        "NOTICE.txt",
        r"Copyright 2004.*? Ned",
        f"Copyright 2004-{facts.now:%Y} Ned",
    )

    # CHANGES.rst
    title = f"Version {facts.ver} — {facts.now:%Y-%m-%d}"
    rule = "-" * len(title)
    new_head = f".. _changes_{facts.anchor}:\n\n{title}\n{rule}"

    update_file("CHANGES.rst", re.escape(RELEASES_START), "")
    update_file("CHANGES.rst", re.escape(UNRELEASED), RELEASES_START + new_head)

    # doc/conf.py
    new_conf = textwrap.dedent(
        f"""\
        # @@@ editable
        copyright = "2009\N{EN DASH}{facts.now:%Y}, Ned Batchelder"  # pylint: disable=redefined-builtin
        # The short X.Y.Z version.
        version = "{facts.shortver}"
        # The full version, including alpha/beta/rc tags.
        release = "{facts.ver}"
        # The date of release, in "monthname day, year" format.
        release_date = "{facts.now:%B %-d, %Y}"
        # @@@ end
        """,
    )
    update_file("doc/conf.py", r"(?s)# @@@ editable\n.*# @@@ end\n", new_conf)


def do_release_version():
    """Set the version to 'final' for a release."""
    facts = get_release_facts()
    rel_vi = facts.vi[:3] + ("final", 0)
    rel_version = f"version_info = {rel_vi}\n_dev = 0".replace("'", '"')
    update_file(
        "coverage/version.py",
        r"(?m)^version_info = .*\n_dev = \d+$",
        rel_version,
    )


def do_bump_version():
    """Edit a few files right after a release to bump the version."""
    facts = get_release_facts()

    # CHANGES.rst
    update_file(
        "CHANGES.rst",
        re.escape(RELEASES_START),
        f"{UNRELEASED}\n\nNothing yet.\n\n\n" + RELEASES_START,
    )

    # coverage/version.py
    next_version = f"version_info = {facts.next_vi}\n_dev = 1".replace("'", '"')
    update_file(
        "coverage/version.py",
        r"(?m)^version_info = .*\n_dev = \d+$",
        next_version,
    )


def do_cheats():
    """Show a cheatsheet of useful things during releasing."""
    facts = get_release_facts()
    pprint.pprint(facts.__dict__)
    print()
    print(f"Coverage version is {facts.ver}")

    repo = "coveragepy/coveragepy"
    github = f"https://github.com/{repo}"
    print(
        f"https://coverage.readthedocs.io/en/{facts.ver}/changes.html#changes-{facts.anchor}",
    )

    print(
        "\n## For GitHub commenting:\n"
        + "This is now released as part of "
        + f"[coverage {facts.ver}](https://pypi.org/project/coverage/{facts.ver}).",
    )

    print("\n## To install this code:")
    if facts.branch == "main":
        print(f"python3 -m pip install git+{github}")
    else:
        print(f"python3 -m pip install git+{github}@{facts.branch}")
    print(f"python3 -m pip install git+{github}@{facts.sha[:20]}")

    print("\n## To read this code on GitHub:")
    print(f"https://github.com/coveragepy/coveragepy/commit/{facts.sha}")
    print(f"https://github.com/coveragepy/coveragepy/commits/{facts.sha}")
    print(f"https://github.com/coveragepy/coveragepy/tree/{facts.branch}")

    print(
        "\n## For other collaborators to get this code:\n"
        + f"git clone {github}\n"
        + f"cd {repo.partition('/')[-1]}\n"
        + f"git checkout {facts.sha}",
    )


def do_copy_with_hash(*args):
    """Copy files with a cache-busting hash.  Used in tests/gold/html/Makefile."""
    from coverage.html import copy_with_cache_bust

    *srcs, dest_dir = args
    for src in srcs:
        copy_with_cache_bust(src, dest_dir)


def do_help():
    """List the available commands"""
    items = list(globals().items())
    items.sort()
    for name, value in items:
        if name.startswith("do_"):
            print(f"{name[3:]:<20}{value.__doc__}")


def analyze_args(function):
    """What kind of args does `function` expect?

    Returns:
        star, num_pos:
            star(boolean): Does `function` accept *args?
            num_args(int): How many positional arguments does `function` have?
    """
    argspec = inspect.getfullargspec(function)
    return bool(argspec.varargs), len(argspec.args)


def main(args):
    """Main command-line execution for igor.

    Verbs are taken from the command line, and extra words taken as directed
    by the arguments needed by the handler.

    """
    while args:
        verb = args.pop(0)
        handler = globals().get("do_" + verb)
        if handler is None:
            print(f"*** No handler for {verb!r}")
            return 1
        star, num_args = analyze_args(handler)
        if star:
            # Handler has *args, give it all the rest of the command line.
            handler_args = args
            args = []
        else:
            # Handler has specific arguments, give it only what it needs.
            handler_args = args[:num_args]
            args = args[num_args:]
        ret = handler(*handler_args)
        # If a handler returns a failure-like value, stop.
        if ret:
            return ret
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
