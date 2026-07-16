# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Determine contexts for coverage.py"""

from __future__ import annotations

import inspect

from collections.abc import Sequence
from types import FrameType

from coverage.types import TShouldStartContextFn


def combine_context_switchers(
    context_switchers: Sequence[TShouldStartContextFn],
) -> TShouldStartContextFn | None:
    """Create a single context switcher from multiple switchers.

    `context_switchers` is a list of functions that take a frame as an
    argument and return a string to use as the new context label.

    Returns a function that composites `context_switchers` functions, or None
    if `context_switchers` is an empty list.

    When invoked, the combined switcher calls `context_switchers` one-by-one
    until a string is returned.  The combined switcher returns None if all
    `context_switchers` return None.
    """
    if not context_switchers:
        return None

    if len(context_switchers) == 1:
        return context_switchers[0]

    def should_start_context(frame: FrameType) -> str | None:
        """The combiner for multiple context switchers."""
        for switcher in context_switchers:
            new_context = switcher(frame)
            if new_context is not None:
                return new_context
        return None

    return should_start_context


def should_start_context_test_function(frame: FrameType) -> str | None:
    """Is this frame calling a test_* function?"""
    co_name = frame.f_code.co_name
    if co_name.startswith("test") or co_name == "runTest":
        return qualname_from_frame(frame)
    return None


def qualname_from_frame(frame: FrameType) -> str | None:
    """Get a qualified name for the code running in `frame`."""
    co = frame.f_code
    fname = co.co_name
    method = None
    if co.co_argcount and co.co_varnames[0] in ("self", "cls"):
        first_arg = frame.f_locals.get(co.co_varnames[0], None)
        method = getattr(first_arg, fname, None)

    if method is None:
        func = frame.f_globals.get(fname)
        if func is None:
            # `frame` might be a plain function or a static method, neither of
            # which will be found in f_globals if they are nested inside a
            # class (or another function).  Code objects for functions are
            # marked as "optimized" (they use fast locals), while code
            # objects for module and class bodies are not.  Use that to tell
            # a genuine (but unreachable-by-name) function apart from a
            # class body executing a function-like statement, which is the
            # case `test_bug_829` guards against.
            if co.co_flags & inspect.CO_OPTIMIZED:
                module = frame.f_globals.get("__name__", "")
                qualname = co.co_qualname if hasattr(co, "co_qualname") else fname
                return f"{module}.{qualname}" if module else qualname
            return None
        return f"{func.__module__}.{fname}"

    func = getattr(method, "__func__", None)
    if func is None:
        cls = first_arg if isinstance(first_arg, type) else first_arg.__class__
        return f"{cls.__module__}.{cls.__name__}.{fname}"

    return f"{func.__module__}.{func.__qualname__}"
