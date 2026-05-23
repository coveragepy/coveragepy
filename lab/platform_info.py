# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Dump information so we can get a quick look at what's available."""

import platform
import sys


def whatever(f):
    try:
        return f()
    except:
        return f


def dump_module(mod):
    print(f"\n###  {mod.__name__} ---------------------------")
    for name in dir(mod):
        if name.startswith("_"):
            continue
        print(f"{name:30s}: {whatever(getattr(mod, name))!r:.100}")


for mod in [platform, sys]:
    dump_module(mod)
