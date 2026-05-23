# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""
Dump the contents of a .pyc file.

The output will only be correct if run with the same version of Python that
produced the .pyc.

"""

import binascii
import dis
import marshal
import struct
import sys
import time
import types
import warnings


def show_pyc_file(fname):
    f = open(fname, "rb")
    magic = f.read(4)
    print("magic %s" % (binascii.hexlify(magic)))
    read_date_and_size = True
    flags = struct.unpack("<L", f.read(4))[0]
    hash_based = bool(flags & 0x01)
    check_source = bool(flags & 0x02)
    print(f"flags {flags:#08x}")
    if hash_based:
        source_hash = f.read(8)
        read_date_and_size = False
        print(f"hash {binascii.hexlify(source_hash)}")
        print(f"check_source {check_source}")
    if read_date_and_size:
        moddate = f.read(4)
        modtime = time.asctime(time.localtime(struct.unpack("<L", moddate)[0]))
        print(f"moddate {binascii.hexlify(moddate)} ({modtime})")
        size = f.read(4)
        print("pysize %s (%d)" % (binascii.hexlify(size), struct.unpack("<L", size)[0]))
    code = marshal.load(f)
    show_code(code)


def show_py_file(fname):
    text = open(fname, encoding="utf-8").read().replace("\r\n", "\n")
    show_py_text(text, fname=fname)


def show_py_text(text, fname="<string>"):
    code = compile(text, fname, "exec", dont_inherit=True)
    show_code(code)


# fmt:off
CO_FLAGS = [
    ('CO_OPTIMIZED',                0x00001),
    ('CO_NEWLOCALS',                0x00002),
    ('CO_VARARGS',                  0x00004),
    ('CO_VARKEYWORDS',              0x00008),
    ('CO_NESTED',                   0x00010),
    ('CO_GENERATOR',                0x00020),
    ('CO_NOFREE',                   0x00040),
    ('CO_COROUTINE',                0x00080),
    ('CO_ITERABLE_COROUTINE',       0x00100),
    ('CO_ASYNC_GENERATOR',          0x00200),
    ('CO_GENERATOR_ALLOWED',        0x01000),
]

if sys.version_info < (3, 9):
    CO_FLAGS += [
        ('CO_FUTURE_DIVISION',          0x02000),
        ('CO_FUTURE_ABSOLUTE_IMPORT',   0x04000),
        ('CO_FUTURE_WITH_STATEMENT',    0x08000),
        ('CO_FUTURE_PRINT_FUNCTION',    0x10000),
        ('CO_FUTURE_UNICODE_LITERALS',  0x20000),
        ('CO_FUTURE_BARRY_AS_BDFL',     0x40000),
        ('CO_FUTURE_GENERATOR_STOP',    0x80000),
    ]
else:
    CO_FLAGS += [
        ('CO_FUTURE_DIVISION',          0x0020000),
        ('CO_FUTURE_ABSOLUTE_IMPORT',   0x0040000),
        ('CO_FUTURE_WITH_STATEMENT',    0x0080000),
        ('CO_FUTURE_PRINT_FUNCTION',    0x0100000),
        ('CO_FUTURE_UNICODE_LITERALS',  0x0200000),
        ('CO_FUTURE_BARRY_AS_BDFL',     0x0400000),
        ('CO_FUTURE_GENERATOR_STOP',    0x0800000),
        ('CO_FUTURE_ANNOTATIONS',       0x1000000),
    ]

if sys.version_info >= (3, 14):
    CO_FLAGS += [
        ('CO_NO_MONITORING_EVENTS',     0x2000000),
    ]
# fmt: on


def show_code(code, indent="", number=None):
    label = ""
    if number is not None:
        label = "%d: " % number
    print(f"{indent}{label}code")
    indent += "    "
    print(f"{indent}name {code.co_name!r}")
    print("%sargcount %d" % (indent, code.co_argcount))
    print("%snlocals %d" % (indent, code.co_nlocals))
    print("%sstacksize %d" % (indent, code.co_stacksize))
    print(f"{indent}flags {code.co_flags:04x}: {flag_words(code.co_flags, CO_FLAGS)}")
    show_hex("code", code.co_code, indent=indent)
    kwargs = {}
    if sys.version_info >= (3, 13):
        kwargs["show_offsets"] = True
    if sys.version_info >= (3, 14):
        kwargs["show_positions"] = True
    dis.disassemble(code, **kwargs)
    print("%sconsts" % indent)
    for i, const in enumerate(code.co_consts):
        if type(const) == types.CodeType:
            show_code(const, indent + "    ", number=i)
        else:
            print("    %s%d: %r" % (indent, i, const))
    print(f"{indent}names {code.co_names!r}")
    print(f"{indent}varnames {code.co_varnames!r}")
    print(f"{indent}freevars {code.co_freevars!r}")
    print(f"{indent}cellvars {code.co_cellvars!r}")
    print(f"{indent}filename {code.co_filename!r}")
    print("%sfirstlineno %d" % (indent, code.co_firstlineno))
    show_hex("lnotab", code.co_lnotab, indent=indent)
    print(
        "    {}{}".format(
            indent, ", ".join(f"{line!r}:{byte!r}" for byte, line in lnotab_interpreted(code))
        )
    )
    if hasattr(code, "co_linetable"):
        show_hex("linetable", code.co_linetable, indent=indent)
    if hasattr(code, "co_lines"):
        print(
            "    {}co_lines {}".format(
                indent,
                ", ".join(f"{line!r}:{start!r}-{end!r}" for start, end, line in code.co_lines()),
            )
        )
    if hasattr(code, "co_branches"):
        print(
            "    {}co_branches {}".format(
                indent,
                ", ".join(
                    f"{start!r}:{taken!r}/{nottaken!r}"
                    for start, taken, nottaken in code.co_branches()
                ),
            )
        )


def show_hex(label, h, indent):
    h = binascii.hexlify(h)
    if len(h) < 60:
        print("{}{} {}".format(indent, label, h.decode("ascii")))
    else:
        print(f"{indent}{label}")
        for i in range(0, len(h), 60):
            print("{}   {}".format(indent, h[i : i + 60].decode("ascii")))


def lnotab_interpreted(code):
    # Adapted from dis.py in the standard library.
    byte_increments = code.co_lnotab[0::2]
    line_increments = code.co_lnotab[1::2]

    last_line_num = None
    line_num = code.co_firstlineno
    byte_num = 0
    for byte_incr, line_incr in zip(byte_increments, line_increments):
        if byte_incr:
            if line_num != last_line_num:
                yield (byte_num, line_num)
                last_line_num = line_num
            byte_num += byte_incr
        if line_incr >= 0x80:
            line_incr -= 0x100
        line_num += line_incr
    if line_num != last_line_num:
        yield (byte_num, line_num)


def flag_words(flags, flag_defs):
    words = []
    for word, flag in flag_defs:
        if flag & flags:
            words.append(word)
    return ", ".join(words)


def show_file(fname):
    if fname.endswith("pyc"):
        show_pyc_file(fname)
    elif fname.endswith("py"):
        show_py_file(fname)
    else:
        print("Odd file:", fname)


def main(args):
    warnings.filterwarnings(
        "ignore", "co_lnotab is deprecated, use co_lines instead", category=DeprecationWarning
    )
    if args[0] == "-c":
        show_py_text(" ".join(args[1:]).replace(";", "\n"))
    else:
        for a in args:
            show_file(a)


if __name__ == "__main__":
    main(sys.argv[1:])
