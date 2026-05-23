# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Wicked hack to get .pyc files to do bytecode tracing instead of
line tracing.
"""

import marshal, new, opcode, sys, types

from lnotab import lnotab_numbers, lnotab_string


class PycFile:
    def read(self, f):
        if isinstance(f, basestring):
            f = open(f, "rb")
        self.magic = f.read(4)
        self.modtime = f.read(4)
        self.code = marshal.load(f)

    def write(self, f):
        if isinstance(f, basestring):
            f = open(f, "wb")
        f.write(self.magic)
        f.write(self.modtime)
        marshal.dump(self.code, f)

    def hack_line_numbers(self):
        self.code = hack_line_numbers(self.code)


def hack_line_numbers(code):
    """Replace a code object's line number information to claim that every
    byte of the bytecode is a new source line.  Returns a new code
    object.  Also recurses to hack the line numbers in nested code objects.
    """

    # Create a new lnotab table.  Each opcode is claimed to be at
    # 1000*lineno + (opcode number within line), so for example, the opcodes on
    # source line 12 will be given new line numbers 12000, 12001, 12002, etc.
    old_num = list(lnotab_numbers(code.co_lnotab, code.co_firstlineno))
    n_bytes = len(code.co_code)
    new_num = []
    line = 0
    opnum_in_line = 0
    i_byte = 0
    while i_byte < n_bytes:
        if old_num and i_byte == old_num[0][0]:
            line = old_num.pop(0)[1]
            opnum_in_line = 0
        new_num.append((i_byte, 100000000 + 1000 * line + opnum_in_line))
        if ord(code.co_code[i_byte]) >= opcode.HAVE_ARGUMENT:
            i_byte += 3
        else:
            i_byte += 1
        opnum_in_line += 1

    # new_num is a list of pairs, (byteoff, lineoff).  Turn it into an lnotab.
    new_firstlineno = new_num[0][1] - 1
    new_lnotab = lnotab_string(new_num, new_firstlineno)

    # Recurse into code constants in this code object.
    new_consts = []
    for const in code.co_consts:
        if type(const) == types.CodeType:
            new_consts.append(hack_line_numbers(const))
        else:
            new_consts.append(const)

    # Create a new code object, just like the old one, except with new
    # line numbers.
    new_code = new.code(
        code.co_argcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
        code.co_code,
        tuple(new_consts),
        code.co_names,
        code.co_varnames,
        code.co_filename,
        code.co_name,
        new_firstlineno,
        new_lnotab,
    )

    return new_code


def hack_file(f):
    pyc = PycFile()
    pyc.read(f)
    pyc.hack_line_numbers()
    pyc.write(f)


if __name__ == "__main__":
    hack_file(sys.argv[1])
