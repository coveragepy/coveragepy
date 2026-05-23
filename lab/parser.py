# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Parser.py: a main for invoking code in coverage/parser.py"""

import collections
import dis
import glob
import optparse
import os
import re
import sys
import textwrap
import types

from coverage.parser import PythonParser
from coverage.python import get_python_source


class ParserMain:
    """A main for code parsing experiments."""

    def main(self, args):
        """A main function for trying the code from the command line."""

        parser = optparse.OptionParser()
        parser.add_option("-d", action="store_true", dest="dis", help="Disassemble")
        parser.add_option(
            "-R", action="store_true", dest="recursive", help="Recurse to find source files"
        )
        parser.add_option("-q", action="store_true", dest="quiet", help="Suppress output")
        parser.add_option("-s", action="store_true", dest="source", help="Show analyzed source")
        parser.add_option("-t", action="store_true", dest="tokens", help="Show tokens")

        options, args = parser.parse_args()
        if options.recursive:
            if args:
                root = args[0]
            else:
                root = "."
            for root, _, _ in os.walk(root):
                for f in glob.glob(root + "/*.py"):
                    if not options.quiet:
                        print(f"Parsing {f}")
                    self.one_file(options, f)
        elif not args:
            parser.print_help()
        else:
            self.one_file(options, args[0])

    def one_file(self, options, filename):
        """Process just one file."""
        # `filename` can have a line number suffix. In that case, extract those
        # lines, dedent them, and use that.  This is for trying test cases
        # embedded in the test files.
        if match := re.search(r"^(.*):(\d+)-(\d+)$", filename):
            filename, start, end = match.groups()
            start, end = int(start), int(end)
        else:
            start = end = None

        try:
            text = get_python_source(filename)
            if start is not None:
                lines = text.splitlines(True)
                text = textwrap.dedent("".join(lines[start - 1 : end]).replace("\\\\", "\\"))
            pyparser = PythonParser(text, filename=filename, exclude=r"no\s*cover")
            pyparser.parse_source()
        except Exception as err:
            print(f"{err}")
            return

        if options.dis:
            print("Main code:")
            disassemble(pyparser.text)

        arcs = pyparser.arcs()

        if options.source or options.tokens:
            pyparser.show_tokens = options.tokens
            pyparser.parse_source()

            if options.source:
                arc_chars = self.arc_ascii_art(arcs)
                if arc_chars:
                    arc_width = max(len(a) for a in arc_chars.values())

                exit_counts = pyparser.exit_counts()

                for lineno, ltext in enumerate(pyparser.text.splitlines(), start=1):
                    marks = [" "] * 6
                    a = " "
                    if lineno in pyparser.raw_statements:
                        marks[0] = "-"
                    if lineno in pyparser.statements:
                        marks[1] = "="
                    exits = exit_counts.get(lineno, 0)
                    if exits > 1:
                        marks[2] = str(exits)
                    if lineno in pyparser.raw_docstrings:
                        marks[3] = '"'
                    if lineno in pyparser.raw_excluded:
                        marks[4] = "X"
                    elif lineno in pyparser.excluded:
                        marks[4] = "×"
                    if lineno in pyparser.multiline_map.values():
                        marks[5] = "o"
                    elif lineno in pyparser.multiline_map.keys():
                        marks[5] = "."

                    if arc_chars:
                        a = arc_chars[lineno].ljust(arc_width)
                    else:
                        a = ""

                    if not options.quiet:
                        print("%4d %s%s %s" % (lineno, "".join(marks), a, ltext))

    def arc_ascii_art(self, arcs):
        """Draw arcs as ascii art.

        Returns a dictionary mapping line numbers to ascii strings to draw for
        that line.

        """
        plus_ones = set()
        arc_chars = collections.defaultdict(str)
        for lfrom, lto in sorted(arcs):
            if lfrom < 0:
                arc_chars[lto] += "v"
            elif lto < 0:
                arc_chars[lfrom] += "^"
            else:
                if lfrom == lto - 1:
                    plus_ones.add(lfrom)
                    arc_chars[lfrom] += ""  # ensure this line is in arc_chars
                    continue
                if lfrom < lto:
                    l1, l2 = lfrom, lto
                else:
                    l1, l2 = lto, lfrom
                w = first_all_blanks(arc_chars[l] for l in range(l1, l2 + 1))
                for l in range(l1, l2 + 1):
                    if l == lfrom:
                        ch = "<"
                    elif l == lto:
                        ch = ">"
                    else:
                        ch = "|"
                    arc_chars[l] = set_char(arc_chars[l], w, ch)

        # Add the plusses as the first character
        for lineno, arcs in arc_chars.items():
            arc_chars[lineno] = ("+" if lineno in plus_ones else " ") + arcs

        return arc_chars


def all_code_objects(code):
    """Iterate over all the code objects in `code`."""
    stack = [code]
    while stack:
        # We're going to return the code object on the stack, but first
        # push its children for later returning.
        code = stack.pop()
        stack.extend(c for c in code.co_consts if isinstance(c, types.CodeType))
        yield code


def disassemble(text):
    """Disassemble code, for ad-hoc experimenting."""

    code = compile(text, "", "exec", dont_inherit=True)
    for code_obj in all_code_objects(code):
        if text:
            srclines = text.splitlines()
        else:
            srclines = None
        print("\n%s: " % code_obj)
        upto = None
        for inst in dis.get_instructions(code_obj):
            if inst.starts_line is not None:
                if srclines:
                    upto = upto or inst.starts_line - 1
                    while upto <= inst.starts_line - 1:
                        print("{:>100}{}".format("", srclines[upto]))
                        upto += 1
                elif inst.offset > 0:
                    print("")
            line = inst._disassemble()
            print(f"{line:<70}")

    print("")


def set_char(s, n, c):
    """Set the nth char of s to be c, extending s if needed."""
    s = s.ljust(n)
    return s[:n] + c + s[n + 1 :]


def blanks(s):
    """Return the set of positions where s is blank."""
    return {i for i, c in enumerate(s) if c == " "}


def first_all_blanks(ss):
    """Find the first position that is all blank in the strings ss."""
    ss = list(ss)
    blankss = blanks(ss[0])
    for s in ss[1:]:
        blankss &= blanks(s)
    if blankss:
        return min(blankss)
    else:
        return max(len(s) for s in ss)


if __name__ == "__main__":
    ParserMain().main(sys.argv[1:])
