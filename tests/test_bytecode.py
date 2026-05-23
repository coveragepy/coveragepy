# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for coverage.py's bytecode analysis."""

from __future__ import annotations

import dis

from textwrap import dedent

from tests.coveragetest import CoverageTest

from coverage import env
from coverage.bytecode import ByteParser, op_set


class BytecodeTest(CoverageTest):
    """Tests for bytecode.py"""

    def test_code_objects(self) -> None:
        bp = ByteParser(
            text=dedent("""\
                def f(x):
                    def g(y):
                        return {z for z in range(10)}
                    def j():
                        return [z for z in range(10)]
                    return g(x)
                def h(x):
                    return x+1
                """),
        )

        objs = list(bp.code_objects())

        expected = {"<module>", "f", "g", "j", "h"}
        if env.PYVERSION < (3, 12):
            # Comprehensions were compiled as implicit functions in earlier
            # versions of Python.
            expected.update({"<setcomp>", "<listcomp>"})
        assert {c.co_name for c in objs} == expected

    def test_op_set(self) -> None:
        opcodes = op_set("LOAD_CONST", "NON_EXISTENT_OPCODE", "RETURN_VALUE")
        assert opcodes == {dis.opmap["LOAD_CONST"], dis.opmap["RETURN_VALUE"]}
