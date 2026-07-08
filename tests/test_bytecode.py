# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for coverage.py's bytecode analysis."""

from __future__ import annotations

import dis
import importlib
import inspect

from collections.abc import Iterable
from textwrap import dedent
from types import CodeType

import pytest

from tests.coveragetest import CoverageTest

from coverage import env
from coverage.bytecode import (
    ALWAYS_JUMPS,
    JUMPS,
    RETURNS,
    BranchArcResolver,
    ByteParser,
    bytes_to_lines,
    op_set,
)
from coverage.types import TArc, TLineNo, TOffset


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


def compile_module(text: str) -> CodeType:
    """Compile `text` as a module, returning its code object."""
    return compile(dedent(text), "<test>", "exec", dont_inherit=True)


def function_code(text: str, name: str = "f") -> CodeType:
    """Compile `text` and return the code object of the function named `name`."""
    for code in ByteParser(code=compile_module(text)).code_objects():
        if code.co_name == name:
            return code
    raise AssertionError(f"No function {name!r} in {text!r}")


def conditional_jumps(code: CodeType) -> list[tuple[TOffset, TOffset, TOffset]]:
    """Find the conditional jumps in `code`.

    Returns a list of (source, taken_dest, fallthrough_dest) offset triples,
    one per conditional jump instruction.  These are the (source, dest) pairs
    that BRANCH_LEFT/BRANCH_RIGHT events would deliver for the branch.
    """
    insts = list(dis.get_instructions(code))
    return [
        (inst.offset, inst.argval, insts[i + 1].offset)
        for i, inst in enumerate(insts)
        if inst.opcode in JUMPS and inst.opcode not in ALWAYS_JUMPS
    ]


def branches_on_line(code: CodeType, line: TLineNo) -> list[tuple[TOffset, TOffset, TOffset]]:
    """The conditional jumps in `code` whose source is on `line`."""
    b2l = bytes_to_lines(code)
    found = [triple for triple in conditional_jumps(code) if b2l[triple[0]] == line]
    assert found, f"No conditional jump on line {line}"
    return found


def make_resolver(
    code: CodeType,
    multiline_map: dict[TLineNo, TLineNo] | None = None,
) -> BranchArcResolver:
    """Make a BranchArcResolver for `code`, as the sysmon core would."""
    return BranchArcResolver(code, bytes_to_lines(code), multiline_map or {})


@pytest.mark.skipif(
    not env.PYBEHAVIOR.branch_right_left,
    reason="BranchArcResolver is only used for sys.monitoring branch coverage (3.14+). "
    + "Its opcode sets don't cover earlier bytecode (3.12/3.13 RETURN_CONST, for example).",
)
class BranchArcResolverTest(CoverageTest):
    """Directed tests of BranchArcResolver.resolve()."""

    run_in_temp_dir = False

    def test_if_else(self) -> None:
        code = function_code("""\
            def f(x):
                if x:
                    y = 3
                else:
                    y = 5
                return y
            """)
        resolver = make_resolver(code)
        [(source, taken, fallthrough)] = branches_on_line(code, 2)
        assert resolver.resolve(source, fallthrough) == (2, 3)
        assert resolver.resolve(source, taken) == (2, 5)

    def test_arc_to_exit(self) -> None:
        code = function_code("""\
            def f(x):
                while x:
                    x -= 1
            """)
        resolver = make_resolver(code)
        # The while-loop tests on line 2 (there can be more than one) each
        # branch to the loop body, or leave the function.
        arcs = {
            resolver.resolve(source, dest)
            for source, taken, fallthrough in branches_on_line(code, 2)
            for dest in (taken, fallthrough)
        }
        assert arcs == {(2, 3), (2, -1)}

    def test_same_line_body_follows_forward_jump(self) -> None:
        code = function_code("""\
            def f(x):
                if x: y = 3
                else: y = 5
                return y
            """)
        resolver = make_resolver(code)
        [(source, taken, fallthrough)] = branches_on_line(code, 2)
        # The if-body is on the same line as the branch, so the trail
        # continues through it, follows the jump over the else-clause, and
        # stops on the return line.
        assert resolver.resolve(source, fallthrough) == (2, 4)
        assert resolver.resolve(source, taken) == (2, 3)

    def test_trail_stops_at_another_branch(self) -> None:
        code = function_code("""\
            def f(x, y):
                if x and y:
                    z = 3
                return z
            """)
        resolver = make_resolver(code)
        # The `x` test's true-branch falls into the `y` test on the same
        # line: no arc, the second branch will produce its own events.
        source, taken, fallthrough = branches_on_line(code, 2)[0]
        assert resolver.resolve(source, fallthrough) is None
        assert resolver.resolve(source, taken) == (2, 4)

    def test_backward_jump_to_loop_head(self) -> None:
        code = function_code("""\
            def f(n):
                total = 0
                for i in range(n):
                    if i:
                        total += i
                return total
            """)
        resolver = make_resolver(code)
        [(source, taken, fallthrough)] = branches_on_line(code, 4)
        # Whether the compiler jumps on true or on false, one destination
        # leads into the body, and the other follows the loop's backward
        # jump to the `for` line.
        arcs = {resolver.resolve(source, dest) for dest in (taken, fallthrough)}
        assert arcs == {(4, 3), (4, 5)}

    def test_extended_arg_jump(self) -> None:
        # A jump over more than 255 instruction units needs an EXTENDED_ARG
        # prefix, which the resolver has to accumulate while walking, both
        # to skip it and to compute the jump's target.
        lines = ["def f(n):", "    total = 0", "    for i in range(n):"]
        lines.extend(f"        total += {i}" for i in range(300))
        lines.append("        if total > 999999: total = 0")
        lines.append("    return total")
        code = function_code("\n".join(lines) + "\n")
        # Make sure the loop is big enough that its backward jumps need
        # EXTENDED_ARG.
        jump_args = [
            inst.arg
            for inst in dis.get_instructions(code)
            if inst.opcode in ALWAYS_JUMPS and inst.arg is not None
        ]
        assert max(jump_args) > 255
        resolver = make_resolver(code)
        if_line = len(lines) - 1
        [(source, taken, fallthrough)] = branches_on_line(code, if_line)
        # Both destinations of the `if` at the bottom of the loop lead to the
        # backward jump, whose extended arg must be read to land on the `for`
        # line, and not somewhere in the middle of the loop body.
        arcs = {resolver.resolve(source, dest) for dest in (taken, fallthrough)}
        assert arcs == {(if_line, 3)}

    def test_multiline_condition_is_attributed_to_first_line(self) -> None:
        source_text = """\
            def f(a, b):
                if (a and
                        b):
                    y = 4
                return y
            """
        code = function_code(source_text)
        # The `b` test is on line 3, but the statement starts on line 2.
        [(source, taken, fallthrough)] = branches_on_line(code, 3)
        resolver = make_resolver(code, multiline_map={2: 2, 3: 2})
        assert resolver.resolve(source, taken) == (2, 5)
        assert resolver.resolve(source, fallthrough) == (2, 4)
        # Without the multiline map, the arcs would come from line 3.
        raw_resolver = make_resolver(code)
        assert raw_resolver.resolve(source, taken) == (3, 5)

    def test_infinite_loop_terminates(self) -> None:
        code = function_code("""\
            def f():
                while True: pass
            """)
        resolver = make_resolver(code)
        jump_offsets = [
            inst.offset for inst in dis.get_instructions(code) if inst.opcode in ALWAYS_JUMPS
        ]
        assert jump_offsets, "No unconditional jump in an infinite loop?"
        # Every instruction in the loop is on line 2, so a trail from inside
        # the loop cycles without finding an arc, and must terminate.
        assert resolver.resolve(jump_offsets[0], jump_offsets[0]) is None

    def test_unknown_source_offset(self) -> None:
        code = function_code("""\
            def f(x):
                if x:
                    y = 3
                return y
            """)
        resolver = BranchArcResolver(code, {}, {})
        assert resolver.resolve(0, 0) is None


class InstructionWalker:
    """A dis-based reference walker, following jump trails through code.

    This is the InstructionWalker that coverage's sysmon core used before
    BranchArcResolver, kept here as an independent reference implementation.
    """

    def __init__(self, code: CodeType) -> None:
        self.code = code
        self.insts: dict[TOffset, dis.Instruction] = {}
        inst = None
        for inst in dis.get_instructions(code):
            self.insts[inst.offset] = inst
        assert inst is not None
        self.max_offset = inst.offset

    def walk(self, *, start_at: TOffset = 0) -> Iterable[dis.Instruction]:
        """Yield instructions from `start_at`, following unconditional jumps."""
        seen = set()
        offset = start_at
        while offset < self.max_offset + 1:
            if offset in seen:
                break
            seen.add(offset)
            if inst := self.insts.get(offset):
                yield inst
                if inst.opcode in ALWAYS_JUMPS:
                    offset = inst.jump_target
                    continue
            offset += 2


def resolve_with_dis(
    code: CodeType,
    walker: InstructionWalker,
    multiline_map: dict[TLineNo, TLineNo],
    source: TOffset,
    dest: TOffset,
) -> TArc | None:
    """A reference implementation of BranchArcResolver.resolve().

    Implements the same trail-walking semantics, but from dis Instructions
    instead of raw bytecode bytes, so that dis computes lines, jump targets,
    and inline cache handling for us.
    """
    inst = walker.insts.get(source)
    from_line = inst.line_number if inst is not None else None
    if from_line is None:
        return None
    from_line = multiline_map.get(from_line, from_line)
    for inst in walker.walk(start_at=dest):
        line = inst.line_number
        if line is not None:
            line = multiline_map.get(line, line)
        if line and line != from_line:
            return (from_line, line)
        if inst.opcode in JUMPS and inst.opcode not in ALWAYS_JUMPS:
            return None
        if inst.opcode in RETURNS:
            return (from_line, -code.co_firstlineno)
    return None


# Snippets guaranteeing branch shapes the stdlib corpus below might not
# contain: match/case, async constructs, except*, and EXTENDED_ARG jumps.
AGREEMENT_SNIPPETS = [
    """\
    def f(command):
        match command.split():
            case ["go", direction] if direction in "nsew":
                return direction
            case ["go", *rest]:
                return rest
            case {"action": action}:
                return action
            case [1, 2, *_] | (3, 4):
                return "numbers"
            case _:
                return None
    """,
    """\
    def gen(n):
        for i in range(n):
            if i % 3:
                yield i
            else:
                yield from range(i)

    async def agen(source):
        async with source as src:
            async for item in src:
                if item:
                    await item
    """,
    """\
    def f(x):
        try:
            g()
        except* ValueError:
            x += 1
        except* TypeError:
            x += 2
        assert x > 0, "positive"
        with open("name") as fobj:
            for line in fobj:
                if line.strip():
                    return line
    """,
    # A function big enough to need EXTENDED_ARG jumps.
    "def f(x):\n    if x:\n        y = 1\n    else:\n"
    + "".join(f"        y = {i}\n" for i in range(300))
    + "    return y\n",
]

# Real stdlib modules as an agreement corpus: hundreds of code objects with
# compiler output shapes no hand-written snippet anticipates.  The dis-based
# reference computes the expected arc for each branch, so the test needs no
# per-module (or per-version) knowledge of what's in them.
STDLIB_CORPUS = ["argparse", "dataclasses"]


@pytest.mark.skipif(
    env.PYVERSION < (3, 13),
    reason="The reference implementation needs Instruction.line_number and .jump_target",
)
class BranchArcResolverAgreementTest(CoverageTest):
    """BranchArcResolver agrees with a dis-based reference on both dests of
    every conditional jump in a corpus of compiled code."""

    run_in_temp_dir = False

    def check_all_branches(self, module_code: CodeType, context: str) -> int:
        """Check resolver-vs-reference agreement on every conditional jump.

        Returns the number of (source, dest) pairs checked.
        """
        checked = 0
        for code in ByteParser(code=module_code).code_objects():
            resolver = make_resolver(code)
            walker = InstructionWalker(code)
            for source, taken, fallthrough in conditional_jumps(code):
                for dest in (taken, fallthrough):
                    expected = resolve_with_dis(code, walker, {}, source, dest)
                    actual = resolver.resolve(source, dest)
                    assert actual == expected, (
                        f"resolve({source}, {dest}) in {context}:{code.co_qualname}: "
                        + f"{actual} != {expected}"
                    )
                    checked += 1
        return checked

    @pytest.mark.parametrize("snippet", AGREEMENT_SNIPPETS)
    def test_agrees_with_dis(self, snippet: str) -> None:
        checked = self.check_all_branches(compile_module(snippet), "snippet")
        assert checked >= 2, "Each snippet should contain branches to check"

    @pytest.mark.parametrize("modname", STDLIB_CORPUS)
    def test_agrees_with_dis_on_stdlib(self, modname: str) -> None:
        source = inspect.getsource(importlib.import_module(modname))
        module_code = compile(source, f"<{modname}>", "exec", dont_inherit=True)
        checked = self.check_all_branches(module_code, modname)
        assert checked > 200, "A stdlib module should have hundreds of branch pairs"
