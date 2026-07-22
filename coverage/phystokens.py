# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Better tokenizing for coverage.py."""

from __future__ import annotations

import ast
import io
import keyword
import sys
import token
import tokenize
from collections.abc import Iterable

from coverage import env
from coverage.types import TLineNo, TSourceTokenLines

TToken = tuple[int, str, tuple[int, int], tuple[int, int], str]
TokenInfos = Iterable[TToken]


def _phys_tokens(toks: TokenInfos) -> TokenInfos:
    """Return all physical tokens, even line continuations.

    tokenize.generate_tokens() doesn't return a token for the backslash that
    continues lines.  This wrapper provides those tokens so that we can
    re-create a faithful representation of the original source.

    Returns the same values as generate_tokens()

    """
    last_line: str | None = None
    last_lineno = -1
    last_ttext: str = ""
    for ttype, ttext, (slineno, scol), (elineno, ecol), ltext in toks:
        if last_lineno != elineno:
            if last_line and last_line.endswith("\\\n"):
                # We are at the beginning of a new line, and the last line
                # ended with a backslash.  We probably have to inject a
                # backslash token into the stream. Unfortunately, there's more
                # to figure out.  This code::
                #
                #   usage = """\
                #   HEY THERE
                #   """
                #
                # triggers this condition, but the token text is::
                #
                #   '"""\\\nHEY THERE\n"""'
                #
                # so we need to figure out if the backslash is already in the
                # string token or not.
                inject_backslash = True
                if last_ttext.endswith("\\"):
                    inject_backslash = False
                elif ttype == token.STRING:
                    if (  # pylint: disable=simplifiable-if-statement
                        last_line.endswith("\\\n")
                        and last_line.rstrip(" \\\n").endswith(last_ttext)
                    ):
                        # Deal with special cases like such code::
                        #
                        #   a = ["aaa",\ # there may be zero or more blanks between "," and "\".
                        #        "bbb \
                        #        ccc"]
                        #
                        inject_backslash = True
                    else:
                        # It's a multi-line string and the first line ends with
                        # a backslash, so we don't need to inject another.
                        inject_backslash = False
                elif env.PYBEHAVIOR.fstring_syntax and ttype == token.FSTRING_MIDDLE:
                    inject_backslash = False
                if inject_backslash:
                    # Figure out what column the backslash is in.
                    line_start = last_line.rfind("\n", 0, len(last_line) - 1) + 1
                    ccol = len(last_line) - 2 - line_start
                    # Yield the token, with a fake token type.
                    yield (99999, "\\\n", (slineno, ccol), (slineno, ccol + 2), last_line)
            last_line = ltext
        if ttype not in (tokenize.NEWLINE, tokenize.NL):
            last_ttext = ttext
        yield (ttype, ttext, (slineno, scol), (elineno, ecol), ltext)
        last_lineno = elineno


def find_soft_key_lines(source: str) -> set[TLineNo]:
    """Helper for finding lines with soft keywords, like match/case lines."""
    soft_key_lines: set[TLineNo] = set()

    for node in ast.walk(ast.parse(source)):
        # PYVERSION: we use sys.version_info here so that mypy will be ok with
        # us accessing attributes that appeared in those versions.
        if isinstance(node, ast.Match):
            soft_key_lines.add(node.lineno)
            for case in node.cases:
                soft_key_lines.add(case.pattern.lineno)
        elif sys.version_info >= (3, 12) and isinstance(node, ast.TypeAlias):
            soft_key_lines.add(node.lineno)
        elif sys.version_info >= (3, 15) and isinstance(node, (ast.Import, ast.ImportFrom)):
            if node.is_lazy:
                soft_key_lines.add(node.lineno)

    return soft_key_lines


def source_token_lines(source: str) -> TSourceTokenLines:
    """Generate a series of lines, one for each line in `source`.

    Each line is a list of pairs, each pair is a token::

        [('key', 'def'), ('ws', ' '), ('nam', 'hello'), ('op', '('), ... ]

    Each pair has a token class, and the token text.

    If you concatenate all the token texts, and then join them with newlines,
    you should have your original `source` back, with two differences:
    trailing white space is not preserved, and a final line with no newline
    is indistinguishable from a final line with a newline.

    """

    ws_tokens = {token.INDENT, token.DEDENT, token.NEWLINE, tokenize.NL}
    tok_name_get = tokenize.tok_name.get
    iskeyword = keyword.iskeyword
    issoftkeyword = keyword.issoftkeyword
    fstring_syntax = env.PYBEHAVIOR.fstring_syntax
    line: list[tuple[str, str]] = []
    col = 0

    source = source.expandtabs(8).replace("\r\n", "\n")
    tokgen = generate_tokens(source)

    soft_key_lines = find_soft_key_lines(source)

    for ttype, ttext, (sline, scol), (_, ecol), _ in _phys_tokens(tokgen):
        if "\n" not in ttext:
            if ttext and ttype not in ws_tokens:
                part = ttext
                if fstring_syntax and ttype == token.FSTRING_MIDDLE:
                    part = part.replace("{", "{{").replace("}", "}}")
                    ecol = scol + len(part)
                if scol > col:
                    line.append(("ws", " " * (scol - col)))
                tok_class = tok_name_get(ttype, "xx").lower()[:3]
                if ttype == token.NAME:
                    if iskeyword(ttext):
                        tok_class = "key"
                    elif issoftkeyword(ttext):
                        is_start_of_line = not line or (len(line) == 1 and line[0][0] == "ws")
                        if is_start_of_line and sline in soft_key_lines:
                            tok_class = "key"
                line.append((tok_class, part))
                col = ecol
            continue

        mark_start = True
        parts = ttext.splitlines(keepends=True)
        for part in parts:
            if part == "\n":
                yield line
                line = []
                col = 0
                mark_end = False
            elif part.endswith("\n"):
                part = part[:-1]
                if part:
                    if ttype in ws_tokens:
                        mark_end = False
                    else:
                        if fstring_syntax and ttype == token.FSTRING_MIDDLE:
                            part = part.replace("{", "{{").replace("}", "}}")
                            ecol = scol + len(part)
                        if mark_start and scol > col:
                            line.append(("ws", " " * (scol - col)))
                            mark_start = False
                        tok_class = tok_name_get(ttype, "xx").lower()[:3]
                        if ttype == token.NAME:
                            if iskeyword(ttext):
                                tok_class = "key"
                            elif issoftkeyword(ttext):
                                is_start_of_line = not line or (
                                    len(line) == 1 and line[0][0] == "ws"
                                )
                                if is_start_of_line and sline in soft_key_lines:
                                    tok_class = "key"
                        line.append((tok_class, part))
                        mark_end = True
                    scol = 0
                yield line
                line = []
                col = 0
                mark_end = False
            elif part == "":
                mark_end = False
            elif ttype in ws_tokens:
                mark_end = False
            else:
                if fstring_syntax and ttype == token.FSTRING_MIDDLE:
                    part = part.replace("{", "{{").replace("}", "}}")
                    ecol = scol + len(part)
                if mark_start and scol > col:
                    line.append(("ws", " " * (scol - col)))
                    mark_start = False
                tok_class = tok_name_get(ttype, "xx").lower()[:3]
                if ttype == token.NAME:
                    if iskeyword(ttext):
                        # Hard keywords are always keywords.
                        tok_class = "key"
                    elif issoftkeyword(ttext):
                        # Soft keywords appear at the start of their line.
                        if len(line) == 0:
                            is_start_of_line = True
                        elif (len(line) == 1) and line[0][0] == "ws":
                            is_start_of_line = True
                        else:
                            is_start_of_line = False
                        if is_start_of_line and sline in soft_key_lines:
                            tok_class = "key"
                line.append((tok_class, part))
                mark_end = True
            scol = 0
        if mark_end:
            col = ecol

    if line:
        yield line


def generate_tokens(text: str) -> TokenInfos:
    """A helper around `tokenize.generate_tokens`.

    Originally this was used to cache the results, but it didn't seem to make
    reporting go faster, and caused issues with using too much memory.

    """
    readline = io.StringIO(text).readline
    return tokenize.generate_tokens(readline)


def source_encoding(source: bytes) -> str:
    """Determine the encoding for `source`, according to PEP 263.

    `source` is a byte string: the text of the program.

    Returns a string, the name of the encoding.

    """
    readline = iter(source.splitlines(True)).__next__
    return tokenize.detect_encoding(readline)[0]
