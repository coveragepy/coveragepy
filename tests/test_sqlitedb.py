# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for coverage.sqlitedb"""

from __future__ import annotations

from unittest import mock

import pytest

from coverage.exceptions import DataError
from coverage.sqlitedb import SqliteDb

from tests.coveragetest import CoverageTest
from tests.helpers import DebugControlString, FailingProxy

DB_INIT = """\
create table name (first text, last text);
insert into name (first, last) values ("pablo", "picasso");
"""


class SqliteDbTest(CoverageTest):
    """Tests of tricky parts of SqliteDb."""

    def test_error_reporting(self) -> None:
        msg = "Couldn't use data file 'test.db': no such table: bar"
        with SqliteDb("test.db", DebugControlString(options=["sql"])) as db:
            with pytest.raises(DataError, match=msg):
                with db.execute("select foo from bar"):
                    # Entering the context manager raises the error, this line doesn't run:
                    pass  # pragma: not covered

    def test_retry_execute(self) -> None:
        with SqliteDb("test.db", DebugControlString(options=["sql"])) as db:
            db.executescript(DB_INIT)
            proxy = FailingProxy(db.con, "execute", [Exception("WUT")])
            with mock.patch.object(db, "con", proxy):
                with db.execute("select first from name order by 1") as cur:
                    assert list(cur) == [("pablo",)]

    def test_retry_execute_failure(self) -> None:
        with SqliteDb("test.db", DebugControlString(options=["sql"])) as db:
            db.executescript(DB_INIT)
            proxy = FailingProxy(db.con, "execute", [Exception("WUT"), RuntimeError("Fake")])
            with mock.patch.object(db, "con", proxy):
                with pytest.raises(RuntimeError, match="Fake"):
                    with db.execute("select first from name order by 1"):
                        # Entering the context manager raises the error, this line doesn't run:
                        pass  # pragma: not covered

    def test_retry_executemany_void(self) -> None:
        with SqliteDb("test.db", DebugControlString(options=["sql"])) as db:
            db.executescript(DB_INIT)
            proxy = FailingProxy(db.con, "executemany", [Exception("WUT")])
            with mock.patch.object(db, "con", proxy):
                db.executemany_void(
                    "insert into name (first, last) values (?, ?)",
                    [("vincent", "van gogh")],
                )
            with db.execute("select first from name order by 1") as cur:
                assert list(cur) == [("pablo",), ("vincent",)]

    def test_retry_executemany_void_failure(self) -> None:
        with SqliteDb("test.db", DebugControlString(options=["sql"])) as db:
            db.executescript(DB_INIT)
            proxy = FailingProxy(db.con, "executemany", [Exception("WUT"), RuntimeError("Fake")])
            with mock.patch.object(db, "con", proxy):
                with pytest.raises(RuntimeError, match="Fake"):
                    db.executemany_void(
                        "insert into name (first, last) values (?, ?)",
                        [("vincent", "van gogh")],
                    )

    def test_open_fails_on_bad_db(self) -> None:
        self.make_file("bad.db", "boogers")
        msg = "Couldn't use data file 'bad.db': file is not a database"
        with pytest.raises(DataError, match=msg):
            with SqliteDb("bad.db", DebugControlString(options=["sql"])):
                pass  # pragma: not covered

    def test_execute_void_can_allow_failure(self) -> None:
        with SqliteDb("fail.db", DebugControlString(options=["sql"])) as db:
            db.executescript(DB_INIT)
            proxy = FailingProxy(db.con, "execute", [Exception("WUT")])
            with mock.patch.object(db, "con", proxy):
                db.execute_void("select x from nosuchtable", fail_ok=True)

    def test_execute_void_can_refuse_failure(self) -> None:
        with SqliteDb("fail.db", DebugControlString(options=["sql"])) as db:
            db.executescript(DB_INIT)
            proxy = FailingProxy(db.con, "execute", [Exception("WUT")])
            with mock.patch.object(db, "con", proxy):
                msg = "Couldn't use data file 'fail.db': no such table: nosuchtable"
                with pytest.raises(DataError, match=msg):
                    db.execute_void("select x from nosuchtable", fail_ok=False)
