"""Offline failure/latch tests. They do not replace the live DB/ingest canary."""
import contextlib
import copy
import io
import os
from pathlib import Path
import runpy
import sys
import types
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).parent / "operations/capacity_guard.py"
CAP = 2 * 1024**3


class Backend:
    def __init__(self, size=100, latched=False, orgs=None):
        self.state = {"size": size, "latched": latched, "threshold": CAP,
                      "orgs": [True, False] if orgs is None else orgs,
                      "success": None}
        self.fail_size = False
        self.fail_commit = False
        self.missing = False
        self.row = None

    @contextlib.contextmanager
    def atomic(self):
        before = copy.deepcopy(self.state)
        try:
            yield
            if self.fail_commit:
                raise RuntimeError("commit failed")
        except BaseException:
            self.state = before
            raise

    def cursor(self):
        return contextlib.nullcontext(self)

    def execute(self, sql, args=None):
        if sql.startswith("SET LOCAL"):
            return
        if sql.startswith("SELECT latched"):
            self.row = None if self.missing else (self.state["latched"], self.state["threshold"])
        elif sql.startswith("SELECT pg_database_size"):
            if self.fail_size:
                raise RuntimeError("size read failed")
            self.row = (self.state["size"],)
        elif sql.startswith("UPDATE infra_capacity_guard"):
            self.state.update(success=args[0], latched=args[1], size=args[2], closed=args[3])
        else:
            raise AssertionError("unexpected SQL")

    def fetchone(self):
        return self.row

    def filter(self, **kwargs):
        wanted = kwargs["is_accepting_events"]
        backend = self

        class Selection:
            def count(self):
                return backend.state["orgs"].count(wanted)

            def update(self, **values):
                assert values == {"is_accepting_events": False}
                n = self.count()
                backend.state["orgs"] = [False if x == wanted else x for x in backend.state["orgs"]]
                return n
        return Selection()

    def run(self, database_ok=True):
        django = types.ModuleType("django")
        django.setup = lambda: None
        db = types.ModuleType("django.db")
        db.connection = self
        db.transaction = types.SimpleNamespace(atomic=self.atomic)
        models = types.ModuleType("apps.organizations_ext.models")
        models.Organization = types.SimpleNamespace(objects=self)
        support = types.ModuleType("infra_support")

        def check_database():
            if not database_ok:
                raise RuntimeError("wrong DB identity/TLS")
        support.check_database = check_database
        modules = {"django": django, "django.db": db,
                   "apps.organizations_ext.models": models, "infra_support": support}
        output = io.StringIO()
        try:
            with patch.dict(sys.modules, modules), patch.dict(os.environ, {"GLITCHTIP_CAPACITY_BYTES": str(CAP)}), contextlib.redirect_stdout(output):
                runpy.run_path(str(SCRIPT))
        finally:
            self.output = output.getvalue()


class Tests(unittest.TestCase):
    def test_below_threshold_never_reopens_existing_closed_org(self):
        b = Backend(); b.run()
        self.assertEqual(b.state["orgs"], [True, False])
        self.assertFalse(b.state["latched"])

    def test_threshold_latches_and_closes_all_orgs(self):
        b = Backend(size=CAP, orgs=[True, True]); b.run()
        self.assertTrue(b.state["latched"])
        self.assertEqual(b.state["orgs"], [False, False])

    def test_latch_survives_size_reduction_and_closes_new_org(self):
        b = Backend(size=10, latched=True, orgs=[False, True]); b.run()
        self.assertTrue(b.state["latched"])
        self.assertEqual(b.state["orgs"], [False, False])

    def test_failed_size_query_does_not_publish_success(self):
        b = Backend(); b.fail_size = True
        with self.assertRaises(RuntimeError): b.run()
        self.assertEqual(b.output, "")
        self.assertIsNone(b.state["success"])

    def test_commit_failure_rolls_back_latch_and_never_prints_success(self):
        b = Backend(size=CAP); b.fail_commit = True
        with self.assertRaises(RuntimeError): b.run()
        self.assertEqual(b.output, "")
        self.assertFalse(b.state["latched"])
        self.assertEqual(b.state["orgs"], [True, False])

    def test_foreign_threshold_or_missing_state_rejected(self):
        for missing in (False, True):
            b = Backend(); b.missing = missing; b.state["threshold"] = CAP + 1
            with self.assertRaises(RuntimeError): b.run()
            self.assertEqual(b.output, "")

    def test_foreign_db_or_unverified_tls_prevents_updates(self):
        b = Backend(size=CAP)
        with self.assertRaises(RuntimeError): b.run(database_ok=False)
        self.assertFalse(b.state["latched"])
        self.assertIsNone(b.state["success"])


if __name__ == "__main__":
    unittest.main()
