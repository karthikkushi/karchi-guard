"""Report tests with sample inputs shaped like the real tools' output."""

import json
import tempfile
import unittest
from pathlib import Path

from karchi_guard import cli, report

ADVISORS = [
    {"name": "rls_disabled_in_public", "title": "RLS Disabled in Public", "level": "ERROR", "facing": "EXTERNAL",
     "categories": ["SECURITY"], "description": "Detects tables without RLS.",
     "detail": "Table `public.profiles` is public, but RLS has not been enabled.",
     "remediation": "https://supabase.com/docs/guides/database/database-linter?lint=0013_rls_disabled_in_public",
     "metadata": {"schema": "public", "name": "profiles", "type": "table"}, "cacheKey": "x"},
    {"name": "some_new_lint", "title": "Something New", "level": "WARN", "facing": "EXTERNAL",
     "categories": ["SECURITY"], "description": "A lint we have no template for.", "detail": "Detail.",
     "remediation": "https://example.invalid/fix", "metadata": {"schema": "public", "name": "notes"}, "cacheKey": "y"},
    {"name": "unindexed_foreign_keys", "title": "Unindexed foreign keys", "level": "INFO", "facing": "EXTERNAL",
     "categories": ["PERFORMANCE"], "description": "perf", "detail": "perf", "remediation": "", "cacheKey": "z"},
]
RLS = {"ok": False, "iterations": 300, "skipped": 20, "skip_reasons": {"no target row on this table": 20}, "no_probes": False,
       "breaches": [
           {"actor_role": "authenticated", "actor_tenant": "a1", "target_tenant": "b2", "schema": "public", "table": "orders",
            "operation": "SELECT", "detail": "row {'id': 7, 'email': 'priya@example.com'}"},
           {"actor_role": "authenticated", "actor_tenant": "a2", "target_tenant": "b1", "schema": "public", "table": "orders",
            "operation": "select", "detail": "duplicate"}]}
UNTESTED = {"ok": True, "iterations": 300, "skipped": 300, "skip_reasons": {"probe raised a database error": 150},
            "no_probes": False, "breaches": []}
SCAN = {"blast_radius": [{"effect": "read every row in every table", "source": "B1 .env:1"}],
        "findings": [{"check": "B1", "severity": "HIGH", "title": "Supabase service_role / secret key", "where": ".env:1",
                      "why": "This key skips every RLS rule.", "fix": "Rotate the key.", "effects": ["read"]}],
        "not_checked": ["RLS rules and policies: run Supabase Security Advisor", "Whether user A can read user B's rows: run rlsgrid",
                        "Keys in old git commits: run gitleaks"]}


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.text = report.build("Demo App", SCAN, ADVISORS, RLS)

    def test_names_and_fix_sql_appear(self):
        self.assertIn("# Supabase safety report: Demo App", self.text)
        self.assertIn("alter table public.profiles enable row level security;", self.text)
        self.assertIn("A logged-in user can read other users' rows", self.text)
        self.assertIn("read every row in every table (B1 .env:1)", self.text)
        self.assertIn("See https://example.invalid/fix", self.text)

    def test_order_counts_and_dedupe(self):
        table = self.text.split("## What to fix first")[1].split("## Details")[0]
        severities = [row.split("|")[2].strip() for row in table.strip().splitlines()[2:]]
        self.assertEqual(severities, ["CRITICAL", "HIGH", "HIGH", "MEDIUM"])  # perf lint dropped, leak deduped

    def test_no_row_data_reaches_the_report(self):
        self.assertNotIn("priya@example.com", self.text)
        self.assertNotIn("'id': 7", self.text)

    def test_covered_items_leave_not_checked(self):
        not_checked = self.text.split("## What was not checked")[1]
        self.assertNotIn("RLS rules", not_checked)
        self.assertNotIn("user A", not_checked)
        self.assertIn("gitleaks", not_checked)

    def test_cli_results_wrapper_and_untested_rlsgrid(self):
        text = report.build("Demo", None, {"results": ADVISORS, "message": ""}, UNTESTED)
        self.assertIn("alter table public.profiles enable row level security;", text)
        self.assertIn("The cross-user test could not run on most tables", text)
        self.assertIn("300 of 300 probes skipped", text)
        self.assertNotIn("0 leaks, 0 of", text)

    def test_two_tenant_section_counts_as_checked(self):
        text = report.build("Demo", SCAN, ADVISORS, None, "| Check | Result |\n|---|---|\n| Other clinic rows | 0 |")
        self.assertIn("## Two-tenant test\n\n| Check | Result |", text)
        self.assertNotIn("user A", text.split("## What was not checked")[1])
        self.assertNotIn("\n\n\n", text)

    def test_cli_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = {}
            for name, data in (("scan", SCAN), ("advisors", ADVISORS), ("rlsgrid", RLS)):
                paths[name] = Path(tmp, name + ".json")
                paths[name].write_text(json.dumps(data))
            out = Path(tmp, "report.md")
            code = cli.main(["report", "--scan", str(paths["scan"]), "--advisors", str(paths["advisors"]),
                             "--rlsgrid", str(paths["rlsgrid"]), "--project", "Demo", "--out", str(out)])
            self.assertEqual(code, 0)
            self.assertIn("Supabase safety report: Demo", out.read_text())


if __name__ == "__main__":
    unittest.main()
