"""End-to-end on the deliberately unsafe local Supabase in dev/.

Skipped unless GUARD_E2E=1. Needs Docker, the supabase CLI, rlsgrid in .venv, and `supabase start` run in dev/.
The demo app repo (fake keys, risky agent settings) is built in a temp folder and never committed.
Writes out/e2e-report.md so a person can read the result.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from karchi_guard import report, scan
from test_scan import PAT, SERVICE

ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "dev"
DB_URL = "postgresql://postgres:postgres@127.0.0.1:55322/postgres"


@unittest.skipUnless(os.environ.get("GUARD_E2E") == "1", "set GUARD_E2E=1 to run against the local Supabase")
class EndToEnd(unittest.TestCase):
    def test_full_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp)
            shutil.copytree(DEV / "supabase", app / "supabase", ignore=shutil.ignore_patterns(".temp", ".branches"))
            (app / ".env").write_text(f"VITE_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\nSUPABASE_SERVICE_ROLE_KEY={SERVICE}\n")
            (app / ".mcp.json").write_text(json.dumps({"mcpServers": {"supabase": {
                "type": "http", "url": "https://mcp.supabase.com/mcp", "headers": {"Authorization": f"Bearer {PAT}"}}}}, indent=2))
            (app / ".claude").mkdir()
            (app / ".claude/settings.json").write_text(json.dumps({"permissions": {"allow": ["Bash(supabase:*)"]}}))
            found = scan.scan(app)
            scan_json = json.loads(scan.to_json(app, found))

        advisors = json.loads(subprocess.run(
            ["supabase", "db", "advisors", "--local", "--type", "security", "--output-format", "json", "--workdir", str(DEV)],
            capture_output=True, text=True, check=True).stdout)
        rls = subprocess.run(
            [str(ROOT / ".venv/bin/rlsgrid"), "check", "--config", str(DEV / "rlsgrid.toml"), "--json"],
            capture_output=True, text=True, env={**os.environ, "DATABASE_URL": DB_URL})
        rls_json = json.loads(rls.stdout)

        text = report.build("Unsafe demo app", scan_json, advisors, rls_json)
        (ROOT / "out").mkdir(exist_ok=True)
        (ROOT / "out/e2e-report.md").write_text(text)

        # Scan: keys, MCP, Claude Code rules, backups.
        self.assertEqual({f.check for f in found}, {"B1", "B2", "B3", "B4", "B6", "B7"})
        # Advisor: RLS off on profiles, and the always-true INSERT policy on notes.
        self.assertIn("alter table public.profiles enable row level security;", text)
        self.assertIn('drop policy "anyone can add notes" on public.notes;', text)
        # rlsgrid: the leaks the Advisor misses, and no leak on the safe table.
        self.assertEqual(rls.returncode, 1)
        self.assertIn("A logged-in user can read other users' rows | `public.orders`", text)
        self.assertIn("A logged-out visitor can read other users' rows | `public.notes`", text)
        self.assertNotIn("public.messages", text)
        self.assertNotIn("could not run on most tables", text)
        # Nothing secret and no row data in the report; rlsgrid left no rows behind.
        for secret in (SERVICE, PAT, *[b["actor_tenant"] for b in rls_json["breaches"]]):
            self.assertNotIn(secret, text)
        counts = subprocess.run(
            ["docker", "exec", "supabase_db_guard-dev", "psql", "-U", "postgres", "-tAc",
             "select (select count(*) from auth.users) + (select count(*) from public.notes)"
             " + (select count(*) from public.orders) + (select count(*) from public.messages)"],
            capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(counts, "0")

    def test_two_tenant_sql_finds_the_planted_leaks(self):
        a, b = "aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000001"
        seed = (f"begin;\ninsert into auth.users (id, email) values ('{a}', 'a@test.local'), ('{b}', 'b@test.local');\n"
                + "".join(f"insert into public.{t} (user_id, {col}) values ('{a}', {v}), ('{b}', {v});\n"
                          for t, col, v in (("notes", "body", "'x'"), ("orders", "total_cents", "100"),
                                            ("messages", "body", "'x'"))))
        # The test file's own rollback also removes the seed, so nothing is left behind.
        out = subprocess.run(
            ["docker", "exec", "-i", "supabase_db_guard-dev", "psql", "-U", "postgres", "-tA", "-F", "|",
             "-v", f"user_a={a}", "-v", f"tenant_a={a}", "-v", "tenant_col=user_id"],
            input=seed + (ROOT / "delivery/two-tenant-test.sql").read_text(), capture_output=True, text=True, check=True).stdout
        rows = {tuple(line.split("|")) for line in out.splitlines() if line.count("|") >= 1}
        # Section 1 (table|own|other): leaks on notes and orders, none on messages; own rows prove the setup.
        self.assertTrue({("notes", "1", "1"), ("orders", "1", "1"), ("messages", "1", "0")} <= rows)
        # Section 2 (table|visible to anon): notes is readable by anyone. Section 3: all_phones() is callable by anon.
        self.assertIn(("notes", "2"), rows)
        self.assertIn(("all_phones()", "t", "t"), rows)
        left = subprocess.run(["docker", "exec", "supabase_db_guard-dev", "psql", "-U", "postgres", "-tAc",
                               "select count(*) from auth.users"], capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(left, "0")


if __name__ == "__main__":
    unittest.main()
