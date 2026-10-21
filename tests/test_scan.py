"""Scan tests on throwaway fixture repos. Fake keys are built here at run time and never committed."""

import base64
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from karchi_guard import cli, scan
from karchi_guard.scan import CRITICAL, HIGH, MEDIUM


def fake_jwt(role, iss="supabase"):
    def enc(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc({'iss': iss, 'ref': 'abcdefghijklmnopqrst', 'role': role})}.{'x' * 43}"


SERVICE = fake_jwt("service_role")
ANON = fake_jwt("anon")
SECRET = "sb_" + "secret_" + "A1b2C3d4" * 4
PAT = "sb" + "p_" + "0123456789abcdef" * 2 + "01234567"
DB_URL = "postgresql://postgres.abcdefghijklmnopqrst:" + "Hunter2Hunter2" + "@aws-0-ap-south-1.pooler.supabase.com:5432/postgres"
SAFE_MCP = {"mcpServers": {"supabase": {"type": "http", "url": "https://mcp.supabase.com/mcp?project_ref=abc&read_only=true"}}}
OPEN_MCP = {"mcpServers": {"supabase": {"type": "http", "url": "https://mcp.supabase.com/mcp"}}}


class Repo:
    """A temporary folder with files; names in `commit` are added to a git index."""

    def __init__(self, files, commit=()):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        (self.path / "supabase").mkdir()
        for name, text in files.items():
            target = self.path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text if isinstance(text, str) else json.dumps(text, indent=2))
        if commit:
            subprocess.run(["git", "init", "-q", str(self.path)], check=True)
            subprocess.run(["git", "-C", str(self.path), "add", *commit], check=True)

    def __enter__(self):
        return self.path

    def __exit__(self, *exc):
        self.tmp.cleanup()


def run(files, commit=()):
    with Repo(files, commit) as path:
        return scan.scan(path)


def only(findings, check):
    return [f for f in findings if f.check == check]


class SecretTests(unittest.TestCase):
    def test_service_key_in_untracked_env_is_high(self):
        [f] = only(run({".env": f"SUPABASE_SERVICE_ROLE_KEY={SERVICE}\n"}), "B1")
        self.assertEqual((f.severity, f.where), (HIGH, ".env:1"))

    def test_service_key_committed_is_critical(self):
        [f] = only(run({"src/admin.ts": f'const key = "{SERVICE}"\n'}, commit=["src/admin.ts"]), "B1")
        self.assertEqual(f.severity, CRITICAL)
        self.assertIn("committed", f.why)

    def test_service_key_in_public_env_var_or_bundle_is_critical(self):
        self.assertEqual(only(run({".env": f"VITE_SUPABASE_KEY={SECRET}\n"}), "B1")[0].severity, CRITICAL)
        self.assertEqual(only(run({"dist/assets/index.js": f'x="{SERVICE}"'}), "B1")[0].severity, CRITICAL)

    def test_public_keys_and_local_demo_keys_are_ignored(self):
        files = {".env": f"VITE_SUPABASE_ANON_KEY={ANON}\nKEY=sb_publishable_abcdefghijklmnopqrstuv\n"
                         f"LOCAL={fake_jwt('service_role', iss='supabase-demo')}\n"}
        self.assertEqual(only(run(files), "B1"), [])

    def test_access_token_is_always_critical(self):
        [f] = only(run({".env": f"SUPABASE_ACCESS_TOKEN={PAT}\n"}), "B2")
        self.assertEqual(f.severity, CRITICAL)
        self.assertIn("delete", f.effects)

    def test_db_url_with_password_found_but_placeholders_and_local_ignored(self):
        self.assertEqual(len(only(run({".env": f"DATABASE_URL={DB_URL}\n"}), "B2")), 1)
        placeholders = {".env": "A=postgresql://postgres:[YOUR-PASSWORD]@db.abc.supabase.co:5432/postgres\n"
                                "B=postgresql://postgres:${DB_PASSWORD}@db.abc.supabase.co:5432/postgres\n"
                                "C=postgresql://postgres:postgres@127.0.0.1:54322/postgres\n"}
        self.assertEqual(only(run(placeholders), "B2"), [])


class McpTests(unittest.TestCase):
    def test_open_supabase_mcp_flags_read_only_and_project_scope(self):
        findings = run({".mcp.json": OPEN_MCP})
        self.assertEqual([f.severity for f in only(findings, "B3")], [HIGH])
        self.assertEqual(len(only(findings, "B4")), 1)
        self.assertEqual(only(findings, "B3")[0].where, ".mcp.json:3")

    def test_scoped_read_only_mcp_is_fine_in_every_format(self):
        npx = {"servers": {"db": {"command": "npx", "args": ["-y", "@supabase/mcp-server-supabase", "--read-only", "--project-ref=abc"]}}}
        findings = run({".mcp.json": SAFE_MCP, ".cursor/mcp.json": SAFE_MCP, ".vscode/mcp.json": npx})
        self.assertEqual(only(findings, "B3") + only(findings, "B4"), [])

    def test_auto_allowed_write_mcp_is_critical(self):
        settings = {"permissions": {"allow": ["mcp__supabase"]}}
        [f] = only(run({".mcp.json": OPEN_MCP, ".claude/settings.json": settings}), "B3")
        self.assertEqual(f.severity, CRITICAL)

    def test_token_inside_mcp_config_is_found(self):
        config = {"mcpServers": {"supabase": {"url": "https://mcp.supabase.com/mcp?project_ref=abc&read_only=true",
                                              "headers": {"Authorization": f"Bearer {PAT}"}}}}
        self.assertEqual(only(run({".cursor/mcp.json": config}), "B2")[0].where, ".cursor/mcp.json:6")


class ClaudeTests(unittest.TestCase):
    def test_bypass_permissions_makes_destructive_steps_critical(self):
        findings = only(run({".claude/settings.json": {"permissions": {"defaultMode": "bypassPermissions"}}}), "B6")
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(f.severity == CRITICAL for f in findings))

    def test_allow_rule_lets_db_reset_run(self):
        findings = only(run({".claude/settings.json": {"permissions": {"allow": ["Bash(supabase:*)"]}}}), "B6")
        self.assertEqual([f.title for f in findings], [
            "Claude Code would not stop: supabase db reset --linked",
            "Claude Code would not stop: supabase projects delete abcdefghijklmnopqrst"])

    def test_deny_rules_stop_everything(self):
        settings = {"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash"],
                                    "deny": ["Bash(supabase db reset:*)", "Bash(supabase projects delete:*)", "Bash(psql:*)",
                                             "Read(**/.env*)"]}}
        files = {".claude/settings.json": settings, ".env": f"KEY={SERVICE}\n"}
        self.assertEqual(only(run(files), "B6"), [])

    def test_env_with_keys_is_readable_by_default(self):
        [f] = only(run({"CLAUDE.md": "notes", ".env.local": f"KEY={SERVICE}\n"}), "B6")
        self.assertEqual((f.severity, f.title), (HIGH, "Claude Code can read .env.local"))

    def test_hook_makes_it_unknown_not_safe(self):
        settings = {"permissions": {"allow": ["Bash"]}, "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": []}]}}
        findings = only(run({".claude/settings.json": settings}), "B6")
        self.assertTrue(findings and all(f.severity == MEDIUM for f in findings))

    def test_no_claude_settings_no_b6(self):
        self.assertEqual(only(run({".env": f"KEY={SERVICE}\n"}), "B6"), [])


class BackupAndOutputTests(unittest.TestCase):
    def test_backup_job_found_or_not(self):
        self.assertEqual(len(only(run({}), "B7")), 1)
        job = {".github/workflows/backup.yml": "run: supabase db dump -f backup.sql\n"}
        self.assertEqual(only(run(job), "B7"), [])

    def test_not_a_supabase_repo_gives_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "app.py").write_text("print('hi')\n")
            self.assertEqual(scan.scan(Path(tmp)), [])

    def test_output_never_contains_a_secret_and_exit_code_follows_critical(self):
        files = {".env": f"A={SERVICE}\nB={SECRET}\nC={PAT}\nD={DB_URL}\n", ".mcp.json": OPEN_MCP}
        with Repo(files) as path:
            for extra in ([], ["--json"]):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = cli.main(["scan", str(path), *extra])
                text = out.getvalue()
                self.assertEqual(code, 1)
                for secret in (SERVICE, SECRET, PAT, "Hunter2Hunter2", SERVICE.split(".")[2]):
                    self.assertNotIn(secret, text)
            self.assertIn("delete the whole project", text)

    def test_clean_repo_exits_zero(self):
        files = {".mcp.json": SAFE_MCP, ".github/workflows/backup.yml": "pg_dump\n"}
        with Repo(files) as path, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["scan", str(path)]), 0)


if __name__ == "__main__":
    unittest.main()
