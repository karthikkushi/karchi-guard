"""Agent blast-radius scan for Supabase repos.

The question: if an AI coding agent working in this folder goes wrong, what can it read or destroy?
Reads files only. No network, no database, and secret values are never printed.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import claude_rules

CRITICAL, HIGH, MEDIUM = "CRITICAL", "HIGH", "MEDIUM"
RANK = {CRITICAL: 0, HIGH: 1, MEDIUM: 2}

# What an agent could do with the access a finding gives it. Order = order in the blast-radius list.
EFFECTS = {
    "read": "read every row in every table",
    "write": "change or delete every row",
    "sql": "run any SQL, including DROP TABLE",
    "delete": "delete the whole project, and its backups with it",
    "account": "reach every project in your Supabase account",
}

NOT_CHECKED = [
    "RLS rules and policies: run Supabase Security Advisor (supabase db advisors --type security)",
    "Whether user A can read user B's rows: run rlsgrid on a local copy of the database",
    "Keys in old git commits: run gitleaks",
    "Cursor and Windsurf command allowlists (they live in the app, not in the repo)",
    "What an agent actually does at run time",
]

MAX_BYTES = 5_000_000  # ponytail: bigger files are skipped; raise if real bundles hit it
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".turbo", ".cache"}
FRONTEND_DIRS = {"dist", "build", "out", "public"}
PUBLIC_ENV = ("VITE_", "NEXT_PUBLIC_", "EXPO_PUBLIC_", "REACT_APP_", "PUBLIC_", "NUXT_PUBLIC_", "GATSBY_")
MCP_FILES = (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json")
HOME_FILES = (".claude.json", ".claude/settings.json", ".cursor/mcp.json", ".codeium/windsurf/mcp_config.json")

_JWT = re.compile(r"eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}")
_SECRET_KEY = re.compile(r"\bsb_secret_[\w-]{20,}")
# The local-only key every `supabase start` prints; it is public and the same on every machine.
LOCAL_SECRET_KEY = "sb_" + "secret_N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz"
_ACCESS_TOKEN = re.compile(r"\bsbp_\w{20,}")
_DB_URL = re.compile(r"postgres(?:ql)?://[^\s:/@'\"]+:([^\s@'\"]+)@([^\s/:'\"?]+)")
_BACKUP = re.compile(r"pg_dump|supabase db dump|wal-g|pgbackrest")
_USES_SUPABASE = re.compile(r"[a-z0-9]{20}\.supabase\.co|\bSUPABASE_URL\b")

# Dangerous steps checked against Claude Code permission rules (B6):
# (tool, input, what it does, effect, rule that stops it, where the rule goes)
ATTEMPTS = (
    ("Bash", "supabase db reset --linked", "wipe the live database linked to this folder", "sql",
     "Bash(supabase db reset:*)", "deny"),
    ("Bash", "supabase projects delete abcdefghijklmnopqrst", "delete a Supabase project and its backups", "delete",
     "Bash(supabase projects delete:*)", "deny"),
    ("Bash", 'psql "$DATABASE_URL" -c "drop table profiles"', "drop a table with psql", "sql",
     "Bash(psql:*)", "ask"),
)


@dataclass
class Finding:
    check: str  # B1..B7
    severity: str
    title: str
    where: str  # file:line, never the secret itself
    why: str
    fix: str
    effects: list[str] = field(default_factory=list)


@dataclass
class _File:
    label: str  # path relative to the folder, or ~/... for home files
    text: str
    committed: bool = False
    frontend: bool = False


def scan(folder: Path, *, home: Path | None = None) -> list[Finding]:
    folder = folder.resolve()
    files = list(_repo_files(folder))
    if home:
        files += [_File(f"~/{name}", text) for name in HOME_FILES if (text := _read_text(home / name)) is not None]

    findings: list[Finding] = []
    for f in files:
        findings += _secrets(f)

    settings_paths = [folder / ".claude/settings.json", folder / ".claude/settings.local.json"]
    if home:
        settings_paths.append(home / ".claude/settings.json")
    try:
        settings = claude_rules.load(settings_paths)
    except ValueError as error:
        settings = None
        findings.append(Finding("B6", MEDIUM, "Claude Code settings could not be read", "-", str(error),
                                "Fix the JSON. Claude Code may ignore a broken settings file."))
    uses_claude = settings or (folder / ".claude").is_dir() or (folder / "CLAUDE.md").is_file()
    settings = settings or claude_rules.Settings((), (), (), (), None, ())

    for f in files:
        if f.label.endswith(MCP_FILES) or f.label == "~/.claude.json" or f.label.endswith("mcp_config.json"):
            findings += _mcp(f, settings)

    is_supabase = (folder / "supabase").is_dir() or findings or any(
        "supabase" in f.text.lower() for f in files
        if Path(f.label).name in ("package.json", "requirements.txt", "pyproject.toml")) or any(
        _USES_SUPABASE.search(f.text) for f in files if not f.label.startswith("~"))  # plain fetch/httpx calls
    if not is_supabase:
        return []
    if uses_claude:
        where = ", ".join(_label(p, folder, home) for p in settings.files) or "(no Claude Code settings file)"
        findings += _claude(settings, findings, where)
    if not any(_BACKUP.search(f.text) for f in files if not f.label.startswith("~")):
        findings.append(Finding(
            "B7", MEDIUM, "No off-site backup found in this repo", "(whole repo)",
            "Supabase keeps backups inside the project. If the project is deleted, by a person or an agent, "
            "its backups are deleted with it. We found no pg_dump or 'supabase db dump' job here.",
            "Add a daily job (for example a GitHub Action) that runs 'supabase db dump' and stores the file "
            "outside Supabase, such as a private S3 or R2 bucket."))
    return sorted(findings, key=lambda f: (RANK[f.severity], f.check, f.where))


# ---- B1, B2: keys and passwords an agent can read ----------------------------------------------

def _secrets(f: _File) -> list[Finding]:
    found = []
    for number, line in enumerate(f.text.splitlines(), 1):
        if not any(s in line for s in ("eyJ", "sb_secret_", "sbp_", "postgres")):
            continue
        kinds = []
        if any(k != LOCAL_SECRET_KEY for k in _SECRET_KEY.findall(line)) or any(
                _jwt_role(t) == "service_role" for t in _JWT.findall(line)):
            kinds.append("service")
        if _ACCESS_TOKEN.search(line):
            kinds.append("token")
        if any(host.endswith((".supabase.co", ".supabase.com")) and not _placeholder(pw) for pw, host in _DB_URL.findall(line)):
            kinds.append("db")
        exposed = f.frontend or line.lstrip().removeprefix("export ").startswith(PUBLIC_ENV)
        found += [_secret_finding(kind, f"{f.label}:{number}", f.committed, exposed) for kind in kinds]
    return found


def _secret_finding(kind: str, where: str, committed: bool, exposed: bool) -> Finding:
    check, title, effects, why, fix = {
        "service": ("B1", "Supabase service_role / secret key", ["read", "write"],
                    "This key skips every RLS rule.",
                    "Rotate the key in Supabase (Project Settings > API Keys). Keep the new one only in server-side "
                    "secrets your agent cannot read, never in a VITE_ or NEXT_PUBLIC_ variable."),
        "token": ("B2", "Supabase personal access token (sbp_)", ["delete", "account", "sql"],
                  "This token can manage every project in your account, including deleting one. "
                  "Deleting a project also deletes its backups.",
                  "Revoke it at supabase.com/dashboard/account/tokens. For MCP, use the browser login (OAuth) "
                  "or an ${ENV} reference, together with project_ref and read_only=true."),
        "db": ("B2", "Database password in a connection string", ["read", "write", "sql"],
               "This password logs in as the database owner. It skips RLS and can drop tables.",
               "Reset the database password (Project Settings > Database). Keep the URL out of files your "
               "agent can read, and give tools a read-only role."),
    }[kind]
    if exposed:
        severity, place = CRITICAL, "It is shipped to the browser, so anyone on the internet can use it."
    elif committed:
        severity, place = CRITICAL, "It is committed to git, so everyone with access to the repo has it."
    else:
        severity = CRITICAL if kind == "token" else HIGH
        place = "It is not committed, but any AI agent working in this folder can read it."
    return Finding(check, severity, title, where, f"{why} {place}", fix, effects)


def _jwt_role(token: str) -> str | None:
    try:
        part = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (ValueError, IndexError):
        return None
    # iss "supabase" = a real project key. The local demo keys say "supabase-demo" and are public.
    return claims.get("role") if isinstance(claims, dict) and claims.get("iss") == "supabase" else None


def _placeholder(password: str) -> bool:
    return password.startswith(("$", "[", "<", "{", "*")) or password.lower() in {
        "password", "postgres", "your-password", "your_password", "pass"}


# ---- B3, B4: Supabase MCP server settings ------------------------------------------------------

def _mcp(f: _File, settings: claude_rules.Settings) -> list[Finding]:
    try:
        data = json.loads(f.text)
    except ValueError:
        return []
    found = []
    for name, server in _servers(data):
        text = json.dumps(server)
        if "mcp.supabase.com" not in text and "mcp-server-supabase" not in text:
            continue
        where = f"{f.label}:{_line_of(f.text, json.dumps(name))}"
        if "read_only=true" not in text and "--read-only" not in text:
            state, reason = (claude_rules.decide(settings, f"mcp__{name}__execute_sql")
                             if f.label.endswith(".mcp.json") or f.label == "~/.claude.json" else (claude_rules.ASKS, ""))
            runs = state == claude_rules.RUNS
            found.append(Finding(
                "B3", CRITICAL if runs else HIGH, f"Supabase MCP server '{name}' is not read-only", where,
                "Your agent can run any SQL through it: change data or drop tables. " + (
                    f"Claude Code runs its tools without asking ({reason})." if runs else
                    "Most tools ask before each call, but one wrong click, or a prompt hidden in your data, is enough."),
                "Add read_only=true to the URL, for example "
                "https://mcp.supabase.com/mcp?project_ref=<ref>&read_only=true (or --read-only for the npx server). "
                "Keep a separate entry without read_only only for the rare times you need writes.",
                ["sql", "write"]))
        if "project_ref=" not in text and "--project-ref" not in text:
            found.append(Finding(
                "B4", HIGH, f"Supabase MCP server '{name}' is not limited to one project", where,
                "Without project_ref the server turns on account tools, so your agent can reach every project "
                "in your account: list, create, pause and query them.",
                "Add project_ref=<your project ref> to the URL (or --project-ref=<ref> for the npx server).",
                ["account"]))
    return found


def _servers(data: object):
    if not isinstance(data, dict):
        return
    for key in ("mcpServers", "servers"):  # "servers" is the VS Code format
        if isinstance(data.get(key), dict):
            yield from ((n, s) for n, s in data[key].items() if isinstance(s, dict))
    projects = data.get("projects")  # ~/.claude.json keeps servers per project too
    for project in projects.values() if isinstance(projects, dict) else ():
        if isinstance(project, dict):
            yield from _servers({"mcpServers": project.get("mcpServers")})


# ---- B6: dangerous steps Claude Code would not stop --------------------------------------------

def _claude(settings: claude_rules.Settings, findings: list[Finding], where: str) -> list[Finding]:
    found = []
    for tool, command, what, effect, rule, kind in ATTEMPTS:
        state, reason = claude_rules.decide(settings, tool, command)
        if state == claude_rules.RUNS:
            severity = CRITICAL if settings.mode == "bypassPermissions" else HIGH
        elif state == claude_rules.UNKNOWN:
            severity = MEDIUM
        else:
            continue
        found.append(Finding(
            "B6", severity, f"Claude Code would not stop: {command}", where,
            f"This would {what} (if this machine is logged in to Supabase). Status: {state}, because {reason}.",
            f'Add "{rule}" to permissions.{kind} in .claude/settings.json.',
            [effect] if state == claude_rules.RUNS else []))
    env_files = sorted({f.where.rsplit(":", 1)[0] for f in findings
                        if f.check in ("B1", "B2") and Path(f.where.rsplit(":", 1)[0]).name.startswith(".env")})
    for env in env_files:
        state, reason = claude_rules.decide(settings, "Read", env)
        if state in (claude_rules.RUNS, claude_rules.UNKNOWN):
            found.append(Finding(
                "B6", HIGH if state == claude_rules.RUNS else MEDIUM, f"Claude Code can read {env}", where,
                f"That file holds the keys listed above. Status: {state}, because {reason}.",
                'Add "Read(**/.env*)" to permissions.deny in .claude/settings.json.'))
    return found


# ---- files -------------------------------------------------------------------------------------

def _repo_files(folder: Path):
    tracked = _tracked(folder)
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            rel = Path(dirpath, name).relative_to(folder)
            text = _read_text(folder / rel)
            if text is not None:
                frontend = bool(FRONTEND_DIRS & set(rel.parts[:-1])) or ".next/static/" in rel.as_posix()
                yield _File(rel.as_posix(), text, rel.as_posix() in tracked, frontend)


def _tracked(folder: Path) -> set[str]:
    try:
        done = subprocess.run(["git", "-C", str(folder), "ls-files", "-z"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return set()
    return set(done.stdout.split("\0")) if done.returncode == 0 else set()


def _read_text(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    return None if b"\0" in data[:8000] else data.decode("utf-8", "replace")


def _line_of(text: str, needle: str) -> int:
    return next((n for n, line in enumerate(text.splitlines(), 1) if needle in line), 1)


def _label(path: Path, folder: Path, home: Path | None) -> str:
    if path.is_relative_to(folder):
        return path.relative_to(folder).as_posix()
    return f"~/{path.relative_to(home).as_posix()}" if home and path.is_relative_to(home) else str(path)


# ---- output ------------------------------------------------------------------------------------

def blast_radius(findings: list[Finding]) -> list[tuple[str, str]]:
    first: dict[str, str] = {}
    for f in findings:  # already sorted, worst first
        for effect in f.effects:
            first.setdefault(effect, f"{f.check} {f.where}")
    return [(text, first[key]) for key, text in EFFECTS.items() if key in first]


def render(folder: Path, findings: list[Finding]) -> str:
    lines = ["Karchi Guard: agent blast-radius scan", f"Folder: {folder.resolve()}",
             "Read files only. No network, no database. Secret values are never shown.", ""]
    radius = blast_radius(findings)
    if radius:
        width = max(len(text) for text, _ in radius)
        lines.append("BLAST RADIUS: an AI agent working here has enough access to:")
        lines += [f"  - {text.ljust(width)}   ({source})" for text, source in radius]
    else:
        lines.append("BLAST RADIUS: no path found from this folder to admin power over your Supabase data.")
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[s]} {s}" for s in RANK if counts[s])
    lines += ["", f"{len(findings)} findings: {summary}" if findings else "No findings."]
    for f in findings:
        lines += ["", f"[{f.severity}] {f.check} {f.title}", f"  Where: {f.where}", f"  Why:   {f.why}", f"  Fix:   {f.fix}"]
    lines += ["", "Not checked:"] + [f"  - {item}" for item in NOT_CHECKED]
    lines += ["", "This is not a full security check. It shows what an AI agent here could reach."]
    return "\n".join(lines)


def to_json(folder: Path, findings: list[Finding]) -> str:
    return json.dumps({
        "tool": "karchi-guard", "version": 1, "folder": str(folder.resolve()),
        "blast_radius": [{"effect": text, "source": source} for text, source in blast_radius(findings)],
        "findings": [asdict(f) for f in findings], "not_checked": NOT_CHECKED,
    }, indent=2)
