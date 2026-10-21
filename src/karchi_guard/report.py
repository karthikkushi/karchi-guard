"""One plain-English Markdown report from three inputs:

- the Karchi Guard scan (`karchi-guard scan --json`)
- Supabase Security Advisor (`supabase db advisors --type security --output-format json`)
- rlsgrid cross-user test (`rlsgrid check --json > rls.json`), run on a local copy only

Only names (tables, columns, files) reach the report, never row data.
"""

from __future__ import annotations

import datetime
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from string import Template

RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
ADVISOR_LEVEL = {"ERROR": "CRITICAL", "WARN": "MEDIUM", "INFO": "LOW"}

# Plain-English "why" and fix SQL for the Advisor lints we see most. {t} = schema.name of the object.
ADVISOR_FIXES = {
    "rls_disabled_in_public": (
        "Anyone with your public anon key (it is in your website's code) can read and change every row.",
        "alter table {t} enable row level security;\n"
        "-- Then let each user see only their own rows, for example:\n"
        "create policy \"own rows\" on {t} for select to authenticated\n"
        "  using ((select auth.uid()) = user_id);"),
    "policy_exists_rls_disabled": (
        "You wrote policies, but RLS is off, so they do nothing.",
        "alter table {t} enable row level security;"),
    "security_definer_view": (
        "This view runs with the owner's rights, so it skips RLS and can show every user's rows.",
        "alter view {t} set (security_invoker = on);"),
    "function_search_path_mutable": (
        "The function's search_path can be changed by the caller, which can make it run the wrong code.",
        "alter function {t} set search_path = '';"),
    "anon_security_definer_function_executable": (
        "Logged-out visitors can call this function, and it runs with the owner's rights, skipping RLS.",
        "revoke execute on function {t} from public, anon;"),
    "authenticated_security_definer_function_executable": (
        "Any logged-in user can call this function, and it runs with the owner's rights, skipping RLS.",
        "-- Only if normal users should not call it:\nrevoke execute on function {t} from public, authenticated;"),
    "rls_policy_always_true": (
        "This policy's check is always true, so anyone it applies to can {command} any row.",
        "drop policy \"{policy_name}\" on {t};\n"
        "create policy \"{policy_name}\" on {t} for {command} to authenticated\n"
        "  {clause} ((select auth.uid()) = user_id);  -- check the owner column name"),
    "auth_users_exposed": (
        "User emails and other account data from auth.users can be read through the API.",
        "revoke select on {t} from anon, authenticated;"),
}

RLSGRID_VERBS = {"select": "read", "insert": "add", "update": "change", "delete": "delete"}


@dataclass
class Item:
    severity: str
    source: str
    title: str
    where: str
    what: str
    why: str
    fix: str  # SQL goes in a code block; anything else is plain text
    sql: bool = False


def build(project: str, scan: dict | None, advisors: list | None, rls: dict | None) -> str:
    items = _from_scan(scan) + _from_advisors(advisors) + _from_rlsgrid(rls)
    items.sort(key=lambda i: (RANK[i.severity], i.source, i.where))
    counts = Counter(i.severity for i in items)

    summary = "| How bad | Count |\n|---|---|\n" + "\n".join(f"| {s} | {counts[s]} |" for s in RANK) if items \
        else "No problems were found in the checks below."
    radius = (scan or {}).get("blast_radius", [])
    blast = ("**If an AI agent in this repo goes wrong, it has enough access to:**\n\n"
             + "\n".join(f"- {r['effect']} ({r['source']})" for r in radius)) if radius else ""
    table = "| # | How bad | What | Where |\n|---|---|---|---|\n" + "\n".join(
        f"| {n} | {i.severity} | {i.title} | `{i.where}` |" for n, i in enumerate(items, 1)) if items else "Nothing to fix."
    details = "\n\n".join(_detail(n, i) for n, i in enumerate(items, 1)) or "None."

    checked, not_checked = [], list((scan or {}).get("not_checked", []))
    if scan:
        checked.append(f"Agent blast-radius scan of the repo (Karchi Guard): {len(_from_scan(scan))} findings")
    if advisors is not None:
        checked.append(f"Supabase Security Advisor, security lints: {len(_from_advisors(advisors))} findings")
        not_checked = [n for n in not_checked if not n.startswith("RLS rules")]
    if rls is not None:
        leaks = len({_leak(b) for b in rls.get("breaches", [])})
        checked.append(f"rlsgrid cross-user test on a local copy of the database: {leaks} leaks, "
                       f"{rls.get('skipped', 0)} of {rls.get('iterations', 0)} probes skipped")
        if not _untested(rls):
            not_checked = [n for n in not_checked if not n.startswith("Whether user A")]

    template = Template((Path(__file__).with_name("report.md")).read_text(encoding="utf-8"))
    return template.safe_substitute(
        project=project, date=datetime.date.today().isoformat(), summary=summary, blast=blast, table=table,
        details=details, checked=_bullets(checked) or "Nothing.", not_checked=_bullets(not_checked) or "Nothing listed.")


def load_json(path: str | None):
    return json.loads(Path(path).read_text(encoding="utf-8")) if path else None


def _from_scan(scan: dict | None) -> list[Item]:
    return [Item(f["severity"], f["check"], f["title"], f["where"], f["title"] + ".", f["why"], f["fix"])
            for f in (scan or {}).get("findings", [])]


def _from_advisors(advisors) -> list[Item]:
    # The CLI prints {"results": [...]}; the Management API uses {"lints": [...]}.
    lints = (advisors.get("results") or advisors.get("lints") or []) if isinstance(advisors, dict) else advisors or []
    items = []
    for lint in lints:
        if "SECURITY" not in (lint.get("categories") or ["SECURITY"]):
            continue
        meta = lint.get("metadata") or {}
        target = ".".join(p for p in (meta.get("schema"), meta.get("name")) if p) or lint.get("name", "?")
        command = str(meta.get("command") or "all").lower()
        fields = _Fields(meta, t=target, command=command, clause="with check" if command == "insert" else "using")
        known = ADVISOR_FIXES.get(lint.get("name"))
        why = known[0].format_map(fields) if known else lint.get("description", "")
        fix = known[1].format_map(fields) if known else f"See {lint.get('remediation', 'the Supabase docs')}"
        items.append(Item(ADVISOR_LEVEL.get(str(lint.get("level")).upper(), "MEDIUM"), "Advisor",
                          lint.get("title", lint.get("name", "?")), target, lint.get("detail", ""), why, fix, bool(known)))
    return items


def _from_rlsgrid(rls: dict | None) -> list[Item]:
    items = []
    for role, table, op in sorted({_leak(b) for b in (rls or {}).get("breaches", [])}):
        who = "A logged-out visitor" if role == "anon" else "A logged-in user"
        sql_op = "select" if op == "read" else op
        verb = RLSGRID_VERBS.get(sql_op, op)
        clause = "with check" if sql_op == "insert" else "using"
        items.append(Item(
            "CRITICAL" if role == "anon" else "HIGH", "rlsgrid", f"{who} can {verb} other users' rows", table,
            f"rlsgrid made test users on a local copy. {who} ({role}) could {verb} rows that belong to another user.",
            "One user can see or change another user's private data.",
            f"-- Find the {sql_op} policy on {table} that allows this, then tie it to the row owner:\n"
            f"drop policy \"<policy name>\" on {table};\n"
            f"create policy \"own rows only\" on {table} for {sql_op} to authenticated\n"
            f"  {clause} ((select auth.uid()) = user_id);", True))
    if rls and _untested(rls):
        reasons = "; ".join(f"{reason} ({count})" for reason, count in rls.get("skip_reasons", {}).items())
        items.append(Item(
            "MEDIUM", "rlsgrid", "The cross-user test could not run on most tables", "rlsgrid",
            f"{rls.get('skipped', 0)} of {rls.get('iterations', 0)} probes were skipped: {reasons or 'no reason given'}.",
            "Leaks between users may be hidden. Do not read this as safe.",
            "Fix the rlsgrid setup (owner column, test rows) and run it again, or test these tables by hand with two test users."))
    return items


def _leak(breach: dict) -> tuple[str, str, str]:
    # Only role, table and operation. Never "detail", which can hold row ids.
    return breach.get("actor_role", "?"), f"{breach.get('schema', '?')}.{breach.get('table', '?')}", str(breach.get("operation", "?")).lower()


def _untested(rls: dict) -> bool:
    # ponytail: half the probes skipped = untrustworthy; tune if real projects need a finer rule
    return bool(rls.get("no_probes")) or rls.get("skipped", 0) * 2 >= max(rls.get("iterations", 0), 1)


class _Fields(dict):
    """Template fields from lint metadata; a missing one shows as <name> instead of crashing."""

    def __missing__(self, key):
        return f"<{key}>"


def _detail(n: int, i: Item) -> str:
    fix = f"```sql\n{i.fix}\n```" if i.sql else i.fix
    return (f"### {n}. [{i.severity}] {i.title}\n\n"
            f"**Where:** `{i.where}` · found by {i.source}\n\n"
            f"**What is wrong:** {i.what}\n\n**Why it matters:** {i.why}\n\n**Fix:**\n\n{fix}")


def _bullets(lines: list[str]) -> str:
    return "\n".join(f"- {line}" for line in lines)
