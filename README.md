# Karchi Guard

**What can an AI agent in your Supabase repo read or destroy?**

Karchi Guard reads your repo and your agent settings, then lists the keys, MCP servers and missing rules that let an AI coding agent (Claude Code, Cursor, and others) read all your data, drop tables, or delete the whole project along with its backups.

It reads files only. It uses no network, never touches your database, and never prints a secret.

## Run it

You need Python 3.11 or newer. Nothing else to install.

```
PYTHONPATH=src python3 -m karchi_guard scan /path/to/your/app
PYTHONPATH=src python3 -m karchi_guard scan /path/to/your/app --home   # also reads ~/.claude.json, ~/.cursor/mcp.json
```

It exits with code 1 when it finds anything CRITICAL, so it can fail a CI job.

## What it checks

| ID | Finds |
|---|---|
| B1 | `service_role` or `sb_secret_` keys in files, `.env`, the built frontend, or `VITE_`/`NEXT_PUBLIC_` variables |
| B2 | Supabase access tokens (`sbp_`) and database URLs with a password |
| B3 | Supabase MCP server without `read_only=true` |
| B4 | Supabase MCP server without `project_ref`, which gives it account-wide tools |
| B6 | Claude Code rules that would not stop `supabase db reset --linked`, `supabase projects delete`, `psql ... drop table`, or reading `.env` |
| B7 | No off-site backup job. Deleting a Supabase project also deletes its backups |

**Not checked:** RLS policies (run `supabase db advisors --type security`), whether user A can read user B's rows (run [rlsgrid](https://github.com/matte97p/rlsgrid) on a local copy), keys in old commits (run gitleaks), Cursor and Windsurf allowlists, and how an agent behaves at run time.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: karthikkushi/karchi-guard@v0   # not published yet
```

## One report from three tools

```
karchi-guard report --scan scan.json --advisors advisors.json --rlsgrid rls.sarif --project "My App" --out report.md
```

This combines the scan, Supabase Security Advisor and rlsgrid results into one plain-English Markdown report with fix SQL. The report contains names only, never row data.

## Tests

```
PYTHONPATH=src python3 -m unittest discover -s tests
```

MIT license. B6 reuses the rule matcher from [Rogue Drill](https://github.com/karthikkushi/nova-harbor).
