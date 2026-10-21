# Karchi Guard

**What can an AI agent in your Supabase repo read or destroy?**

Karchi Guard is a free, read-only check for apps built on Supabase with tools like Lovable, Bolt, Cursor and Claude Code. It finds the keys, MCP servers and agent settings that let an AI agent read all your data, drop tables, or delete the whole project along with its backups.

- Reads files only. No network, no database, no account.
- Never prints a secret. Findings show `file:line` only.
- No dependencies. Python 3.11 or newer.

```
$ karchi-guard scan ./my-app

BLAST RADIUS: an AI agent working here has enough access to:
  - read every row in every table                       (B1 .env:2)
  - change or delete every row                          (B3 .mcp.json:3)
  - run any SQL, including DROP TABLE                   (B2 .mcp.json:7)
  - delete the whole project, and its backups with it   (B2 .mcp.json:7)
  - reach every project in your Supabase account        (B2 .mcp.json:7)

8 findings: 2 CRITICAL, 5 HIGH, 1 MEDIUM
```

*(Real output on a test repo with fake keys. Each finding also says why it matters and how to fix it.)*

## Run it

```
git clone https://github.com/karthikkushi/karchi-guard
cd karchi-guard
PYTHONPATH=src python3 -m karchi_guard scan /path/to/your/app
PYTHONPATH=src python3 -m karchi_guard scan /path/to/your/app --home   # also reads ~/.claude.json, ~/.cursor/mcp.json
PYTHONPATH=src python3 -m karchi_guard scan /path/to/your/app --json   # for scripts
```

Or install it: `pip install .` inside the folder, then run `karchi-guard scan /path/to/your/app`.

It exits with code 1 when it finds anything CRITICAL, so it can fail a CI job.

### GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: karthikkushi/karchi-guard@v0
  with:
    folder: .
```

## What it checks

| ID | Finds | Why it matters |
|---|---|---|
| B1 | `service_role` or `sb_secret_` keys in files, `.env`, the built frontend, or `VITE_`/`NEXT_PUBLIC_` variables | The key skips every RLS rule |
| B2 | Supabase access tokens (`sbp_`) and database URLs with a password | A token can delete projects; the DB password can drop tables |
| B3 | Supabase MCP server without `read_only=true` | The agent can run any SQL |
| B4 | Supabase MCP server without `project_ref` | The agent reaches every project in your account |
| B6 | Claude Code rules that would not stop `supabase db reset --linked`, `supabase projects delete`, `psql ... drop table`, or reading `.env`; also `bypassPermissions` and `auto` modes | Shows what runs without asking you |
| B7 | No off-site backup job | Deleting a Supabase project also deletes its backups |

## What it does not check

- RLS policies: run `supabase db advisors --type security`.
- Whether user A can read user B's rows: run [rlsgrid](https://github.com/matte97p/rlsgrid) on a local copy.
- Keys in old git commits: run [gitleaks](https://github.com/gitleaks/gitleaks).
- Cursor and Windsurf command allowlists (they live in the app, not the repo).
- What an agent actually does at run time.

A clean result means none of the problems above were found. It does not mean the app is secure.

## Guides

1. [Your AI agent can read your Supabase service key. Here is how to stop it.](docs/guides/01-agent-can-read-your-service-key.md)
2. [Make your Supabase MCP server read-only](docs/guides/02-make-supabase-mcp-read-only.md)
3. [The RLS leak the Security Advisor missed in my test](docs/guides/03-logged-in-users-can-read-every-row.md)
4. [Supabase's 30 Oct 2026 change: "permission denied for table" and the one-line fix that leaks your data](docs/guides/04-oct-30-permission-denied-for-table.md)

## One report from three tools

```
karchi-guard report --scan scan.json --advisors advisors.json --rlsgrid rls.json --project "My App" --out report.md
```

This combines the scan, the Supabase Security Advisor (`supabase db advisors --type security --output-format json`) and rlsgrid (`rlsgrid check --json`) into one plain-English Markdown report with fix SQL. It shows names only, never row data.

## Want it fixed for you?

I offer a fixed-price fix: $49 for one Supabase project. I work on a local copy of your schema (never your live database), send a report and a pull request with the fixes, and re-check after. [See a sample report](docs/sample-report.md). Details: REPLACE_SITE_URL

## Tests

```
PYTHONPATH=src python3 -m unittest discover -s tests
```

End-to-end on a deliberately unsafe local Supabase (needs Docker, the Supabase CLI and rlsgrid in `.venv`):

```
cd dev && supabase start -x realtime,imgproxy,mailpit,postgres-meta,studio,edge-runtime,logflare,vector,supavisor && cd ..
GUARD_E2E=1 PYTHONPATH=src:tests python3 -m unittest tests/test_e2e.py   # writes out/e2e-report.md
```

## License

MIT. Not affiliated with Supabase, Lovable, Cursor or Anthropic. B6 reuses the rule matcher from [Rogue Drill](https://github.com/karthikkushi/nova-harbor).
