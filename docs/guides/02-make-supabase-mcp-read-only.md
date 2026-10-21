---
title: Make your Supabase MCP server read-only (a 2-minute fix)
tags: supabase, mcp, security, ai
---

The Supabase MCP server lets Cursor, Claude Code or Windsurf talk to your database. It is very useful. With the default settings it is also very powerful: your agent can run any SQL, and it can reach every project in your account.

Two small settings fix most of the risk.

## What the default config allows

The basic config from the docs looks like this:

```json
{
  "mcpServers": {
    "supabase": {
      "type": "http",
      "url": "https://mcp.supabase.com/mcp"
    }
  }
}
```

With this URL:

- **Writes are on.** The agent can run any SQL, including `drop table`.
- **Account tools are on.** The agent can list, create, pause and query every project in your Supabase account, not just this app.

Most clients ask before each tool call. But one wrong click is enough, and Supabase's own docs warn that a prompt hidden in your data can make the model run queries you did not want.

## The fix: two URL options

Add `project_ref` and `read_only=true`:

```json
{
  "mcpServers": {
    "supabase": {
      "type": "http",
      "url": "https://mcp.supabase.com/mcp?project_ref=YOUR_PROJECT_REF&read_only=true"
    }
  }
}
```

- `read_only=true` runs every query as a read-only Postgres user.
- `project_ref=...` limits the server to one project and turns off the account tools.

Your project ref is the part of your project URL before `.supabase.co`.

If you use the older npx server, the same options are flags:

```json
"args": ["-y", "@supabase/mcp-server-supabase@latest", "--read-only", "--project-ref=YOUR_PROJECT_REF"]
```

## Do not paste a token into the config

The hosted server logs you in with your browser (OAuth), so you do not need a personal access token. If you must use one (for example in CI), put it in an environment variable such as `${SUPABASE_ACCESS_TOKEN}`, not in the file. An `sbp_` token can delete projects in your account, and deleting a Supabase project also deletes its backups.

## Need writes sometimes?

Keep the read-only entry as your default. Add a second entry without `read_only`, point it at a development project or branch, and turn it on only when you need it.

## In Claude Code, do not auto-allow the server

If your `.claude/settings.json` has `"mcp__supabase"` in the `allow` list, Claude Code runs every Supabase tool without asking you. Remove it, or allow only the tools you are sure about.

## Check it

Karchi Guard is a free, open-source check. It reads your `.mcp.json`, `.cursor/mcp.json` and `.vscode/mcp.json` (and with `--home`, the configs in your home folder) and flags a Supabase MCP server that is not read-only or not limited to one project.

```
git clone https://github.com/karthikkushi/karchi-guard
cd karchi-guard
PYTHONPATH=src python3 -m karchi_guard scan /path/to/your/app --home
```

Sources: [Supabase MCP docs](https://supabase.com/docs/guides/getting-started/mcp), [Deleting a project](https://supabase.com/docs/guides/platform/delete-project).
