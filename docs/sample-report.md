> **Sample report.** This is real output from a deliberately unsafe demo app built for testing: fake keys, made-up tables, no real users. A $49 fix includes a report like this for your project, plus a pull request with the fixes.

# Supabase safety report: Unsafe demo app

2026-10-21 · Prepared with Karchi Guard

## Summary

| How bad | Count |
|---|---|
| CRITICAL | 4 |
| HIGH | 8 |
| MEDIUM | 3 |
| LOW | 0 |

**If an AI agent in this repo goes wrong, it has enough access to:**

- read every row in every table (B1 .env:2)
- change or delete every row (B1 .env:2)
- run any SQL, including DROP TABLE (B2 .mcp.json:7)
- delete the whole project, and its backups with it (B2 .mcp.json:7)
- reach every project in your Supabase account (B2 .mcp.json:7)

## What to fix first

| # | How bad | What | Where |
|---|---|---|---|
| 1 | CRITICAL | Security Definer View | `public.order_totals` |
| 2 | CRITICAL | RLS Disabled in Public | `public.profiles` |
| 3 | CRITICAL | Supabase personal access token (sbp_) | `.mcp.json:7` |
| 4 | CRITICAL | A logged-out visitor can read other users' rows | `public.notes` |
| 5 | HIGH | Supabase service_role / secret key | `.env:2` |
| 6 | HIGH | Supabase MCP server 'supabase' is not read-only | `.mcp.json:3` |
| 7 | HIGH | Supabase MCP server 'supabase' is not limited to one project | `.mcp.json:3` |
| 8 | HIGH | Claude Code would not stop: supabase db reset --linked | `.claude/settings.json` |
| 9 | HIGH | Claude Code would not stop: supabase projects delete abcdefghijklmnopqrst | `.claude/settings.json` |
| 10 | HIGH | Claude Code can read .env | `.claude/settings.json` |
| 11 | HIGH | A logged-in user can read other users' rows | `public.notes` |
| 12 | HIGH | A logged-in user can read other users' rows | `public.orders` |
| 13 | MEDIUM | Function Search Path Mutable | `public.all_phones` |
| 14 | MEDIUM | RLS Policy Always True | `public.notes` |
| 15 | MEDIUM | No off-site backup found in this repo | `(whole repo)` |

## Details

### 1. [CRITICAL] Security Definer View

**Where:** `public.order_totals` · found by Advisor

**What is wrong:** View `public.order_totals` is defined with the SECURITY DEFINER property

**Why it matters:** This view runs with the owner's rights, so it skips RLS and can show every user's rows.

**Fix:**

```sql
alter view public.order_totals set (security_invoker = on);
```

### 2. [CRITICAL] RLS Disabled in Public

**Where:** `public.profiles` · found by Advisor

**What is wrong:** Table `public.profiles` is public, but RLS has not been enabled.

**Why it matters:** Anyone with your public anon key (it is in your website's code) can read and change every row.

**Fix:**

```sql
alter table public.profiles enable row level security;
-- Then let each user see only their own rows, for example:
create policy "own rows" on public.profiles for select to authenticated
  using ((select auth.uid()) = user_id);
```

### 3. [CRITICAL] Supabase personal access token (sbp_)

**Where:** `.mcp.json:7` · found by B2

**What is wrong:** Supabase personal access token (sbp_).

**Why it matters:** This token can manage every project in your account, including deleting one. Deleting a project also deletes its backups. It is not committed, but any AI agent working in this folder can read it.

**Fix:**

Revoke it at supabase.com/dashboard/account/tokens. For MCP, use the browser login (OAuth) or an ${ENV} reference, together with project_ref and read_only=true.

### 4. [CRITICAL] A logged-out visitor can read other users' rows

**Where:** `public.notes` · found by rlsgrid

**What is wrong:** rlsgrid made test users on a local copy. A logged-out visitor (anon) could read rows that belong to another user.

**Why it matters:** One user can see or change another user's private data.

**Fix:**

```sql
-- Find the select policy on public.notes that allows this, then tie it to the row owner:
drop policy "<policy name>" on public.notes;
create policy "own rows only" on public.notes for select to authenticated
  using ((select auth.uid()) = user_id);
```

### 5. [HIGH] Supabase service_role / secret key

**Where:** `.env:2` · found by B1

**What is wrong:** Supabase service_role / secret key.

**Why it matters:** This key skips every RLS rule. It is not committed, but any AI agent working in this folder can read it.

**Fix:**

Rotate the key in Supabase (Project Settings > API Keys). Keep the new one only in server-side secrets your agent cannot read, never in a VITE_ or NEXT_PUBLIC_ variable.

### 6. [HIGH] Supabase MCP server 'supabase' is not read-only

**Where:** `.mcp.json:3` · found by B3

**What is wrong:** Supabase MCP server 'supabase' is not read-only.

**Why it matters:** Your agent can run any SQL through it: change data or drop tables. Most tools ask before each call, but one wrong click, or a prompt hidden in your data, is enough.

**Fix:**

Add read_only=true to the URL, for example https://mcp.supabase.com/mcp?project_ref=<ref>&read_only=true (or --read-only for the npx server). Keep a separate entry without read_only only for the rare times you need writes.

### 7. [HIGH] Supabase MCP server 'supabase' is not limited to one project

**Where:** `.mcp.json:3` · found by B4

**What is wrong:** Supabase MCP server 'supabase' is not limited to one project.

**Why it matters:** Without project_ref the server turns on account tools, so your agent can reach every project in your account: list, create, pause and query them.

**Fix:**

Add project_ref=<your project ref> to the URL (or --project-ref=<ref> for the npx server).

### 8. [HIGH] Claude Code would not stop: supabase db reset --linked

**Where:** `.claude/settings.json` · found by B6

**What is wrong:** Claude Code would not stop: supabase db reset --linked.

**Why it matters:** This would wipe the live database linked to this folder (if this machine is logged in to Supabase). Status: runs, because allowed without asking by Bash(supabase:*).

**Fix:**

Add "Bash(supabase db reset:*)" to permissions.deny in .claude/settings.json.

### 9. [HIGH] Claude Code would not stop: supabase projects delete abcdefghijklmnopqrst

**Where:** `.claude/settings.json` · found by B6

**What is wrong:** Claude Code would not stop: supabase projects delete abcdefghijklmnopqrst.

**Why it matters:** This would delete a Supabase project and its backups (if this machine is logged in to Supabase). Status: runs, because allowed without asking by Bash(supabase:*).

**Fix:**

Add "Bash(supabase projects delete:*)" to permissions.deny in .claude/settings.json.

### 10. [HIGH] Claude Code can read .env

**Where:** `.claude/settings.json` · found by B6

**What is wrong:** Claude Code can read .env.

**Why it matters:** That file holds the keys listed above. Status: runs, because Claude Code reads files without asking by default.

**Fix:**

Add "Read(**/.env*)" to permissions.deny in .claude/settings.json.

### 11. [HIGH] A logged-in user can read other users' rows

**Where:** `public.notes` · found by rlsgrid

**What is wrong:** rlsgrid made test users on a local copy. A logged-in user (authenticated) could read rows that belong to another user.

**Why it matters:** One user can see or change another user's private data.

**Fix:**

```sql
-- Find the select policy on public.notes that allows this, then tie it to the row owner:
drop policy "<policy name>" on public.notes;
create policy "own rows only" on public.notes for select to authenticated
  using ((select auth.uid()) = user_id);
```

### 12. [HIGH] A logged-in user can read other users' rows

**Where:** `public.orders` · found by rlsgrid

**What is wrong:** rlsgrid made test users on a local copy. A logged-in user (authenticated) could read rows that belong to another user.

**Why it matters:** One user can see or change another user's private data.

**Fix:**

```sql
-- Find the select policy on public.orders that allows this, then tie it to the row owner:
drop policy "<policy name>" on public.orders;
create policy "own rows only" on public.orders for select to authenticated
  using ((select auth.uid()) = user_id);
```

### 13. [MEDIUM] Function Search Path Mutable

**Where:** `public.all_phones` · found by Advisor

**What is wrong:** Function `public.all_phones` has a role mutable search_path

**Why it matters:** The function's search_path can be changed by the caller, which can make it run the wrong code.

**Fix:**

```sql
alter function public.all_phones set search_path = '';
```

### 14. [MEDIUM] RLS Policy Always True

**Where:** `public.notes` · found by Advisor

**What is wrong:** Table `public.notes` has an RLS policy `anyone can add notes` for `INSERT` that allows unrestricted access (WITH CHECK clause is always true). This effectively bypasses row-level security for -.

**Why it matters:** This policy's check is always true, so anyone it applies to can insert any row.

**Fix:**

```sql
drop policy "anyone can add notes" on public.notes;
create policy "anyone can add notes" on public.notes for insert to authenticated
  with check ((select auth.uid()) = user_id);  -- check the owner column name
```

### 15. [MEDIUM] No off-site backup found in this repo

**Where:** `(whole repo)` · found by B7

**What is wrong:** No off-site backup found in this repo.

**Why it matters:** Supabase keeps backups inside the project. If the project is deleted, by a person or an agent, its backups are deleted with it. We found no pg_dump or 'supabase db dump' job here.

**Fix:**

Add a daily job (for example a GitHub Action) that runs 'supabase db dump' and stores the file outside Supabase, such as a private S3 or R2 bucket.

## What was checked

- Agent blast-radius scan of the repo (Karchi Guard): 8 findings
- Supabase Security Advisor, security lints: 4 findings
- rlsgrid cross-user test on a local copy of the database: 3 leaks, 94 of 300 probes skipped

## What was not checked

- Keys in old git commits: run gitleaks
- Cursor and Windsurf command allowlists (they live in the app, not in the repo)
- What an agent actually does at run time

---

This report lists what was checked and what was found. It does not prove the app is secure.
It shows only table names, column names and counts. No user data was copied.
