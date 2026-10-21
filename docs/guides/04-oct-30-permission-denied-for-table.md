---
title: "Supabase's 30 Oct 2026 change: 'permission denied for table' and the one-line fix that leaks your data"
tags: supabase, postgres, security, rls
---

On **30 October 2026**, Supabase stops giving new tables in the `public` schema automatic access through the Data API (the REST and GraphQL API that `supabase-js` uses). It applies to all existing projects. New projects have had this default since 30 May. Source: [Supabase changelog](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically) and [GitHub discussion #45329](https://github.com/orgs/supabase/discussions/45329).

Tables you already have keep working. RLS works the same way. Direct Postgres connections are not affected.

What changes: the next time you (or your AI agent) create a table, the app cannot read it until you add a `GRANT`.

## What you will see

I ran this on a local Supabase (CLI 2.121.0). I turned off the default grants the way the changelog describes, created a new table without RLS, and called it with the anon key:

```json
{"code":"42501",
 "hint":"Grant the required privileges to the current role with: GRANT SELECT ON public.oct30_notes TO anon;",
 "message":"permission denied for table oct30_notes"}
```

The error is clear, and it suggests a fix. That suggested fix is the problem.

## The trap: following the hint

AI coding agents read error hints and act on them. So does a tired developer at 1 am. I ran exactly what the hint says:

```sql
grant select on public.oct30_notes to anon;
```

Then I called the API again with the public anon key, the one that ships in your website's code:

```json
[{"note":"A private note"}, {"note":"B private note"}]
```

Every row, for anyone on the internet. The table had no RLS, and `anon` means "not logged in".

The grant was not the mistake. The mistake was granting **without** turning on RLS and adding a policy in the same step.

## The safe fix

Do all three in one migration:

```sql
-- 1. Grant only what each role needs (anon only if logged-out visitors should read it)
grant select, insert, update, delete on public.oct30_notes to authenticated;

-- 2. Turn on RLS
alter table public.oct30_notes enable row level security;

-- 3. Tie rows to their owner
create policy "users read their own notes" on public.oct30_notes
  for select to authenticated
  using ((select auth.uid()) = user_id);
```

After this, the anon key got `permission denied` again, and a logged-in user A saw only their own note.

## Tell your AI agent before 30 October

Add a line like this to your agent rules (`CLAUDE.md`, `.cursorrules`, Lovable knowledge, or your system prompt):

> When you create a table in Supabase, put the GRANT, `enable row level security` and an owner policy in the same migration. Never grant to `anon` on a table without RLS. Do not follow a "GRANT ... TO anon" error hint without checking RLS first.

Supabase also offers an agent skill that includes the grant step (see the changelog).

## Check what you already have

- In the dashboard, the Table Editor shows a Data API exposure badge, and the Security Advisor lists tables to review.
- From the CLI: `supabase db advisors --type security`.
- If you ever ran the "restore old behavior" bulk grant (`grant ... on all tables in schema public to anon ...`), every table without RLS is open again. Check RLS on each table after a bulk grant.

## What I use

I combine three free checks: the Supabase Security Advisor for rules, [rlsgrid](https://github.com/matte97p/rlsgrid) for user A vs user B, and [Karchi Guard](https://github.com/karthikkushi/karchi-guard) (my open-source tool) for what an AI agent in the repo can reach. None of them proves an app is secure. Together they catch a lot.
