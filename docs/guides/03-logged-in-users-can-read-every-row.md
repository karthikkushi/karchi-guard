---
title: "The Supabase RLS leak the Security Advisor missed in my test: any logged-in user can read every row"
tags: supabase, postgres, security, rls
---

Here is a policy I see often in apps built with AI tools:

```sql
create policy "logged-in users read orders" on public.orders
  for select to authenticated
  using (true);
```

It looks safe because it says `to authenticated`. It is not. `using (true)` means "every row". Any person who signs up for your app can read every user's orders.

## The Security Advisor did not flag it in my test

I built a small, deliberately unsafe test database on a local Supabase (CLI 2.121.0) and ran:

```
supabase db advisors --local --type security
```

The Advisor did a good job. It flagged a table with RLS turned off, a security definer view, a function with a mutable `search_path`, and an `insert` policy with `with check (true)`.

It did **not** flag the `select ... to authenticated using (true)` policy above. That makes sense: some apps really do want every logged-in user to read a table, so a static rule cannot know if it is a bug. You have to test it with two users.

## Test it with two users (local copy only)

Run this on a local copy of your database, never on production. Make two test users and one row for each, then act as user A:

```sql
begin;
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated"}', true);

-- Rows that belong to OTHER users. This should be 0.
select count(*) from public.orders
where user_id <> '11111111-1111-1111-1111-111111111111';
rollback;
```

In my test this returned `1`. User A could see user B's order.

## The fix

Tie the policy to the row owner:

```sql
drop policy "logged-in users read orders" on public.orders;

create policy "users read their own orders" on public.orders
  for select to authenticated
  using ((select auth.uid()) = user_id);
```

After this, the same test returned `0` rows from other users, and user A still saw their own order.

Writing `(select auth.uid())` instead of `auth.uid()` lets Postgres run the function once per query instead of once per row.

## Test every table, not just one

Doing this by hand for every table is slow. [rlsgrid](https://github.com/matte97p/rlsgrid) is an open-source tool that makes test users and tries to read, add, change and delete other users' rows. Two tips from my run:

- If your rows point to `auth.users`, add `"auth"` to `schema_search_path` and remove it from the `exclude` list in `rlsgrid.toml`. Otherwise its test users are never created, every insert fails, and the result means nothing.
- If it says it skipped most of its probes, do not read "Safe" as safe.

## What I use

I combine three free checks: the Supabase Security Advisor for rules, rlsgrid for user A vs user B, and [Karchi Guard](https://github.com/karthikkushi/karchi-guard) (my open-source tool) for what an AI agent in the repo can reach. None of them proves an app is secure. Together they catch a lot.
