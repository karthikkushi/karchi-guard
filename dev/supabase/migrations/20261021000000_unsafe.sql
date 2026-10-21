-- Deliberately UNSAFE schema, used only to test Karchi Guard on a local Supabase.
-- Never copy this into a real app.

-- 1. RLS off: anyone with the public anon key can read and write every row.
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  phone text
);

-- 2. RLS on, but the policies let anyone read and write every row.
create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references auth.users on delete cascade,
  body text
);
alter table public.notes enable row level security;
create policy "anyone can read notes" on public.notes for select using (true);
create policy "anyone can add notes" on public.notes for insert with check (true);

-- 3. Any logged-in user can read every user's orders (a common AI-built app bug).
create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references auth.users on delete cascade,
  total_cents int not null
);
alter table public.orders enable row level security;
create policy "logged-in users read orders" on public.orders for select to authenticated using (true);
create policy "users add their own orders" on public.orders for insert to authenticated with check ((select auth.uid()) = user_id);

-- 4. A safe table, for comparison.
create table public.messages (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references auth.users on delete cascade,
  body text
);
alter table public.messages enable row level security;
create policy "users read their own messages" on public.messages for select to authenticated using ((select auth.uid()) = user_id);
create policy "users add their own messages" on public.messages for insert to authenticated with check ((select auth.uid()) = user_id);

-- 5. A view that runs as its owner, so it skips RLS on orders.
create view public.order_totals as
  select user_id, sum(total_cents) as total_cents from public.orders group by user_id;

-- 6. A security definer function that anyone can call, with no fixed search_path.
create function public.all_phones() returns setof text
  language sql security definer
  as $$ select phone from public.profiles $$;

-- 7. A public storage bucket that anyone can list.
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
create policy "anyone can list avatars" on storage.objects for select using (bucket_id = 'avatars');
