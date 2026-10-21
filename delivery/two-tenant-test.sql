-- Two-tenant leak test. Run it on a LOCAL COPY only, after you seed at least two tenants
-- (two users, each linked to a different tenant, with a few rows in every table).
-- Everything runs inside one transaction that is rolled back, so this file changes nothing.
--
--   psql "$DATABASE_URL" -v user_a=<uuid> -v tenant_a=<uuid> -v tenant_col=clinic_id -f two-tenant-test.sql
--
-- tenant_col is the column that says who owns a row: clinic_id, org_id, team_id, or user_id.

\set ON_ERROR_STOP on
\pset footer off
begin;

select set_config('request.jwt.claims', json_build_object('sub', :'user_a', 'role', 'authenticated')::text, true) \g /dev/null

\echo
\echo '1. own_rows must be above 0 (proves user A is set up right; if all are 0 the test means nothing).'
\echo '   other_tenant_rows must be 0 (rows from other tenants that user A can read).'
set local role authenticated;
select format('select %L as table_name, count(*) filter (where %I = %L) as own_rows, '
              'count(*) filter (where %I is distinct from %L) as other_tenant_rows from public.%I',
              c.table_name, c.column_name, :'tenant_a', c.column_name, :'tenant_a', c.table_name)
from information_schema.columns c
join pg_tables t on t.schemaname = c.table_schema and t.tablename = c.table_name
where c.table_schema = 'public' and c.column_name = :'tenant_col'
  and has_table_privilege('authenticated', format('%I.%I', c.table_schema, c.table_name), 'select')
order by c.table_name \gexec
reset role;

\echo
\echo '2. Rows a logged-out visitor (anon) can read. Must be 0 unless the table is meant to be public.'
set local role anon;
select format('select %L as table_name, count(*) as rows_visible from public.%I', tablename, tablename)
from pg_tables
where schemaname = 'public' and has_table_privilege('anon', format('%I.%I', schemaname, tablename), 'select')
order by tablename \gexec
reset role;

\echo
\echo '3. SECURITY DEFINER functions in public. They skip RLS, so read the code of every one that anon or users can call.'
select p.oid::regprocedure as function,
       has_function_privilege('anon', p.oid, 'execute') as anon_can_call,
       has_function_privilege('authenticated', p.oid, 'execute') as users_can_call
from pg_proc p
where p.pronamespace = 'public'::regnamespace and p.prosecdef
order by 1;

rollback;
