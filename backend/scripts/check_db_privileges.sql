
-- TrustVault production privilege verification
-- Run against the production "trustvault" database using a PostgreSQL
-- account authorized to inspect role and object privileges.
-- Read-only checks: this script does not modify database objects or data.

SELECT
    current_database() AS database_name,
    current_user AS inspection_user;

-- Runtime application role must not be a superuser, create databases,
-- or create roles.
SELECT
    rolname,
    rolsuper,
    rolcreatedb,
    rolcreaterole,
    rolcanlogin
FROM pg_roles
WHERE rolname = 'trustvault_app';

-- Runtime application role should not be able to create objects
-- in the public schema.
SELECT
    has_schema_privilege(
        'trustvault_app', 'public', 'USAGE'
    ) AS schema_usage,
    has_schema_privilege(
        'trustvault_app', 'public', 'CREATE'
    ) AS schema_create;

-- Runtime application role must not be able to modify or delete
-- audit records, or truncate the audit table.
SELECT
    has_table_privilege(
        'trustvault_app', 'public.audit_logs', 'SELECT'
    ) AS audit_select,
    has_table_privilege(
        'trustvault_app', 'public.audit_logs', 'INSERT'
    ) AS audit_insert,
    has_table_privilege(
        'trustvault_app', 'public.audit_logs', 'UPDATE'
    ) AS audit_update,
    has_table_privilege(
        'trustvault_app', 'public.audit_logs', 'DELETE'
    ) AS audit_delete,
    has_table_privilege(
        'trustvault_app', 'public.audit_logs', 'TRUNCATE'
    ) AS audit_truncate;

-- Show the owner of the audit table and its trigger function.
SELECT
    c.relname AS object_name,
    pg_get_userbyid(c.relowner) AS object_owner
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname = 'audit_logs';

SELECT
    p.proname AS function_name,
    pg_get_userbyid(p.proowner) AS function_owner
FROM pg_proc AS p
JOIN pg_namespace AS n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.proname = 'trg_prevent_audit_log_modification';
