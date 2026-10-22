-- TrustVault Database Roles & Privilege Separation Script
-- Must be executed as a PostgreSQL superuser (e.g. postgres) during initial database setup.

-- 1. Create separated roles if they do not exist
DO
$do$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'trustvault_admin') THEN
      CREATE ROLE trustvault_admin WITH LOGIN PASSWORD 'admin_password_change_me' CREATEDB;
   END IF;
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'trustvault_app') THEN
      CREATE ROLE trustvault_app WITH LOGIN PASSWORD 'app_password_change_me' NOSUPERUSER NOCREATEDB NOCREATEROLE;
   END IF;
END
$do$;

-- 2. Databases setup
-- In PostgreSQL, database creation is typically done before running table DDL:
-- CREATE DATABASE trustvault OWNER trustvault_admin;
-- CREATE DATABASE trustvault_test OWNER trustvault_admin;

-- 3. Schema grants within target database:
GRANT CONNECT ON DATABASE trustvault TO trustvault_app;
GRANT USAGE ON SCHEMA public TO trustvault_app;

-- 4. Table grants for trustvault_app (Runtime Role)
-- Grants DML for business entities
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users TO trustvault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE documents TO trustvault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE document_permissions TO trustvault_app;

-- 5. CRITICAL: Least Privilege on audit_logs
-- trustvault_app is restricted to INSERT and SELECT only.
GRANT INSERT, SELECT ON TABLE audit_logs TO trustvault_app;
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_logs FROM trustvault_app;

-- 6. Sequence grants for any auto-generated sequences
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO trustvault_app;

-- 7. Ensure future tables created by trustvault_admin do not grant dangerous privileges by default
ALTER DEFAULT PRIVILEGES FOR ROLE trustvault_admin IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO trustvault_app;

-- Revoke UPDATE and DELETE on audit_logs specifically even in default privileges
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_logs FROM trustvault_app;
