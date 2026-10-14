-- Creates the application's database and a limited login role for it.
-- Run through scripts/setup-db.ps1 (it supplies :pw). Safe to run again.

-- 1. A role for the application: can log in, but is NOT a superuser and
--    cannot create other databases or roles (least privilege).
SELECT 'CREATE ROLE secanalyst_app'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'secanalyst_app') \gexec

ALTER ROLE secanalyst_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'pw';

-- 2. A database owned by that role, so Flyway can create tables in it.
SELECT 'CREATE DATABASE secanalyst OWNER secanalyst_app'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'secanalyst') \gexec

-- 3. Nobody else may connect to it.
REVOKE ALL ON DATABASE secanalyst FROM PUBLIC;
