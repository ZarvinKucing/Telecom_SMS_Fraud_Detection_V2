"""Fail-closed checks for runtime database identities."""
from __future__ import annotations

from sqlalchemy import Engine, text


class RuntimeRoleError(RuntimeError):
    """The configured database role has owner, DDL, or audit mutation powers."""


_PRIVILEGE_CHECK = text("""
SELECT r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolreplication, r.rolbypassrls,
       has_database_privilege(current_user, current_database(), 'CREATE') AS db_create,
       has_database_privilege(current_user, current_database(), 'TEMP') AS db_temp,
       has_schema_privilege(current_user, 'public', 'CREATE') AS schema_create,
       EXISTS (
           SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public' AND c.relowner = r.oid
             AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
       ) AS owns_public_object,
       (
           pg_has_role(r.oid, 'pg_database_owner', 'MEMBER')
           OR EXISTS (
               SELECT 1 FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
                 AND pg_has_role(r.oid, c.relowner, 'MEMBER')
           )
           OR EXISTS (
               SELECT 1 FROM pg_roles privileged
               WHERE privileged.rolname IN (
                   'pg_read_all_data', 'pg_write_all_data', 'pg_read_server_files',
                   'pg_write_server_files', 'pg_execute_server_program', 'pg_signal_backend',
                   'pg_monitor', 'pg_checkpoint', 'pg_create_subscription',
                   'pg_use_reserved_connections', 'pg_maintain'
               )
                 AND pg_has_role(r.oid, privileged.oid, 'MEMBER')
           )
       ) AS owner_or_privileged_role_member,
       has_table_privilege(current_user, 'public.audit_log', 'UPDATE') AS audit_update,
       has_table_privilege(current_user, 'public.audit_log', 'DELETE') AS audit_delete,
       has_table_privilege(current_user, 'public.audit_log', 'TRUNCATE') AS audit_truncate
FROM pg_roles r
WHERE r.rolname = current_user
""")


def verify_runtime_role(engine: Engine) -> None:
    """Reject runtime identities with superuser, DDL, ownership, or audit rewrite access."""
    with engine.connect() as conn:
        row = conn.execute(_PRIVILEGE_CHECK).mappings().one()
    if any(bool(value) for value in row.values()):
        raise RuntimeRoleError("runtime database role exceeds the required least-privilege policy")
