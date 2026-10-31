"""Provision the least-privilege PostgreSQL role used by API and worker services."""

from __future__ import annotations

import os
import sys

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url


def provision_runtime_role() -> None:
    configured_url = os.environ.get("DATABASE_URL", "").strip()
    runtime_role = os.environ.get("COUNTERSTRIKE_DB_RUNTIME_ROLE", "").strip()
    runtime_password = os.environ.get("COUNTERSTRIKE_DB_RUNTIME_PASSWORD", "")
    if not configured_url or not runtime_role or not runtime_password:
        raise ValueError("Database owner URL, runtime role, and runtime password are required")

    owner_url = make_url(configured_url)
    owner_role = owner_url.username
    database_name = owner_url.database
    if not owner_role or not database_name:
        raise ValueError("DATABASE_URL must identify a database owner and database name")
    if runtime_role == owner_role:
        raise ValueError("Runtime role must be distinct from the migration owner")

    conninfo = owner_url.set(drivername="postgresql").render_as_string(hide_password=False)
    role_identifier = sql.Identifier(runtime_role)
    role_password = sql.Literal(runtime_password)
    database_identifier = sql.Identifier(database_name)
    owner_identifier = sql.Identifier(owner_role)

    with psycopg.connect(conninfo, autocommit=True) as connection:
        exists = connection.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s", (runtime_role,)
        ).fetchone()
        if exists:
            connection.execute(
                sql.SQL(
                    "ALTER ROLE {} WITH LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                ).format(role_identifier, role_password)
            )
        else:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} WITH LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                ).format(role_identifier, role_password)
            )

        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                database_identifier, role_identifier
            )
        )
        connection.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        connection.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(role_identifier))
        connection.execute(
            sql.SQL(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}"
            ).format(role_identifier)
        )
        connection.execute(
            sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}").format(
                role_identifier
            )
        )
        connection.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
                "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}"
            ).format(owner_identifier, role_identifier)
        )
        connection.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
                "GRANT USAGE, SELECT ON SEQUENCES TO {}"
            ).format(owner_identifier, role_identifier)
        )
        for immutable_table in ("audit_events", "llm_audit_access", "review_decisions"):
            connection.execute(
                sql.SQL("REVOKE UPDATE, DELETE ON TABLE public.{} FROM {}").format(
                    sql.Identifier(immutable_table), role_identifier
                )
            )
        connection.execute(
            sql.SQL("REVOKE DELETE ON TABLE public.llm_exchange_artifacts FROM {}").format(
                role_identifier
            )
        )


def main() -> None:
    try:
        provision_runtime_role()
    except Exception as error:  # Keep connection strings and SQL literals out of service logs.
        safe_error = f"Database runtime-role provisioning failed ({type(error).__name__})"
        print(safe_error, file=sys.stderr)
        raise SystemExit(1) from None
    print("Database runtime role provisioned with least-privilege grants")


if __name__ == "__main__":
    main()
