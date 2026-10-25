
"""Add explicit audit hash versioning without changing historical hashes.

Revision ID: aad08b3e7823
Revises: ed28e992c911
"""

from datetime import timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "aad08b3e7823"
down_revision: Union[str, None] = "ed28e992c911"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _record_hash(row, version: int) -> str:
    from app.models.audit_log import AuditLog

    timestamp = row["timestamp"]
    if timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(timezone.utc)

    common = {
        "prev_hash": row["prev_hash"],
        "timestamp": timestamp,
        "request_id": row["request_id"],
        "actor_id": row["actor_id"],
        "action": row["action"],
        "target_type": row["target_type"],
        "target_id": row["target_id"],
        "result": row["result"],
        "denial_reason": row["denial_reason"],
        "metadata_json": row["metadata_json"],
    }

    if version == 1:
        return AuditLog.calculate_record_hash(**common)

    if version == 2:
        return AuditLog.calculate_record_hash(
            **common,
            actor_email=row["actor_email"],
            actor_ip=row["actor_ip"],
            user_agent=row["user_agent"],
        )

    raise ValueError(f"Unsupported audit hash version: {version}")


def upgrade() -> None:
    bind = op.get_bind()

    # Temporarily remove the immutable-row trigger for the controlled
    # hash-version backfill. Transactional DDL protects the rollback.
    op.execute(
        "DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs"
    )

    op.add_column(
        "audit_logs",
        sa.Column("hash_version", sa.Integer(), nullable=True),
    )

    rows = bind.execute(
        sa.text("""
            SELECT
                id, request_id, actor_id, actor_email, actor_ip,
                user_agent, action, target_type, target_id, result,
                denial_reason, metadata_json, prev_hash, record_hash,
                timestamp
            FROM audit_logs
            ORDER BY timestamp ASC, id ASC
        """)
    ).mappings().all()

    update_version = sa.text("""
        UPDATE audit_logs
        SET hash_version = :version
        WHERE id = :id
    """)

    for row in rows:
        matches = [
            version
            for version in (1, 2)
            if _record_hash(row, version) == row["record_hash"]
        ]

        if len(matches) != 1:
            raise RuntimeError(
                "Cannot safely classify audit record "
                f"{row['id']}: expected exactly one matching hash "
                f"algorithm, found {matches}. Migration aborted."
            )

        bind.execute(
            update_version,
            {"version": matches[0], "id": row["id"]},
        )

    op.alter_column(
        "audit_logs",
        "hash_version",
        existing_type=sa.Integer(),
        nullable=False,
        server_default=sa.text("2"),
    )

    op.execute("""
        CREATE TRIGGER trg_audit_logs_immutable
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION
            trg_prevent_audit_log_modification();
    """)


def downgrade() -> None:
    op.drop_column("audit_logs", "hash_version")
