
"""preserve historical audit actor ids

Revision ID: ed28e992c911
Revises: 001_initial_schema
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "ed28e992c911"
down_revision: Union[str, None] = "001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Preserve historical actor UUIDs independently of user account lifetime.
    # This drops the foreign key only; it does not modify audit rows.
    op.drop_constraint(
        "audit_logs_actor_id_fkey",
        "audit_logs",
        type_="foreignkey",
    )


def downgrade() -> None:
    # Recreate the FK only if every non-null historical actor still exists.
    bind = op.get_bind()
    has_orphans = bind.execute(
        sa.text("""
            SELECT EXISTS (
                SELECT 1
                FROM audit_logs a
                LEFT JOIN users u ON u.id = a.actor_id
                WHERE a.actor_id IS NOT NULL
                  AND u.id IS NULL
            )
        """)
    ).scalar()

    if has_orphans:
        raise RuntimeError(
            "Cannot restore the audit actor foreign key: "
            "historical actor IDs no longer exist in users."
        )

    op.create_foreign_key(
        "audit_logs_actor_id_fkey",
        "audit_logs",
        "users",
        ["actor_id"],
        ["id"],
        ondelete="SET NULL",
    )
