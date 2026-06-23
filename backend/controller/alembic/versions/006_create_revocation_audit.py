"""Create portal_revocation_audit table.

Append-only audit trail for credential revocations.  Each row records
who revoked a credential, when, the motive, and the on-chain transaction
hash that proves the revocation.  The admin email is denormalized and the
foreign key uses ``ON DELETE SET NULL`` so audit records are never lost.

Revision ID: 006
Revises: 005
Create Date: 2026-06-23

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "portal_revocation_audit",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("credential_hash", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=256), nullable=False),
        sa.Column("revocation_txn_id", sa.String(length=128), nullable=True),
        sa.Column("revoked_by_id", sa.Integer(), nullable=True),
        sa.Column("revoked_by_email", sa.String(length=254), nullable=False),
        sa.Column(
            "revoked_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["revoked_by_id"],
            ["portal_students.id"],
            name="fk_revocation_audit_admin",
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "ix_portal_revocation_audit_credential_hash",
        "portal_revocation_audit",
        ["credential_hash"],
    )
    op.create_index(
        "ix_portal_revocation_audit_revoked_by_id",
        "portal_revocation_audit",
        ["revoked_by_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_portal_revocation_audit_revoked_by_id",
        table_name="portal_revocation_audit",
    )
    op.drop_index(
        "ix_portal_revocation_audit_credential_hash",
        table_name="portal_revocation_audit",
    )
    op.drop_table("portal_revocation_audit")
