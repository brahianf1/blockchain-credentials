"""Create portal_credential_visibility table.

Revision ID: 003
Revises: 002
"""

from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "portal_credential_visibility",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("moodle_user_id", sa.Integer(), nullable=False, index=True),
        sa.Column("credential_hash", sa.String(64), nullable=False, index=True),
        sa.Column("is_public", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "moodle_user_id",
            "credential_hash",
            name="uq_visibility_user_hash",
        ),
    )


def downgrade() -> None:
    op.drop_table("portal_credential_visibility")
