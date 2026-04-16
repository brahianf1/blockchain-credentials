"""Create portal_students table

Revision ID: 001
Revises: None
Create Date: 2026-04-16

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "portal_students",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("moodle_user_id", sa.BigInteger(), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("full_name", sa.String(200), nullable=False),
        sa.Column("password_hash", sa.String(128), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_portal_students_moodle_user_id", "portal_students", ["moodle_user_id"], unique=True)
    op.create_index("ix_portal_students_email", "portal_students", ["email"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_portal_students_email", table_name="portal_students")
    op.drop_index("ix_portal_students_moodle_user_id", table_name="portal_students")
    op.drop_table("portal_students")
