"""Add role column to portal_students

Revision ID: 004
Revises: 003
Create Date: 2026-04-23

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "portal_students",
        sa.Column(
            "role",
            sa.String(length=16),
            server_default=sa.text("'student'"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_portal_students_role",
        "portal_students",
        ["role"],
    )


def downgrade() -> None:
    op.drop_index("ix_portal_students_role", table_name="portal_students")
    op.drop_column("portal_students", "role")
