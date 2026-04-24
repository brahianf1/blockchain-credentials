"""Add revocation_txn_id column to portal_blockchain_anchors

Stores the on-chain transaction hash of the revocation call,
separate from the original issuance ``txn_id``.  This lets the
ledger client return the most relevant TX based on current state.

Revision ID: 005
Revises: 004
Create Date: 2026-04-24

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "portal_blockchain_anchors",
        sa.Column("revocation_txn_id", sa.String(length=128), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("portal_blockchain_anchors", "revocation_txn_id")
