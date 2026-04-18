"""Create portal_ledger_artifacts and portal_blockchain_anchors tables.

Revision ID: 002
Revises: 001
Create Date: 2026-04-18

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "portal_ledger_artifacts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("artifact_id", sa.String(length=512), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=True),
        sa.Column("version", sa.String(length=32), nullable=True),
        sa.Column("tag", sa.String(length=64), nullable=True),
        sa.Column("issuer_did", sa.String(length=128), nullable=True),
        sa.Column("schema_id", sa.String(length=512), nullable=True),
        sa.Column(
            "supports_revocation",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("txn_id", sa.String(length=128), nullable=True),
        sa.Column("seq_no", sa.Integer(), nullable=True),
        sa.Column("ledger_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("extra", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("kind", "artifact_id", name="uq_ledger_artifact_kind_id"),
    )
    op.create_index(
        "ix_portal_ledger_artifacts_kind",
        "portal_ledger_artifacts",
        ["kind"],
    )
    op.create_index(
        "ix_portal_ledger_artifacts_artifact_id",
        "portal_ledger_artifacts",
        ["artifact_id"],
    )
    op.create_index(
        "ix_portal_ledger_artifacts_issuer_did",
        "portal_ledger_artifacts",
        ["issuer_did"],
    )
    op.create_index(
        "ix_portal_ledger_artifacts_schema_id",
        "portal_ledger_artifacts",
        ["schema_id"],
    )

    op.create_table(
        "portal_blockchain_anchors",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("credential_hash", sa.String(length=64), nullable=False),
        sa.Column("moodle_credential_id", sa.Integer(), nullable=True),
        sa.Column("moodle_user_id", sa.Integer(), nullable=True),
        sa.Column("moodle_course_id", sa.Integer(), nullable=True),
        sa.Column("issuer_did", sa.String(length=128), nullable=True),
        sa.Column("schema_id", sa.String(length=512), nullable=True),
        sa.Column("cred_def_id", sa.String(length=512), nullable=True),
        sa.Column("rev_reg_id", sa.String(length=512), nullable=True),
        sa.Column("cred_rev_id", sa.String(length=64), nullable=True),
        sa.Column("txn_id", sa.String(length=128), nullable=True),
        sa.Column("seq_no", sa.Integer(), nullable=True),
        sa.Column("ledger_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "revoked", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(length=256), nullable=True),
        sa.Column(
            "anchored_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("credential_hash", name="uq_blockchain_anchor_hash"),
    )
    op.create_index(
        "ix_portal_blockchain_anchors_credential_hash",
        "portal_blockchain_anchors",
        ["credential_hash"],
    )
    op.create_index(
        "ix_portal_blockchain_anchors_moodle_credential_id",
        "portal_blockchain_anchors",
        ["moodle_credential_id"],
    )
    op.create_index(
        "ix_portal_blockchain_anchors_moodle_user_id",
        "portal_blockchain_anchors",
        ["moodle_user_id"],
    )
    op.create_index(
        "ix_portal_blockchain_anchors_moodle_course_id",
        "portal_blockchain_anchors",
        ["moodle_course_id"],
    )
    op.create_index(
        "ix_portal_blockchain_anchors_issuer_did",
        "portal_blockchain_anchors",
        ["issuer_did"],
    )
    op.create_index(
        "ix_portal_blockchain_anchors_cred_def_id",
        "portal_blockchain_anchors",
        ["cred_def_id"],
    )
    op.create_index(
        "ix_portal_blockchain_anchors_rev_reg_id",
        "portal_blockchain_anchors",
        ["rev_reg_id"],
    )
    op.create_index(
        "ix_portal_blockchain_anchors_revoked",
        "portal_blockchain_anchors",
        ["revoked"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_portal_blockchain_anchors_revoked",
        table_name="portal_blockchain_anchors",
    )
    op.drop_index(
        "ix_portal_blockchain_anchors_rev_reg_id",
        table_name="portal_blockchain_anchors",
    )
    op.drop_index(
        "ix_portal_blockchain_anchors_cred_def_id",
        table_name="portal_blockchain_anchors",
    )
    op.drop_index(
        "ix_portal_blockchain_anchors_issuer_did",
        table_name="portal_blockchain_anchors",
    )
    op.drop_index(
        "ix_portal_blockchain_anchors_moodle_course_id",
        table_name="portal_blockchain_anchors",
    )
    op.drop_index(
        "ix_portal_blockchain_anchors_moodle_user_id",
        table_name="portal_blockchain_anchors",
    )
    op.drop_index(
        "ix_portal_blockchain_anchors_moodle_credential_id",
        table_name="portal_blockchain_anchors",
    )
    op.drop_index(
        "ix_portal_blockchain_anchors_credential_hash",
        table_name="portal_blockchain_anchors",
    )
    op.drop_table("portal_blockchain_anchors")

    op.drop_index(
        "ix_portal_ledger_artifacts_schema_id",
        table_name="portal_ledger_artifacts",
    )
    op.drop_index(
        "ix_portal_ledger_artifacts_issuer_did",
        table_name="portal_ledger_artifacts",
    )
    op.drop_index(
        "ix_portal_ledger_artifacts_artifact_id",
        table_name="portal_ledger_artifacts",
    )
    op.drop_index(
        "ix_portal_ledger_artifacts_kind",
        table_name="portal_ledger_artifacts",
    )
    op.drop_table("portal_ledger_artifacts")
