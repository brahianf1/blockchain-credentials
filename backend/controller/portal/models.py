from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.sql import func

from portal.database import Base


class PortalStudent(Base):
    __tablename__ = "portal_students"

    id = Column(Integer, primary_key=True, index=True)
    moodle_user_id = Column(Integer, unique=True, nullable=False, index=True)
    email = Column(String(254), unique=True, nullable=False, index=True)
    full_name = Column(String(200), nullable=False)
    password_hash = Column(String(128), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    last_login_at = Column(DateTime(timezone=True), nullable=True)


# Institutional ledger artifacts (contract addresses, deployment records).
# One row per distinct artifact registered on Hyperledger Besu by the issuer.
class LedgerArtifact(Base):
    __tablename__ = "portal_ledger_artifacts"
    __table_args__ = (
        UniqueConstraint("kind", "artifact_id", name="uq_ledger_artifact_kind_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    kind = Column(String(32), nullable=False, index=True)
    artifact_id = Column(String(512), nullable=False, index=True)
    name = Column(String(128), nullable=True)
    version = Column(String(32), nullable=True)
    tag = Column(String(64), nullable=True)
    issuer_did = Column(String(128), nullable=True, index=True)
    schema_id = Column(String(512), nullable=True, index=True)
    supports_revocation = Column(Boolean, default=False, nullable=False)
    txn_id = Column(String(128), nullable=True)
    seq_no = Column(Integer, nullable=True)
    ledger_timestamp = Column(DateTime(timezone=True), nullable=True)
    extra = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# On-chain anchor for a specific credential issued by the institution.
# Populated whenever a credential hash is written to the CredentialRegistry
# smart contract on Hyperledger Besu.
class CredentialAnchor(Base):
    __tablename__ = "portal_blockchain_anchors"

    id = Column(Integer, primary_key=True, index=True)
    credential_hash = Column(String(64), unique=True, nullable=False, index=True)
    moodle_credential_id = Column(Integer, nullable=True, index=True)
    moodle_user_id = Column(Integer, nullable=True, index=True)
    moodle_course_id = Column(Integer, nullable=True, index=True)
    issuer_did = Column(String(128), nullable=True, index=True)
    schema_id = Column(String(512), nullable=True)
    cred_def_id = Column(String(512), nullable=True, index=True)
    rev_reg_id = Column(String(512), nullable=True, index=True)
    cred_rev_id = Column(String(64), nullable=True)
    txn_id = Column(String(128), nullable=True)
    seq_no = Column(Integer, nullable=True)
    ledger_timestamp = Column(DateTime(timezone=True), nullable=True)
    revoked = Column(Boolean, default=False, nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_reason = Column(String(256), nullable=True)
    anchored_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
