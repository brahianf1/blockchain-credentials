"""Shared builders for the blockchain registry views.

Keep the Pydantic → domain translation for ``BlockchainRegistryResponse``
in a single place so both the public read-only endpoint and the admin
status endpoint render the registry identically.
"""
from __future__ import annotations

from typing import Optional

from blockchain import LedgerRepository, get_settings
from blockchain.did_utils import to_sov_did
from blockchain.repository import ArtifactKind, ArtifactRecord
from portal.database import PortalSessionLocal
from portal.schemas import (
    BlockchainRegistryResponse,
    LedgerArtifactView,
    RevRegView,
)


def build_registry_view(
    *, repository: LedgerRepository
) -> BlockchainRegistryResponse:
    """Return a snapshot of the institutional registry stored in the DB."""
    settings = get_settings()
    with PortalSessionLocal() as db:
        schemas = repository.list_artifacts(db, kind=ArtifactKind.SCHEMA)
        cred_defs = repository.list_artifacts(db, kind=ArtifactKind.CRED_DEF)
        rev_regs = repository.list_artifacts(db, kind=ArtifactKind.REV_REG_DEF)
        total_anchored = repository.count_anchors(db)

    schema = schemas[0] if schemas else None
    cred_def = cred_defs[0] if cred_defs else None
    rev_reg = rev_regs[0] if rev_regs else None
    issuer_did = normalize_did_sov(
        (schema.issuer_did if schema else None)
        or (cred_def.issuer_did if cred_def else None)
    )

    return BlockchainRegistryResponse(
        network=settings.network_name,
        issuer_did=issuer_did,
        explorer_url=settings.explorer_url,
        schema=artifact_to_view(
            artifact=schema,
            explorer_url=settings.explorer_url,
        ),
        cred_def=artifact_to_view(
            artifact=cred_def,
            explorer_url=settings.explorer_url,
        ),
        rev_reg=rev_reg_to_view(
            artifact=rev_reg,
            explorer_url=settings.explorer_url,
        ),
        total_anchored_credentials=total_anchored,
    )


def artifact_to_view(
    *, artifact: Optional[ArtifactRecord], explorer_url: Optional[str]
) -> Optional[LedgerArtifactView]:
    if artifact is None:
        return None
    return LedgerArtifactView(
        kind=artifact.kind,
        artifact_id=artifact.artifact_id,
        name=artifact.name,
        version=artifact.version,
        tag=artifact.tag,
        issuer_did=normalize_did_sov(artifact.issuer_did),
        schema_id=artifact.schema_id,
        supports_revocation=artifact.supports_revocation,
        seq_no=artifact.seq_no,
        explorer_url=build_artifact_explorer_url(
            base=explorer_url, seq_no=artifact.seq_no
        ),
    )


def rev_reg_to_view(
    *, artifact: Optional[ArtifactRecord], explorer_url: Optional[str]
) -> Optional[RevRegView]:
    """Render a ``REV_REG_DEF`` artifact into its public view.

    The generic ``LedgerArtifact`` table uses ``schema_id`` as the parent
    cred_def reference for rev_reg rows (see ``bootstrap._persist_rev_reg``)
    and ``version`` to store ``max_cred_num`` as a string. This adapter
    unpacks those fields into the dedicated Pydantic model.
    """
    if artifact is None:
        return None
    max_cred_num: Optional[int] = None
    if artifact.version is not None:
        try:
            max_cred_num = int(artifact.version)
        except ValueError:
            max_cred_num = None
    return RevRegView(
        rev_reg_id=artifact.artifact_id,
        cred_def_id=artifact.schema_id,
        issuer_did=normalize_did_sov(artifact.issuer_did),
        tag=artifact.tag,
        max_cred_num=max_cred_num,
        issuance_type=artifact.name,
        tails_location=_tails_location_for(artifact.artifact_id),
        explorer_url=build_artifact_explorer_url(
            base=explorer_url, seq_no=artifact.seq_no
        ),
    )


def build_artifact_explorer_url(
    *, base: Optional[str], seq_no: Optional[int]
) -> Optional[str]:
    if not base:
        return None
    base = base.rstrip("/")
    if seq_no is None:
        return f"{base}/browse/domain"
    return f"{base}/browse/domain?query={seq_no}"


def normalize_did_sov(did: Optional[str]) -> Optional[str]:
    """Delegator kept for clarity at call sites; see :func:`to_sov_did`."""
    return to_sov_did(did)


def _tails_location_for(rev_reg_id: str) -> Optional[str]:
    """Best-effort public tails URL for ``rev_reg_id``.

    The tails file is served under ``<tails_server_url>/<tails_hash>``
    but the hash is only known after ACA-Py uploads it. Since we do not
    store the hash in the artifact table, we return the tails server
    base URL as a hint — full verifier wiring resolves the file via the
    rev_reg_def's ``tailsLocation`` field anyway.
    """
    settings = get_settings()
    return settings.tails_server_url or None
