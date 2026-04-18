"""Shared builders for the blockchain registry views.

Keep the Pydantic → domain translation for ``BlockchainRegistryResponse``
in a single place so both the public read-only endpoint and the admin
status endpoint render the registry identically.
"""
from __future__ import annotations

from typing import Optional

from blockchain import LedgerRepository, get_settings
from blockchain.repository import ArtifactKind, ArtifactRecord
from portal.database import PortalSessionLocal
from portal.schemas import BlockchainRegistryResponse, LedgerArtifactView


def build_registry_view(
    *, repository: LedgerRepository
) -> BlockchainRegistryResponse:
    """Return a snapshot of the institutional registry stored in the DB."""
    settings = get_settings()
    with PortalSessionLocal() as db:
        schemas = repository.list_artifacts(db, kind=ArtifactKind.SCHEMA)
        cred_defs = repository.list_artifacts(db, kind=ArtifactKind.CRED_DEF)
        total_anchored = repository.count_anchors(db)

    schema = schemas[0] if schemas else None
    cred_def = cred_defs[0] if cred_defs else None
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
    if not did:
        return None
    return did if did.startswith("did:") else f"did:sov:{did}"
