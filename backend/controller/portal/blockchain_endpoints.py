"""Public, read-only blockchain endpoints (Mocked)."""
from fastapi import APIRouter
from portal.schemas import BlockchainRegistryResponse

blockchain_public_router = APIRouter(
    prefix="/public/blockchain", tags=["Public Blockchain"]
)

@blockchain_public_router.get(
    "/registry",
    response_model=BlockchainRegistryResponse,
)
def public_registry() -> dict:
    """Return the institutional mocked registry as seen by verifiers."""
    return {
        "issuer_did": "did:solidity:smartcontract",
        "network": "besu-evm",
        "explorer_url": "https://explorer.utnpf.site",
        "schema": None,
        "cred_def": None,
        "rev_reg": None,
        "total_anchored_credentials": 0,
    }
