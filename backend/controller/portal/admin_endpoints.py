from fastapi import APIRouter

admin_router = APIRouter(prefix="/admin/blockchain", tags=["Admin · Blockchain"])

@admin_router.post("/bootstrap")
async def bootstrap_blockchain():
    return {
        "issuer_did": "did:solidity:smartcontract",
        "network": "besu-evm",
        "schema_id": "none",
        "cred_def_id": "none",
        "supports_revocation": True,
        "schema": {
            "kind": "schema",
            "artifact_id": "none",
            "outcome": "skipped",
            "seq_no": 0
        },
        "cred_def": {
            "kind": "cred_def",
            "artifact_id": "none",
            "outcome": "skipped",
            "seq_no": 0
        },
        "rev_reg": None,
        "rev_reg_id": "none",
        "rev_reg_max_cred_num": 1000,
        "rev_reg_issuance_type": "none"
    }

@admin_router.get("/status")
def blockchain_status():
    return {
        "issuer_did": "did:solidity:smartcontract",
        "network": "besu-evm",
        "schema": None,
        "cred_def": None,
        "rev_reg": None,
    }
