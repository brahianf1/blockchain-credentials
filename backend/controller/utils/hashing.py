import hashlib


def compute_credential_hash(
    student_id: str,
    course_id: str,
    completion_date: str,
    grade: str,
) -> str:
    """Compute the canonical SHA-256 hash that identifies a credential.

    This is the single source of truth for the credential hash used by
    both the student portal API (for display and lookup) and the
    CredentialRegistry smart contract on Hyperledger Besu (which anchors
    the same hash on-chain for immutable proof of issuance).
    """
    data = f"{student_id}{course_id}{completion_date}{grade}"
    return hashlib.sha256(data.encode()).hexdigest()
