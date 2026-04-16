import hashlib


def compute_credential_hash(
    student_id: str,
    course_id: str,
    completion_date: str,
    grade: str,
) -> str:
    """Compute the SHA-256 hash that identifies a credential on the Fabric ledger.

    This is the single source of truth for the hash formula, used by both
    ``fabric_client.py`` (when registering credentials) and the portal API
    (when displaying/verifying credentials).
    """
    data = f"{student_id}{course_id}{completion_date}{grade}"
    return hashlib.sha256(data.encode()).hexdigest()
