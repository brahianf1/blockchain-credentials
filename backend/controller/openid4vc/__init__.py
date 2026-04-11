"""
OpenID4VC Module - Modular Implementation
Complete OpenID4VCI 1.0 implementation with dual flow support
"""

from .config import (
    ISSUER_URL,
    ISSUER_DID,
    PRIVATE_KEY,
    PUBLIC_KEY,
    PUBLIC_KEY_JWK,
    CredentialOfferRequest,
    OpenIDCredentialRequest
)

from .helpers import (
    add_security_headers,
    extract_holder_did_from_proof,
    extract_issuer_state_from_par
)

__all__ = [
    "ISSUER_URL",
    "ISSUER_DID",
    "PRIVATE_KEY",
    "PUBLIC_KEY",
    "PUBLIC_KEY_JWK",
    "CredentialOfferRequest",
    "OpenIDCredentialRequest",
    "add_security_headers",
    "extract_holder_did_from_proof",
    "extract_issuer_state_from_par"
]
