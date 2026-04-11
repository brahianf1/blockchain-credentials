"""
OpenID4VC Module — Implementación Modular OID4VCI 1.0

Soporte dual de grants (pre-authorized_code y authorization_code)
y multi-formato de credenciales (vc+sd-jwt y jwt_vc_json).

Módulos:
    • config              — Configuración, claves criptográficas, modelos Pydantic
    • credential_registry  — Fuente única de verdad para configuraciones de credenciales
    • credential_formatters — Strategy Pattern para formatos de credenciales
    • core_endpoints       — Endpoints: offer, PAR, authorize, token, credential
    • metadata_endpoints   — Endpoints: .well-known discovery
    • helpers              — Funciones utilitarias (DID, headers, PAR)
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

from .credential_registry import (
    CREDENTIAL_CONFIGURATIONS,
    ISSUER_DISPLAY,
    get_all_config_ids,
    get_config,
    get_configurations_for_metadata,
)

from .credential_formatters import (
    resolve_format,
    format_credential,
    build_credential_response,
)

from .helpers import (
    add_security_headers,
    extract_holder_did_from_proof,
    extract_issuer_state_from_par
)

__all__ = [
    # Config
    "ISSUER_URL",
    "ISSUER_DID",
    "PRIVATE_KEY",
    "PUBLIC_KEY",
    "PUBLIC_KEY_JWK",
    "CredentialOfferRequest",
    "OpenIDCredentialRequest",
    # Registry
    "CREDENTIAL_CONFIGURATIONS",
    "ISSUER_DISPLAY",
    "get_all_config_ids",
    "get_config",
    "get_configurations_for_metadata",
    # Formatters
    "resolve_format",
    "format_credential",
    "build_credential_response",
    # Helpers
    "add_security_headers",
    "extract_holder_did_from_proof",
    "extract_issuer_state_from_par",
]
