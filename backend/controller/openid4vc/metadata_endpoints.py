#!/usr/bin/env python3
"""
OpenID4VC Metadata Endpoints
All .well-known endpoints for service discovery

Toda la información de credenciales (display, claims, formatos) proviene
del ``credential_registry`` — fuente única de verdad.  Estos endpoints
solo se encargan de construir la respuesta HTTP con los headers correctos.
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import structlog

from .config import (
    ISSUER_URL,
    ISSUER_DID,
    PUBLIC_KEY_JWK
)
from .credential_registry import (
    ISSUER_DISPLAY,
    UNIVERSITY_DEGREE_CLAIMS,
    UNIVERSITY_DEGREE_DISPLAY,
    get_configurations_for_metadata,
)
from .helpers import add_security_headers

logger = structlog.get_logger()

# Router for metadata endpoints
metadata_router = APIRouter()

# ============================================================================
# OAUTH 2.0 AUTHORIZATION SERVER METADATA (RFC 8414)
# ============================================================================

@metadata_router.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata():
    """
    OAuth 2.0 Authorization Server Metadata
    RFC 8414 compliant - Requerido para descubrimiento automático de configuración
    
    NOTA: PAR endpoint removido intencionalmente para forzar flujo directo
    a /authorize, permitiendo que issuer_state llegue correctamente desde DIDRoom
    """
    logger.info("📋 Serving OAuth Authorization Server Metadata (PAR disabled)")
    
    metadata = {
        "issuer": ISSUER_URL,
        "client_name": "Universidad Tecnológica Nacional",
        "organization_name": "Universidad Tecnológica Nacional",
        "authorization_endpoint": f"{ISSUER_URL}/oid4vc/authorize",
        "token_endpoint": f"{ISSUER_URL}/oid4vc/token",
        # PAR endpoint presente para validación de wallets (DIDRoom),
        # aunque no se use en el flujo Pre-Authorized.
        "pushed_authorization_request_endpoint": f"{ISSUER_URL}/oid4vc/par",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        ],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True  # Habilitado para soporte completo PAR
    }
    
    response = JSONResponse(content=metadata)
    return await add_security_headers(response)

# ============================================================================
# OPENID CREDENTIAL ISSUER METADATA
# ============================================================================

@metadata_router.get("/.well-known/openid-credential-issuer")
async def get_credential_issuer_metadata(request: Request):
    """
    OpenID Credential Issuer Metadata — OID4VCI §11.2.3

    Toda la información de credenciales (display, claims, formatos)
    proviene del ``credential_registry`` — fuente única de verdad.
    Este endpoint solo ensambla la respuesta con la estructura
    requerida por la especificación.
    """
    logger.info("📋 Serving OpenID Credential Issuer Metadata")

    metadata = {
        "credential_issuer": ISSUER_URL,
        "client_name": "Universidad Tecnológica Nacional",
        "organization_name": "Universidad Tecnológica Nacional",
        "authorization_servers": [ISSUER_URL],
        "authorization_server": ISSUER_URL,
        "require_pushed_authorization_requests": False,
        "pre-authorized_grant_anonymous_access_supported": True,
        "credential_endpoint": f"{ISSUER_URL}/oid4vc/credential",
        "token_endpoint": f"{ISSUER_URL}/oid4vc/token",
        "nonce_endpoint": f"{ISSUER_URL}/oid4vc/nonce",
        "notification_endpoint": f"{ISSUER_URL}/oid4vc/notification",
        "jwks_uri": f"{ISSUER_URL}/oid4vc/.well-known/jwks.json",
        # Display del issuer — desde el registry (fuente única de verdad)
        "display": ISSUER_DISPLAY,
        # Configuraciones de credenciales — desde el registry
        "credential_configurations_supported": get_configurations_for_metadata(ISSUER_URL),
    }

    response = JSONResponse(content=metadata)
    return await add_security_headers(response)

# ============================================================================
# JWKS ENDPOINT
# ============================================================================

@metadata_router.get("/.well-known/jwks.json")
async def jwks_endpoint():
    """
    JSON Web Key Set (JWKS) endpoint — RFC 7517

    Sirve la clave pública real ES256 usada para firmar las credenciales,
    permitiendo que los wallets y verificadores validen las firmas JWT
    criptográficamente.  El ``kid`` coincide con el usado en los headers
    de firma de credenciales (ISSUER_DID#key-1) para que la resolución
    de claves funcione correctamente en wallets como Lissi, WaltID, EUDI, etc.
    """
    logger.info("🔑 Serving JWKS (real issuer public key)")

    jwks = {
        "keys": [
            {
                **PUBLIC_KEY_JWK,
                "use": "sig",
                "kid": f"{ISSUER_DID}#key-1",
                "alg": "ES256",
            }
        ]
    }

    response = JSONResponse(content=jwks)
    return await add_security_headers(response)

# ============================================================================
# VCT METADATA ENDPOINT (IETF SD-JWT VC §6.3)
# ============================================================================

@metadata_router.get("/vct/{vct_id}")
async def vct_metadata_endpoint(vct_id: str):
    """
    Verifiable Credential Type Metadata endpoint — IETF SD-JWT VC §6.3

    Sirve metadata del tipo de credencial cuando una wallet derreferencia
    la URL del ``vct``.  WaltID llama a ``resolveVctUrl?vct=<url>`` y espera
    un JSON con nombre, descripción, claims y display del tipo.

    Referencia: draft-ietf-oauth-sd-jwt-vc §6.3 — Type Metadata
    """
    logger.info(f"📋 Serving VCT metadata for: {vct_id}")

    # Por ahora solo soportamos UniversityDegree; extensible vía registry
    if vct_id != "UniversityDegree":
        return JSONResponse(
            status_code=404,
            content={"error": "vct_not_found", "vct": vct_id},
        )

    vct_metadata = {
        "vct": f"{ISSUER_URL}/oid4vc/vct/{vct_id}",
        "name": "University Certificate",
        "description": "Official credential certifying course completion at UTN.",
        "claims": UNIVERSITY_DEGREE_CLAIMS,
        "display": UNIVERSITY_DEGREE_DISPLAY,
    }

    response = JSONResponse(content=vct_metadata)
    return await add_security_headers(response)

# ============================================================================
# DID DOCUMENT ENDPOINT
# ============================================================================

@metadata_router.get("/.well-known/did.json")
async def did_document_endpoint():
    """
    DID Document para resolución de did:web (requerido por Paradym Wallet)
    Según W3C DID Core y did:web Method Specification
    https://w3c-ccg.github.io/did-method-web/
    """
    logger.info(f"📄 Serving DID Document for: {ISSUER_DID}")
    
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": ISSUER_DID,
        "verificationMethod": [
            {
                "id": f"{ISSUER_DID}#key-1",
                "type": "JsonWebKey2020",
                "controller": ISSUER_DID,
                "publicKeyJwk": PUBLIC_KEY_JWK
            }
        ],
        "assertionMethod": [f"{ISSUER_DID}#key-1"],
        "authentication": [f"{ISSUER_DID}#key-1"],
        "capabilityInvocation": [f"{ISSUER_DID}#key-1"],
        "capabilityDelegation": [f"{ISSUER_DID}#key-1"]
    }
    
    response = JSONResponse(content=did_document)
    response.headers["Content-Type"] = "application/did+json"
    return await add_security_headers(response)

# ============================================================================
# CUSTOM CONTEXT ENDPOINT
# ============================================================================

@metadata_router.get("/context/v1")
async def get_custom_context():
    """
    Endpoint para servir el contexto JSON-LD personalizado
    Define UniversityDegree y sus campos para validación correcta en wallets
    """
    logger.info("📄 Serving custom JSON-LD context")
    
    context = {
        "@context": {
            "@version": 1.1,
            "@protected": True,
            "UniversityDegree": {
                "@id": f"{ISSUER_URL}/oid4vc/context/v1#UniversityDegree",
                "@context": {
                    "student_name": "schema:name",
                    "student_id": "schema:identifier",
                    "student_email": "schema:email",
                    "course_name": "schema:course",
                    "course_id": "schema:courseCode",
                    "grade": "schema:grade",
                    "completion_date": "schema:date",
                    "university": "schema:alumniOf",
                    "instructor_name": "schema:contributor"
                }
            },
            "schema": "http://schema.org/"
        }
    }
    
    response = JSONResponse(content=context)
    return await add_security_headers(response)

# ============================================================================
# NONCE ENDPOINT
# ============================================================================

@metadata_router.post("/nonce")
@metadata_router.get("/nonce")
async def nonce_endpoint():
    """
    Nonce Endpoint según OpenID4VCI spec
    Genera c_nonce para proof JWT freshness
    """
    import secrets
    
    c_nonce = secrets.token_urlsafe(32)
    logger.info(f"🔐 Nonce generado: {c_nonce[:10]}...")
    
    response_data = {
        "c_nonce": c_nonce,
        "c_nonce_expires_in": 300
    }
    
    response = JSONResponse(content=response_data)
    response.headers["Cache-Control"] = "no-store"
    
    return await add_security_headers(response)

# ============================================================================
# DEBUG ENDPOINT - Verificar la configuración actual
# ============================================================================

@metadata_router.get("/debug/metadata-config")
async def debug_metadata_config():
    """
    DEBUG: Muestra qué configuración de metadata está activa
    Útil para verificar que los cambios se desplegaron correctamente
    """
    logger.info("🔍 Debug metadata config requested")
    
    # Simular el metadata que se está sirviendo
    oauth_metadata_sample = {
        "issuer": ISSUER_URL,
        "authorization_endpoint": f"{ISSUER_URL}/oid4vc/authorize",
        "token_endpoint": f"{ISSUER_URL}/oid4vc/token",
        # PAR HABILITADO (Metadata only)
        "pushed_authorization_request_endpoint": f"{ISSUER_URL}/oid4vc/par",
        "request_uri_parameter_supported": True
    }
    
    return {
        "status": "PAR_METADATA_ENABLED_PRE_AUTH_FORCED",
        "version": "2.1.0-didroom-fix",
        "deployed_at": "2025-11-28T06:25:00",
        "par_endpoint_enabled": True,
        "request_uri_supported": True,
        "oauth_metadata_sample": oauth_metadata_sample,
        "explanation": "PAR endpoint visible en metadata para validación. Credential Offer fuerza Pre-Auth flow."
    }
