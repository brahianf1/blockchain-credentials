#!/usr/bin/env python3
"""
OpenID4VC Metadata Endpoints
All .well-known endpoints for service discovery
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import structlog

from .config import (
    ISSUER_URL,
    ISSUER_DID,
    PUBLIC_KEY_JWK
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
    OpenID Credential Issuer Metadata
    Modo Estricto Lissi: SD-JWT
    """
    logger.info("📋 Serving OpenID Credential Issuer Metadata (STRICT LISSI MODE)")
    
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
        "display": [
            {
                "name": "Universidad Tecnológica Nacional",
                "locale": "es-AR"
            },
            {
                "name": "National Technological University",
                "locale": "en-US"
            },
            {
                "name": "National Technological University",
                "locale": "en"
            },
            {
                "name": "Universidad Tecnológica Nacional"
            }
        ],
        "credential_configurations_supported": {
            "UniversityDegree": {
                "format": "vc+sd-jwt",
                "scope": "UniversityDegreeScope",
                "vct": "UniversityDegree",
                "cryptographic_binding_methods_supported": ["did:key", "did:jwk", "jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "display": [
                    {
                        "name": "Certificado Universitario",
                        "description": "Credencial oficial que certifica la finalización de un curso.",
                        "locale": "es-AR",
                        "background_color": "#1976d2",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "uri": "https://placehold.co/150x150/1976d2/white?text=UTN",
                            "alt_text": "Logo UTN"
                        }
                    },
                    {
                        "name": "University Certificate",
                        "description": "Official credential certifying course completion.",
                        "locale": "en",
                        "background_color": "#1976d2",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "uri": "https://placehold.co/150x150/1976d2/white?text=UTN",
                            "alt_text": "UTN Logo"
                        }
                    },
                    {
                        "name": "University Certificate",
                        "description": "Official credential certifying course completion.",
                        "locale": "en-US",
                        "background_color": "#1976d2",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "uri": "https://placehold.co/150x150/1976d2/white?text=UTN",
                            "alt_text": "UTN Logo"
                        }
                    },
                    {
                        "name": "University Certificate",
                        "description": "Official credential certifying course completion.",
                        "background_color": "#1976d2",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "uri": "https://placehold.co/150x150/1976d2/white?text=UTN",
                            "alt_text": "UTN Logo"
                        }
                    }
                ],
                "claims": {
                    "student_name": {
                        "mandatory": True,
                        "display": [{"name": "Nombre / Name"}]
                    },
                    "student_id": {
                        "mandatory": False,
                        "display": [{"name": "Identificación / ID"}]
                    },
                    "student_email": {
                        "mandatory": False,
                        "display": [{"name": "Correo / Email"}]
                    },
                    "course_name": {
                        "mandatory": True,
                        "display": [{"name": "Curso / Course"}]
                    },
                    "completion_date": {
                        "mandatory": True,
                        "display": [{"name": "Fecha / Date"}]
                    },
                    "grade": {
                        "mandatory": False,
                        "display": [{"name": "Calificación / Grade"}]
                    },
                    "university": {
                        "mandatory": True,
                        "display": [{"name": "Universidad / University"}]
                    }
                }
            }
        }
    }
    
    response = JSONResponse(content=metadata)
    return await add_security_headers(response)

# ============================================================================
# JWKS ENDPOINT
# ============================================================================

@metadata_router.get("/.well-known/jwks.json")
async def jwks_endpoint():
    """
    JSON Web Key Set endpoint - requerido para validación de certificados SSL
    Compatible con Lissi Wallet y estándares de seguridad Android
    """
    logger.info("🔑 Serving JWKS")
    
    jwks = {
        "keys": [
            {
                "kty": "EC",
                "use": "sig",
                "crv": "P-256",
                "kid": "utnpf-ssl-key-2025",
                "x": "t7eP9kR5F3gN2vQ8mL6yE2nF7K9aZ3QhM2nF7vE8wL6",
                "y": "vN4xShRANCAATt7eP9kR5F3gN2vQ8mL6yE2nF7K9aZ3",
                "alg": "ES256"
            }
        ]
    }
    
    response = JSONResponse(content=jwks)
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
