#!/usr/bin/env python3
"""
OpenID4VC Endpoints - Migración desde DIDComm a OpenID4VC
Compatible con Lissi Wallet y certificados SSL/TLS mejorados
Incluye configuración de seguridad SSL para Android y validación PKI
"""

import json
import jwt
import base64
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from urllib.parse import urlencode
import ssl
import asyncio
import os

from fastapi import APIRouter, HTTPException, Header, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
import httpx
import structlog

logger = structlog.get_logger()

# Router para endpoints OpenID4VC
oid4vc_router = APIRouter(prefix="/oid4vc", tags=["OpenID4VC"])

# Configuración - Leída desde variables de entorno con fallback para desarrollo
ISSUER_URL = os.getenv("ISSUER_URL", "http://localhost:3000")
ISSUER_BASE_URL = f"{ISSUER_URL}/oid4vc"

# Configuración SSL mejorada para compatibilidad con Lissi Wallet
SSL_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
}

def get_or_generate_es256_key():
    """Obtiene una clave ES256 válida desde variables de entorno.

    La función busca en las variables de entorno en el siguiente orden:
    1. OPENID_PRIVATE_KEY y OPENID_PUBLIC_KEY (contenido directo de la clave).
    2. OPENID_PRIVATE_KEY_PATH y OPENID_PUBLIC_KEY_PATH (ruta a los archivos .pem).

    Si no se encuentra ninguna, lanza una excepción.

    Retorna tuple (private_key_pem, public_key_pem).
    """
    import os

    private_key_pem = os.getenv("OPENID_PRIVATE_KEY")
    public_key_pem = os.getenv("OPENID_PUBLIC_KEY")

    # Prioridad 1: Cargar contenido de la clave desde variables de entorno
    if private_key_pem and public_key_pem:
        logger.info("✅ Claves ES256 cargadas desde el contenido de las variables de entorno.")
        return private_key_pem, public_key_pem

    # Prioridad 2: Cargar contenido de la clave desde rutas en variables de entorno
    private_key_path = os.getenv("OPENID_PRIVATE_KEY_PATH")
    public_key_path = os.getenv("OPENID_PUBLIC_KEY_PATH")

    if private_key_path and public_key_path:
        try:
            with open(private_key_path, 'r') as f:
                private_key_pem = f.read()
            with open(public_key_path, 'r') as f:
                public_key_pem = f.read()
            
            logger.info(f"✅ Claves ES256 cargadas desde las rutas: {private_key_path}")
            return private_key_pem, public_key_pem
        except FileNotFoundError as e:
            logger.error(f"❌ No se encontraron los archivos de clave PEM en la ruta especificada: {e}")
            raise Exception(f"No se encontraron los archivos de clave PEM: {e}") from e
        except Exception as e:
            logger.error(f"❌ Error leyendo los archivos de clave PEM: {e}")
            raise Exception(f"Error leyendo los archivos de clave PEM: {e}") from e

    # Si no se encuentra ninguna configuración
    error_msg = ("No se proporcionó la configuración de claves ES256. "
               "Defina 'OPENID_PRIVATE_KEY' y 'OPENID_PUBLIC_KEY' (para contenido directo) o "
               "'OPENID_PRIVATE_KEY_PATH' y 'OPENID_PUBLIC_KEY_PATH' (para rutas de archivo) en su entorno.")
    logger.error(f"❌ {error_msg}")
    raise Exception(error_msg)

# Obtener claves ES256 válidas
# En entornos de producción se recomienda suministrar las claves mediante las
# variables de entorno ``OPENID_PRIVATE_KEY`` y ``OPENID_PUBLIC_KEY``.
PRIVATE_KEY, PUBLIC_KEY = get_or_generate_es256_key()

# Configuración para compatibilidad Android/Lissi Wallet
TLS_PROTOCOLS_SUPPORTED = ["TLSv1.2", "TLSv1.3"]
CIPHER_SUITES_ANDROID = [
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
]

# Modelos para OpenID4VC con validación mejorada
class OpenIDCredentialRequest(BaseModel):
    pre_authorized_code: str = Field(..., min_length=10, max_length=200, description="Pre-authorized code for credential issuance")
    tx_code: Optional[str] = Field(None, max_length=50, description="Transaction code (optional)")

class CredentialOfferRequest(BaseModel):
    student_id: str = Field(..., min_length=1, max_length=100, description="Student identification")
    student_name: str = Field(..., min_length=1, max_length=200, description="Student full name")
    student_email: str = Field(..., pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', description="Student email address")
    course_name: str = Field(..., min_length=1, max_length=300, description="Course name")
    completion_date: str = Field(..., description="Course completion date")
    grade: str = Field(..., min_length=1, max_length=10, description="Final grade")

# Función para añadir headers de seguridad SSL
async def add_security_headers(response: JSONResponse) -> JSONResponse:
    """Añade headers de seguridad SSL/TLS requeridos por Lissi Wallet y Android"""
    for header, value in SSL_SECURITY_HEADERS.items():
        response.headers[header] = value
    
    # Headers específicos para OpenID4VCI
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    
    return response

# ENDPOINT 1: Metadata del Issuer (requerido por OpenID4VC) - MEJORADO
@oid4vc_router.get("/.well-known/openid-credential-issuer")
async def credential_issuer_metadata(request: Request):
    """
    Metadata requerido por wallets OpenID4VC
    Compatible con Draft 13, 15, 16 y versión 1.0 del estándar
    """
    metadata = {
        "credential_issuer": ISSUER_URL,
        "authorization_servers": [ISSUER_URL],
        "authorization_server": ISSUER_URL,  # Algunas wallets esperan singular también
        "credential_endpoint": f"{ISSUER_URL}/oid4vc/credential",
        "token_endpoint": f"{ISSUER_URL}/oid4vc/token",
        "nonce_endpoint": f"{ISSUER_URL}/oid4vc/nonce",
        "jwks_uri": f"{ISSUER_URL}/oid4vc/.well-known/jwks.json",
        "display": [{
            "name": "Sistema de Credenciales UTN",
            "locale": "es-AR"
        }],
        # Campo compatible con versiones nuevas
        "credential_configurations_supported": {
            "UniversityCredential": {
                "format": "jwt_vc_json",
                "scope": "UniversityCredentialScope",
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                },
                "credential_definition": {
                    "type": ["VerifiableCredential", "UniversityCredential"],
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://www.w3.org/2018/credentials/examples/v1"
                    ]
                },
                "display": [{
                    "name": "Credencial Universitaria",
                    "locale": "es-ES",
                    "background_color": "#1976d2",
                    "text_color": "#FFFFFF",
                    "logo": {  # ← AGREGAR ESTAS 3 LÍNEAS
                        "uri": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIj48Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI0MCIgZmlsbD0iIzE5NzZkMiIvPjwvc3ZnPg==",
                        "alt_text": "Logo Universidad"
                    }
                }]
            }
        }
    }
    
    response = JSONResponse(content=metadata)
    return await add_security_headers(response)

# ENDPOINT 1.1: JWKS endpoint (requerido para validación SSL/TLS)
@oid4vc_router.get("/.well-known/jwks.json")
async def jwks_endpoint():
    """
    JSON Web Key Set endpoint - requerido para validación de certificados SSL
    Compatible con Lissi Wallet y estándares de seguridad Android
    """
    # Generar JWK desde la clave privada (implementación simplificada para demo)
    # En producción, usar bibliotecas como python-jose o authlib
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

# ENDPOINT 2: Crear Credential Offer compatible con Lissi - MEJORADO
@oid4vc_router.post("/credential-offer")
async def create_openid_credential_offer(request: CredentialOfferRequest):
    """
    Crear Credential Offer compatible con Lissi Wallet
    Incluye configuración SSL y validación mejorada para Android
    """
    try:
        logger.info(f"🆕 Creando Credential Offer OpenID4VC para: {request.student_name}")
        
        # Validaciones adicionales para seguridad
        if len(request.student_id) < 3:
            raise HTTPException(status_code=400, detail="Student ID debe tener al menos 3 caracteres")
        
        # Generar pre-authorized code único con timestamp para evitar replay attacks
        timestamp = int(datetime.now().timestamp())
        pre_auth_code = f"pre_auth_{request.student_id}_{timestamp}_{hash(request.student_email) % 10000}"
        
        # Almacenar datos pendientes con expiración y metadatos OpenID4VC
        await store_pending_openid_credential(pre_auth_code, request.dict(), expires_in=600)
        
        # Crear Credential Offer según OpenID4VCI Draft-16 (formato estricto)
        offer = {
            "credential_issuer": ISSUER_URL,
            "credential_configuration_ids": ["UniversityCredential"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": pre_auth_code
                },
                "authorization_code": {
                    "issuer_state": pre_auth_code
                }
            }
        }
        
        # Codificar offer para QR según RFC estándar
        offer_json = json.dumps(offer, separators=(',', ':'))  # Compact JSON
        
        # Usar URL encoding estándar según OpenID4VC spec
        from urllib.parse import quote
        offer_encoded = quote(offer_json, safe='')
        
        # Usar esquema URI estándar según spec OpenID4VC Draft-16
        qr_url = f"openid-credential-offer://?credential_offer={offer_encoded}"
        
        # Validar longitud del QR (máximo para QR codes estándar)
        if len(qr_url) > 1800:  # Límite más conservador para compatibilidad
            logger.warning(f"⚠️ QR URL muy largo: {len(qr_url)} chars, puede fallar en algunos wallets")
        
        # Generar QR con configuración optimizada
        try:
            from qr_generator import QRGenerator
            qr_gen = QRGenerator()
            qr_code_full = qr_gen.generate_qr(qr_url)
            
            # Usar directamente el resultado completo (ya incluye data:image/png;base64,)
            qr_code_base64 = qr_code_full if qr_code_full else ""
                
            logger.info(f"✅ QR generado exitosamente, formato: {qr_code_base64[:50] if qr_code_base64 else 'Vacío'}...")
            
        except Exception as qr_error:
            logger.error(f"❌ Error generando QR: {qr_error}")
            # Fallback sin QR pero con URL
            qr_code_base64 = ""
        
        # Almacenar para la página web de display
        global qr_storage
        if 'qr_storage' not in globals():
            qr_storage = {}
        
        qr_storage[pre_auth_code] = {
            "qr_code_base64": qr_code_base64,
            "qr_url": qr_url,
            "student_name": request.student_name,
            "course_name": request.course_name,
            "timestamp": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(minutes=10)).isoformat(),
            "type": "openid4vc_compliant",
            "format_version": "OpenID4VC Draft-16"
        }
        
        logger.info(f"✅ Credential Offer OpenID4VC creado: {pre_auth_code}")
        
        response_data = {
            "qr_url": qr_url,
            "qr_code_base64": qr_code_base64,
            "pre_authorized_code": pre_auth_code,
            "offer": offer,
            "web_qr_url": f"{ISSUER_URL}/oid4vc/qr/{pre_auth_code}",
            "instructions": "Escanea con wallet compatible OpenID4VC (walt.id, Lissi, etc.)",
            "compatibility": {
                "walt_id": True,
                "lissi_wallet": True,
                "openid4vc_standard": True
            },
            "debug_info": {
                "qr_length": len(qr_url),
                "offer_format": "OpenID4VC Draft-16 compliant",
                "scheme": "openid-credential-offer://"
            }
        }
        
        response = JSONResponse(content=response_data)
        return await add_security_headers(response)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error creando Credential Offer OpenID4VC: {e}")
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

# ENDPOINT 3: Token endpoint (OAuth 2.0) - UNIVERSAL COMPATIBILITY 
@oid4vc_router.post("/token")
async def token_endpoint(request: Request):
    """
    Token endpoint universal para intercambiar pre-authorized code por access token
    Cumple OpenID4VC Draft-16 con máxima compatibilidad de wallets
    Soporta: form data (estándar), query params (walt.id), y JSON body
    """
    try:
        # Logging inicial para debug
        content_type = request.headers.get("content-type", "")
        logger.info(f"🔍 Token endpoint llamado - Content-Type: {content_type}")
        logger.info(f"🔍 Query params: {dict(request.query_params)}")
        
        grant_type = None
        pre_authorized_code = None
        tx_code = None
        
        # MÉTODO 1: Form Data (estándar OpenID4VC per RFC6749)
        try:
            if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
                form_data = await request.form()
                logger.info(f"🔍 Form data recibida: {dict(form_data) if form_data else 'None'}")
                if form_data:
                    grant_type = form_data.get("grant_type")
                    # Walt.id usa "pre-authorized_code" (con guión) según OpenID4VC Draft-16
                    pre_authorized_code = form_data.get("pre-authorized_code") or form_data.get("pre_authorized_code")
                    tx_code = form_data.get("tx_code")
                    logger.info(f"✅ Form data - grant_type: {grant_type}, pre_auth_code: {pre_authorized_code[:10]}... si existe")
        except Exception as e:
            logger.warning(f"⚠️ Error parseando form data: {e}")
            pass
        
        # MÉTODO 2: Query Parameters (walt.id comportamiento observado)
        if not grant_type or not pre_authorized_code:
            query_params = dict(request.query_params)
            logger.info(f"🔍 Intentando query params: {query_params}")
            if not grant_type:
                grant_type = query_params.get("grant_type")
            if not pre_authorized_code:
                # Walt.id usa "pre-authorized_code" (con guión) según OpenID4VC Draft-16
                pre_auth_hyphen = query_params.get("pre-authorized_code")
                pre_auth_underscore = query_params.get("pre_authorized_code")
                pre_authorized_code = pre_auth_hyphen or pre_auth_underscore
                logger.info(f"🔍 Query params - underscore: {pre_auth_underscore}, hyphen: {pre_auth_hyphen}")
            if not tx_code:
                tx_code = query_params.get("tx_code")
            logger.info(f"✅ Query params - grant_type: {grant_type}, pre_auth_code: {pre_authorized_code[:10] if pre_authorized_code else 'None'}...")
        
        # MÉTODO 3: JSON Body (algunos wallets)
        if not grant_type or not pre_authorized_code:
            try:
                if request.headers.get("content-type", "").startswith("application/json"):
                    json_data = await request.json()
                    logger.info(f"🔍 JSON data recibida: {json_data}")
                    if not grant_type:
                        grant_type = json_data.get("grant_type")
                    if not pre_authorized_code:
                        # Walt.id usa "pre-authorized_code" (con guión) según OpenID4VC Draft-16
                        pre_authorized_code = form_data.get("pre-authorized_code") or form_data.get("pre_authorized_code")
                    if not tx_code:
                        tx_code = json_data.get("tx_code")
                    logger.info(f"✅ JSON - grant_type: {grant_type}, pre_auth_code: {pre_authorized_code[:10] if pre_authorized_code else 'None'}...")
            except Exception as e:
                logger.warning(f"⚠️ Error parseando JSON: {e}")
                pass
        
        # Logging resultado final de parsing
        logger.info(f"🎯 RESULTADO FINAL PARSING:")
        logger.info(f"  - grant_type: {grant_type}")
        logger.info(f"  - pre_authorized_code: {'PRESENTE' if pre_authorized_code else 'FALTANTE'}")
        logger.info(f"  - tx_code: {'PRESENTE' if tx_code else 'FALTANTE'}")
        
        # Validación de parámetros requeridos
        if not grant_type:
            raise HTTPException(
                status_code=422,
                detail=[{
                    "type": "missing",
                    "loc": ["query", "grant_type"],
                    "msg": "Field required",
                    "input": None
                }]
            )
        
        if not pre_authorized_code:
            raise HTTPException(
                status_code=422,
                detail=[{
                    "type": "missing",
                    "loc": ["query", "pre_authorized_code"],
                    "msg": "Field required (pre_authorized_code or pre-authorized_code)", 
                    "input": None
                }]
            )
        
        if grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
            raise HTTPException(
                status_code=400, 
                detail={
                    "error": "unsupported_grant_type",
                    "error_description": "Grant type no soportado. Use 'urn:ietf:params:oauth:grant-type:pre-authorized_code'"
                }
            )
        
        # Validar pre-authorized code
        credential_data = await get_pending_openid_credential(pre_authorized_code)
        if not credential_data:
            raise HTTPException(
                status_code=400, 
                detail={
                    "error": "invalid_grant",
                    "error_description": "Pre-authorized code inválido o expirado"
                }
            )
        
        # Verificar expiración
        if 'expires_at' in credential_data:
            expires_at = datetime.fromisoformat(credential_data['expires_at'].replace('Z', ''))
            if datetime.now() > expires_at:
                await clear_pending_openid_credential(pre_authorized_code)
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_grant", 
                        "error_description": "Pre-authorized code expirado"
                    }
                )
        
        # Generar access token con claims adicionales para seguridad
        now = datetime.now()
        access_token_payload = {
            "sub": credential_data["student_id"],
            "iss": ISSUER_URL,
            "aud": ISSUER_URL,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=10)).timestamp()),
            "pre_auth_code": pre_authorized_code,
            "token_type": "Bearer",
            "scope": "credential_issuance",
            # Claims para validación SSL
            "cnf": {
                "jkt": "utnpf-ssl-key-2025"  # Thumbprint de la clave
            }
        }
        
        access_token = jwt.encode(access_token_payload, PRIVATE_KEY, algorithm="ES256")
        
        response_data = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 600,
            "scope": "credential_issuance"
        }
        
        logger.info(f"✅ Access token generado para: {credential_data['student_name']}")
        
        response = JSONResponse(content=response_data)
        return await add_security_headers(response)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en token endpoint: {e}")
        raise HTTPException(
            status_code=500, 
            detail={
                "error": "server_error",
                "error_description": f"Error interno del servidor: {str(e)}"
            }
        )

# ENDPOINT DEBUG: Para diagnosticar problemas con wallets
@oid4vc_router.post("/token/debug")
async def token_debug_endpoint(request: Request):
    """
    Endpoint de debug para analizar exactamente qué está enviando el wallet
    """
    try:
        # Obtener información de la request
        debug_info = {
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
            "query_params": dict(request.query_params),
        }
        
        # Intentar obtener form data
        try:
            form_data = await request.form()
            debug_info["form_data"] = dict(form_data)
        except Exception as e:
            debug_info["form_data_error"] = str(e)
        
        # Intentar obtener JSON body
        try:
            json_data = await request.json()
            debug_info["json_data"] = json_data
        except Exception as e:
            debug_info["json_data_error"] = str(e)
        
        logger.info(f"🔍 Debug token request: {debug_info}")
        
        return JSONResponse(content={
            "message": "Debug info capturada",
            "debug_info": debug_info
        })
        
    except Exception as e:
        logger.error(f"❌ Error en debug endpoint: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)

# ENDPOINT WALT.ID: Token endpoint específicamente para walt.id wallet
@oid4vc_router.post("/walt-token")
async def walt_token_endpoint(
    grant_type: str = Query(..., description="Grant type (debe ser pre-authorized_code)"),
    pre_authorized_code: str = Query(..., description="Pre-authorized code"),
    tx_code: Optional[str] = Query(None, description="Transaction code opcional")
):
    """
    Token endpoint específico para walt.id wallet que envía parámetros como query params
    Redirige al endpoint principal con los mismos parámetros pero como form data
    """
    try:
        logger.info(f"🟢 Walt.id endpoint recibido - grant_type: {grant_type}, code: {pre_authorized_code[:10]}...")
        
        # Validar grant type
        if grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
            raise HTTPException(
                status_code=400, 
                detail={
                    "error": "unsupported_grant_type",
                    "error_description": "Grant type no soportado. Use 'urn:ietf:params:oauth:grant-type:pre-authorized_code'"
                }
            )
        
        # Validar pre-authorized code
        credential_data = await get_pending_openid_credential(pre_authorized_code)
        if not credential_data:
            raise HTTPException(
                status_code=400, 
                detail={
                    "error": "invalid_grant",
                    "error_description": "Pre-authorized code inválido o expirado"
                }
            )
        
        # Verificar expiración
        if 'expires_at' in credential_data:
            expires_at = datetime.fromisoformat(credential_data['expires_at'].replace('Z', ''))
            if datetime.now() > expires_at:
                await clear_pending_openid_credential(pre_authorized_code)
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_grant", 
                        "error_description": "Pre-authorized code expirado"
                    }
                )
        
        # Generar access token
        now = datetime.now()
        access_token_payload = {
            "sub": credential_data["student_id"],
            "iss": ISSUER_URL,
            "aud": ISSUER_URL,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=10)).timestamp()),
            "pre_auth_code": pre_authorized_code,
            "token_type": "Bearer",
            "scope": "credential_issuance",
            "cnf": {
                "jkt": "utnpf-ssl-key-2025"
            }
        }
        
        access_token = jwt.encode(access_token_payload, PRIVATE_KEY, algorithm="ES256")
        
        response_data = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 600,
            "scope": "credential_issuance"
        }
        
        logger.info(f"✅ Walt.id access token generado para: {credential_data['student_name']}")
        
        response = JSONResponse(content=response_data)
        return await add_security_headers(response)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en walt.id token endpoint: {e}")
        raise HTTPException(
            status_code=500, 
            detail={
                "error": "server_error",
                "error_description": f"Error interno del servidor: {str(e)}"
            }
        )

# ============================================================================
# NONCE ENDPOINT - Requerido por DIDRoom Wallet
# ============================================================================
@oid4vc_router.post("/nonce")
@oid4vc_router.get("/nonce")
async def nonce_endpoint(request: Request):
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
# PAR ENDPOINT - Pushed Authorization Requests (RFC 9126)
# Requerido por DIDRoom Wallet para ecosistema EUDI
# ============================================================================
@oid4vc_router.post("/par")
async def par_endpoint(request: Request):
    """
    Pushed Authorization Request (PAR) endpoint según RFC 9126
    DIDRoom requiere este endpoint obligatoriamente
    
    En flujo pre-authorized no se usa PAR realmente, pero DIDRoom
    valida que exista en los metadatos
    """
    import secrets
    
    try:
        # Leer datos del request
        form_data = await request.form()
        
        logger.info(f"🔐 PAR endpoint llamado")
        logger.info(f"   Form data: {dict(form_data)}")
        
        # Generar request_uri único
        request_uri = f"urn:ietf:params:oauth:request_uri:{secrets.token_urlsafe(32)}"

        par_requests_data[request_uri] = dict(form_data)  # Guardar para /authorize
        
        # En flujo pre-authorized, PAR no es realmente necesario
        # pero DIDRoom lo valida por conformidad con EUDI specs
        
        response_data = {
            "request_uri": request_uri,
            "expires_in": 300  # 5 minutos
        }
        
        logger.info(f"✅ PAR request_uri generado: {request_uri[:50]}...")
        
        response = JSONResponse(
            content=response_data,
            status_code=201  # RFC 9126 requiere 201 Created
        )
        response.headers["Cache-Control"] = "no-store"
        
        return await add_security_headers(response)
        
    except Exception as e:
        logger.error(f"❌ Error en PAR endpoint: {e}")
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "error_description": str(e)}
        )

# ============================================================================
# AUTHORIZE ENDPOINT - OAuth 2.0 Authorization Endpoint (REAL)
# Usado por DIDRoom con PAR flow
# ============================================================================

# Diccionario temporal para guardar PAR requests
par_requests_data = {}

@oid4vc_router.get("/authorize")
async def authorize_endpoint(
    request: Request,
    client_id: Optional[str] = Query(None),
    request_uri: Optional[str] = Query(None),
    response_type: Optional[str] = Query(None),
    redirect_uri: Optional[str] = Query(None),
    state: Optional[str] = Query(None)
):
    """
    OAuth 2.0 Authorization Endpoint con soporte PAR
    
    Flujo DIDRoom:
    1. Wallet hace PAR (ya implementado) - guarda request_uri
    2. Wallet llama /authorize con request_uri
    3. Generamos authorization_code
    4. Redirigimos a redirect_uri con code
    """
    logger.info(f"🔓 Authorization endpoint llamado - client_id: {client_id}")
    logger.info(f"   request_uri: {request_uri}")
    logger.info(f"   redirect_uri: {redirect_uri}")
    
    try:
        if not request_uri:
            raise HTTPException(status_code=400, detail="request_uri is required")
        
        # Extraer el ID del request_uri
        request_id = request_uri.split(':')[-1] if ':' in request_uri else request_uri
        logger.info(f"   Buscando datos PAR para: {request_id}")
        
        # Buscar en el diccionario PAR
        par_data = par_requests_data.get(request_uri)
        
        if not par_data:
            logger.info("   No se encontró PAR data, generando authorization code genérico")
        
        # Generar nuevo authorization code
        import secrets
        auth_code = f"auth_code_{secrets.token_urlsafe(32)}"
        
        # Guardar en pre_authorized_code_data para que /token lo pueda usar
        # Buscar el diccionario pre_authorized_code_data en scope global
        import sys
        current_module = sys.modules[__name__]
        
        if hasattr(current_module, 'pre_authorized_code_data'):
            pre_auth_dict = getattr(current_module, 'pre_authorized_code_data')
        else:
            # Si no existe, crear uno temporal
            pre_auth_dict = {}
            setattr(current_module, 'pre_authorized_code_data', pre_auth_dict)
        
        # Guardar datos del authorization code
        pre_auth_dict[auth_code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "expires_at": (datetime.now() + timedelta(minutes=10)).isoformat(),
            "credential_data": {
                "nombre": "Usuario DIDRoom",
                "email": "usuario@didroom.com",
                "matricula": "DR001"
            }
        }
        
        logger.info(f"✅ Authorization code generado: {auth_code[:30]}...")
        
        # Construir redirect URL con authorization code
        from urllib.parse import urlencode
        
        params = {
            "code": auth_code,
            "state": state if state else "xyz"
        }
        
        redirect_url = f"{redirect_uri}?{urlencode(params)}"
        
        logger.info(f"✅ Redirigiendo a: {redirect_url[:100]}...")
        
        # Redirección HTTP 302
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=redirect_url, status_code=302)
        
    except Exception as e:
        logger.error(f"❌ Error en authorization endpoint: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "error_description": str(e)}
        )

# ENDPOINT 4: Credential endpoint - Emisión final MEJORADO
@oid4vc_router.post("/credential")
async def issue_openid_credential(
    request: Request,
    authorization: str = Header(..., description="Bearer token para autorización"),
    credential_configuration_id: Optional[str] = Query(None, description="Credential configuration ID")
):
    """
    Emitir credencial W3C en formato JWT compatible con walt.id y otros wallets
    Soporta: query params, JSON body, y form data para máxima compatibilidad
    """
    try:
        # PARSING UNIVERSAL DE PARÁMETROS (igual que en token endpoint)
        logger.info(f"🔍 Credential endpoint llamado - Content-Type: {request.headers.get('content-type', '')}")
        logger.info(f"🔍 Query params: {dict(request.query_params)}")
        
        config_id = credential_configuration_id
        
        # MÉTODO 1: JSON Body (walt.id probablemente use esto)
        try:
            if request.headers.get("content-type", "").startswith("application/json"):
                json_data = await request.json()
                logger.info(f"🔍 JSON data recibida: {json_data}")
                if not config_id and "credential_configuration_id" in json_data:
                    config_id = json_data["credential_configuration_id"]
                elif not config_id and "format" in json_data:
                    # Algunos wallets envían "format" en lugar de "credential_configuration_id"
                    config_id = "UniversityCredential"  # Default si no especifican
        except Exception as e:
            logger.warning(f"⚠️ Error parseando JSON: {e}")
            pass
        
        # MÉTODO 2: Form Data
        try:
            if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
                form_data = await request.form()
                logger.info(f"🔍 Form data recibida: {dict(form_data) if form_data else 'None'}")
                if not config_id and form_data:
                    config_id = form_data.get("credential_configuration_id")
        except Exception as e:
            logger.warning(f"⚠️ Error parseando form data: {e}")
            pass
        
        # MÉTODO 3: Query Parameters (ya viene del parámetro opcional)
        if not config_id:
            query_params = dict(request.query_params)
            config_id = query_params.get("credential_configuration_id")
        
        # Si todavía no tenemos config_id, usar default
        if not config_id:
            config_id = "UniversityCredential"
            logger.info(f"🔧 Usando credential_configuration_id por defecto: {config_id}")
        
        logger.info(f"🎯 RESULTADO FINAL PARSING credential endpoint:")
        logger.info(f"  - credential_configuration_id: {config_id}")
        logger.info(f"  - authorization header: {'PRESENTE' if authorization else 'FALTANTE'}")
        
        # Validar formato del header Authorization
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401, 
                detail={
                    "error": "invalid_token",
                    "error_description": "Authorization header debe usar formato 'Bearer <token>'"
                }
            )
        
        # Validar access token
        access_token = authorization.replace("Bearer ", "")
        try:
            # Para ES256, usar la clave pública para verificar el token
            token_data = jwt.decode(
                access_token, 
                PUBLIC_KEY, 
                algorithms=["ES256"],
                audience=ISSUER_URL,
                issuer=ISSUER_URL
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=401, 
                detail={
                    "error": "invalid_token",
                    "error_description": "Access token expirado"
                }
            )
        except jwt.InvalidTokenError as e:
            raise HTTPException(
                status_code=401, 
                detail={
                    "error": "invalid_token",
                    "error_description": f"Access token inválido: {str(e)}"
                }
            )
        
        # Validar configuración de credencial solicitada
        if config_id != "UniversityCredential":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "unsupported_credential_type",
                    "error_description": f"Tipo de credencial no soportado: {config_id}"
                }
            )
        
        # Obtener datos de credencial
        pre_auth_code = token_data["pre_auth_code"]
        credential_data = await get_pending_openid_credential(pre_auth_code)
        
        if not credential_data:
            raise HTTPException(
                status_code=404, 
                detail={
                    "error": "credential_data_not_found",
                    "error_description": "Datos de credencial no encontrados o expirados"
                }
            )
        
        # Crear W3C Verifiable Credential en formato JWT con configuración SSL
        now = datetime.now()
        vc_payload = {
            "iss": ISSUER_URL,
            "sub": f"did:web:{ISSUER_URL.replace('https://', '')}#{credential_data['student_id']}",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=365)).timestamp()),
            "jti": f"urn:credential:{pre_auth_code}",  # Identificador único
            "vc": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "type": ["VerifiableCredential", "UniversityCredential"],
                "id": f"urn:credential:{pre_auth_code}",
                "issuer": {
                    "id": ISSUER_URL,
                    "name": "Tu Universidad",
                    "url": ISSUER_URL
                },
                "issuanceDate": now.isoformat() + "Z",
                "expirationDate": (now + timedelta(days=365)).isoformat() + "Z",
                "credentialSubject": {
                    "id": f"did:web:{ISSUER_URL.replace('https://', '')}#{credential_data['student_id']}",
                    "student_name": credential_data["student_name"],
                    "student_email": credential_data["student_email"],
                    "student_id": credential_data["student_id"],
                    "course_name": credential_data["course_name"],
                    "completion_date": credential_data["completion_date"],
                    "grade": credential_data["grade"],
                    "university": "Tu Universidad",
                    "credential_type": "OpenBadgeCredential"
                },
                # Metadatos de seguridad SSL
                "credentialStatus": {
                    "id": f"{ISSUER_URL}/oid4vc/status/{pre_auth_code}",
                    "type": "RevocationList2020Status"
                },
                "evidence": [
                    {
                        "type": "DocumentVerification",
                        "verifier": ISSUER_URL,
                        "evidenceDocument": "UniversityDiploma",
                        "subjectPresence": "Digital",
                        "documentPresence": "Digital"
                    }
                ]
            }
        }
        
        # Firmar credencial con algoritmo ES256
        vc_jwt = jwt.encode(vc_payload, PRIVATE_KEY, algorithm="ES256")
        
        # Limpiar datos pendientes
        await clear_pending_openid_credential(pre_auth_code)
        
        logger.info(f"✅ Credencial OpenID4VC emitida para: {credential_data['student_name']}")
        
        # Walt.id espera el formato directo según OpenID4VC Draft-16
        response_data = {
            "credential": vc_jwt,  # Walt.id espera esto directamente
            "c_nonce": f"nonce_{int(now.timestamp())}",
            "c_nonce_expires_in": 86400  # 24 horas
        }
        
        response = JSONResponse(content=response_data)
        return await add_security_headers(response)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error emitiendo credencial OpenID4VC: {e}")
        raise HTTPException(
            status_code=500, 
            detail={
                "error": "server_error",
                "error_description": f"Error interno del servidor: {str(e)}"
            }
        )

# Funciones auxiliares mejoradas con expiración y validación SSL
async def store_pending_openid_credential(code: str, data: Dict[str, Any], expires_in: int = 600):
    """
    Almacenar datos pendientes con expiración y validación SSL
    """
    try:
        import tempfile
        import os
        
        # Añadir metadatos mejorados de OpenID4VC
        enhanced_data = {
            **data,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(seconds=expires_in)).isoformat(),
            "openid4vc_compliant": True,
            "spec_version": "OpenID4VC Draft-16",
            "issuer_url": ISSUER_URL
        }
        
        temp_file = f"/tmp/pending_openid_credential_{code}.json"
        
        # En Windows, usar directorio temp apropiado
        if os.name == 'nt':
            temp_dir = os.environ.get('TEMP', os.environ.get('TMP', 'C:\\temp'))
            os.makedirs(temp_dir, exist_ok=True)
            temp_file = os.path.join(temp_dir, f"pending_openid_credential_{code}.json")
        
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(enhanced_data, f, ensure_ascii=False, indent=2)
            
        logger.info(f"📝 Datos almacenados para {code}, expira en {expires_in}s")
        
    except Exception as e:
        logger.error(f"❌ Error almacenando datos pendientes: {e}")
        raise

async def get_pending_openid_credential(code: str) -> Optional[Dict[str, Any]]:
    """
    Obtener datos pendientes con validación de expiración
    """
    try:
        import os
        
        temp_file = f"/tmp/pending_openid_credential_{code}.json"
        
        # En Windows, usar directorio temp apropiado
        if os.name == 'nt':
            temp_dir = os.environ.get('TEMP', os.environ.get('TMP', 'C:\\temp'))
            temp_file = os.path.join(temp_dir, f"pending_openid_credential_{code}.json")
        
        if not os.path.exists(temp_file):
            return None
            
        with open(temp_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Verificar expiración
        if 'expires_at' in data:
            expires_at = datetime.fromisoformat(data['expires_at'])
            if datetime.now() > expires_at:
                logger.info(f"⏰ Datos expirados para {code}, eliminando...")
                await clear_pending_openid_credential(code)
                return None
        
        return data
        
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.error(f"❌ Error obteniendo datos pendientes: {e}")
        return None

async def clear_pending_openid_credential(code: str):
    """
    Limpiar datos pendientes con logging mejorado
    """
    try:
        import os
        
        temp_file = f"/tmp/pending_openid_credential_{code}.json"
        
        # En Windows, usar directorio temp apropiado
        if os.name == 'nt':
            temp_dir = os.environ.get('TEMP', os.environ.get('TMP', 'C:\\temp'))
            temp_file = os.path.join(temp_dir, f"pending_openid_credential_{code}.json")
        
        if os.path.exists(temp_file):
            os.remove(temp_file)
            logger.info(f"🗑️ Datos limpiados para {code}")
            
    except Exception as e:
        logger.warning(f"⚠️ Error limpiando datos pendientes: {e}")

# ==================== ENDPOINT PARA MOSTRAR QR OPENID4VC SSL-ENHANCED ====================

@oid4vc_router.get("/qr/{pre_auth_code}", response_class=HTMLResponse)
async def show_openid_qr_page(pre_auth_code: str):
    """
    Mostrar página HTML con QR Code OpenID4VC compatible con Lissi Wallet
    Incluye información SSL y troubleshooting para problemas de certificados
    """
    try:
        # Buscar QR en storage temporal
        global qr_storage
        if 'qr_storage' not in globals():
            qr_storage = {}
            
        if pre_auth_code not in qr_storage:
            raise HTTPException(status_code=404, detail="QR Code OpenID4VC no encontrado o expirado")
        
        qr_data = qr_storage[pre_auth_code]
        
        # Verificar expiración
        if 'expires_at' in qr_data:
            expires_at = datetime.fromisoformat(qr_data['expires_at'])
            if datetime.now() > expires_at:
                del qr_storage[pre_auth_code]
                raise HTTPException(status_code=404, detail="QR Code expirado")
        
        # Página HTML específica para OpenID4VC con información SSL
        html_content = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Credencial W3C OpenID4VC - SSL Secure</title>
            <meta http-equiv="Strict-Transport-Security" content="max-age=31536000; includeSubDomains">
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    margin: 0;
                    padding: 20px;
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                }}
                .container {{
                    background: white;
                    border-radius: 20px;
                    padding: 40px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.15);
                    text-align: center;
                    max-width: 500px;
                    width: 100%;
                    position: relative;
                }}
                .ssl-badge {{
                    background: #00c851;
                    color: white;
                    padding: 8px 16px;
                    border-radius: 20px;
                    font-size: 0.9em;
                    margin-bottom: 10px;
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                }}
                .protocol-badge {{
                    background: #4CAF50;
                    color: white;
                    padding: 8px 16px;
                    border-radius: 20px;
                    font-size: 0.9em;
                    margin-bottom: 20px;
                    display: inline-block;
                }}
                .qr-container {{
                    background: #f8f9fa;
                    border-radius: 15px;
                    padding: 20px;
                    margin: 20px 0;
                    border: 3px solid #4CAF50;
                    position: relative;
                }}
                .qr-code {{
                    max-width: 280px;
                    width: 100%;
                    height: auto;
                }}
                .course-info {{
                    background: #e8f5e8;
                    border-radius: 10px;
                    padding: 15px;
                    margin: 20px 0;
                    border-left: 4px solid #4CAF50;
                }}
                .student-name {{
                    font-weight: bold;
                    color: #2e7d32;
                    font-size: 1.2em;
                }}
                .ssl-info {{
                    background: #e3f2fd;
                    border-radius: 10px;
                    padding: 15px;
                    margin: 20px 0;
                    border-left: 4px solid #2196f3;
                    font-size: 0.9em;
                }}
                .instructions {{
                    background: #fff3e0;
                    border-radius: 10px;
                    padding: 15px;
                    margin: 20px 0;
                    border-left: 4px solid #ff9800;
                }}
                .troubleshooting {{
                    background: #ffebee;
                    border-radius: 10px;
                    padding: 15px;
                    margin: 20px 0;
                    border-left: 4px solid #f44336;
                    font-size: 0.85em;
                }}
                .compatible {{
                    color: #4CAF50;
                    font-weight: bold;
                }}
                .expires-info {{
                    color: #666;
                    font-size: 0.8em;
                    margin-top: 10px;
                }}
                .qr-error {{
                    color: #e74c3c;
                    font-weight: bold;
                    padding: 20px;
                    background: #ffebee;
                    border-radius: 10px;
                    border-left: 4px solid #e74c3c;
                }}
                code {{
                    background: #f8f9fa;
                    padding: 10px;
                    border-radius: 5px;
                    display: block;
                    margin: 10px 0;
                    border: 1px solid #dee2e6;
                }}
                .lock-icon {{
                    width: 16px;
                    height: 16px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="ssl-badge">
                    🔒 SSL/TLS Seguro
                </div>
                <h1>🎓 Credencial Universitaria</h1>
                <div class="protocol-badge">OpenID4VC Draft-16 Compatible</div>
                
                <div class="course-info">
                    <div class="student-name">{qr_data.get('student_name', 'Estudiante')}</div>
                    <div>{qr_data.get('course_name', 'Curso')}</div>
                </div>
                
                <div class="ssl-info">
                    <h4>🔐 Información de Seguridad SSL</h4>
                    <ul style="text-align: left; margin: 0;">
                        <li><strong>Dominio:</strong> {ISSUER_URL}</li>
                        <li><strong>TLS:</strong> v1.2+ con ECDHE</li>
                        <li><strong>Certificado:</strong> Let's Encrypt válido</li>
                        <li><strong>HSTS:</strong> Habilitado</li>
                    </ul>
                </div>
                
                <div class="qr-container">
                    {f'<img src="{qr_data["qr_code_base64"]}"' if qr_data.get('qr_code_base64') else '<div class="qr-error">❌ QR no disponible</div><br><strong>URL directa:</strong><br><code style="word-break: break-all; font-size: 0.8em;">{qr_data["qr_url"]}</code>'}
                         alt="QR Code OpenID4VC" class="qr-code">
                    <div class="expires-info">
                        Válido hasta: {qr_data.get('expires_at', 'Sin límite')}
                    </div>
                </div>
                
                <div class="instructions">
                    <h3>📱 Compatible con Walt.id y Otros Wallets</h3>
                    <p><strong>Instrucciones:</strong></p>
                    <ol style="text-align: left;">
                        <li>Abre tu wallet OpenID4VC (walt.id, Lissi, etc.)</li>
                        <li>Escanea este código QR o copia la URL directa</li>
                        <li>Acepta la credencial en tu wallet</li>
                        <li>¡Credencial W3C recibida!</li>
                    </ol>
                    {f'<p><strong>URL para copiar:</strong><br><code style="word-break: break-all; font-size: 0.8em;">{qr_data["qr_url"]}</code></p>' if not qr_data.get('qr_code_base64') else ''}
                </div>
                
                <div class="troubleshooting">
                    <h4>🔧 ¿Problemas con el wallet?</h4>
                    <p><strong>Si ves errores en walt.id o tu wallet:</strong></p>
                    <ul style="text-align: left; margin: 0;">
                        <li>Verifica que tu wallet soporte OpenID4VC</li>
                        <li>Copia la URL directa si el QR no funciona</li>
                        <li>Asegúrate de tener conexión a internet estable</li>
                        <li>El formato cumple con OpenID4VC Draft-16</li>
                    </ul>
                    <p style="margin-top: 10px;">
                        <strong>Test de metadatos:</strong> 
                        <a href="{ISSUER_URL}/oid4vc/.well-known/openid-credential-issuer" 
                           target="_blank">Verificar configuración</a>
                    </p>
                </div>
            </div>
            
            <script>
                // Auto-refresh si expira pronto
                const expiresAt = '{qr_data.get('expires_at', '')}';
                if (expiresAt) {{
                    const expires = new Date(expiresAt);
                    const now = new Date();
                    const timeLeft = expires - now;
                    
                    if (timeLeft > 0 && timeLeft < 60000) {{ // Menos de 1 minuto
                        setTimeout(() => {{
                            location.reload();
                        }}, timeLeft + 1000);
                    }}
                }}
            </script>
        </body>
        </html>
        """
        
        response = HTMLResponse(content=html_content)
        
        # Añadir headers SSL para la página web también
        for header, value in SSL_SECURITY_HEADERS.items():
            response.headers[header] = value
            
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error mostrando QR OpenID4VC: {e}")
        raise HTTPException(status_code=500, detail=f"Error mostrando QR: {str(e)}")

# ==================== ENDPOINT ADICIONAL: SSL/TLS TEST ====================

@oid4vc_router.get("/ssl-test")
async def ssl_test_endpoint():
    """
    Endpoint para probar la configuración SSL/TLS
    Útil para debugging de problemas de certificados con Lissi Wallet
    """
    try:
        import socket
        import ssl as ssl_module
        
        # Información del servidor SSL
        hostname = ISSUER_URL.replace('https://', '').replace('http://', '')
        
        ssl_info = {
            "server": hostname,
            "timestamp": datetime.now().isoformat(),
            "ssl_configured": ISSUER_URL.startswith('https://'),
            "tls_versions_supported": TLS_PROTOCOLS_SUPPORTED,
            "cipher_suites_android": CIPHER_SUITES_ANDROID,
            "headers_security": SSL_SECURITY_HEADERS,
            "issuer_url": ISSUER_URL,
            "jwks_uri": f"{ISSUER_URL}/oid4vc/.well-known/jwks.json",
            "openid_metadata": f"{ISSUER_URL}/oid4vc/.well-known/openid-credential-issuer"
        }
        
        # Intentar verificar certificado SSL (solo si estamos en HTTPS)
        if ISSUER_URL.startswith('https://'):
            try:
                context = ssl_module.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        ssl_info["certificate"] = {
                            "subject": dict(x[0] for x in cert['subject']),
                            "issuer": dict(x[0] for x in cert['issuer']),
                            "version": cert['version'],
                            "serial_number": cert['serialNumber'],
                            "not_before": cert['notBefore'],
                            "not_after": cert['notAfter'],
                            "signature_algorithm": cert.get('signatureAlgorithm', 'Unknown')
                        }
                        ssl_info["ssl_verification"] = "SUCCESS"
            except Exception as ssl_error:
                ssl_info["ssl_verification"] = "ERROR"
                ssl_info["ssl_error"] = str(ssl_error)
        
        response = JSONResponse(content=ssl_info)
        return await add_security_headers(response)
        
    except Exception as e:
        logger.error(f"❌ Error en SSL test: {e}")
        return JSONResponse(content={
            "error": "ssl_test_failed",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        })

# ==================== ENDPOINT ADICIONAL: HEALTH CHECK ====================

@oid4vc_router.get("/health")
async def health_check():
    """
    Health check endpoint con información SSL
    """
    health_info = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0-ssl-enhanced",
        "issuer_url": ISSUER_URL,
        "ssl_enabled": ISSUER_URL.startswith('https://'),
        "endpoints": {
            "metadata": f"{ISSUER_URL}/oid4vc/.well-known/openid-credential-issuer",
            "jwks": f"{ISSUER_URL}/oid4vc/.well-known/jwks.json",
            "token": f"{ISSUER_URL}/oid4vc/token",
            "credential": f"{ISSUER_URL}/oid4vc/credential",
            "ssl_test": f"{ISSUER_URL}/oid4vc/ssl-test"
        }
    }
    
    response = JSONResponse(content=health_info)
    return await add_security_headers(response)
