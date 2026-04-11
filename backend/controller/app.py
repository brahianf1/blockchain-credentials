#!/usr/bin/env python3
"""
Controller Python - Integración Moodle + ACA-Py + Fabric
Sistema REAL de Emisión de Credenciales W3C Verificables

PROHIBIDO USAR SIMULACIONES - Solo implementación real con wallets funcionales
"""

import asyncio
import logging
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field
import httpx
import structlog

from fabric_client import FabricClient
from qr_generator import QRGenerator
from storage import qr_storage
from qr_endpoints import router as qr_router

# OpenID4VC Modular Router - No fallback, clean implementation
from openid4vc.router import oid4vc_router
from openid4vc.core_endpoints import generate_credential_offer as generate_openid_offer

OPENID4VC_AVAILABLE = True
OPENID4VC_MODE = "modular"

# Configuración de logging estructurado
logging.basicConfig(level=logging.INFO)
logger = structlog.get_logger()

logger.info("✅ OpenID4VC modular router initialized")

# Configuración del Controller
ACAPY_ADMIN_URL = os.getenv("ACAPY_ADMIN_URL", "http://acapy-agent:8020")
ACAPY_PUBLIC_URL = os.getenv("ACAPY_PUBLIC_URL", "http://localhost:8021")
CONTROLLER_PORT = int(os.getenv("CONTROLLER_PORT", "3000"))
UNIVERSITY_NAME = os.getenv("UNIVERSITY_NAME", "Universidad Tecnológica Nacional")

# Modelos Pydantic
class StudentCredentialRequest(BaseModel):
    student_id: str
    student_name: str
    student_email: str
    course_id: str
    course_name: str
    completion_date: str
    grade: str
    instructor_name: str

class CredentialResponse(BaseModel):
    connection_id: Optional[str] = None
    invitation_url: Optional[str] = None
    qr_code_base64: str
    # Campos OpenID4VC
    pre_authorized_code: Optional[str] = None
    offer_json: Optional[Dict[str, Any]] = None
    instructions: Optional[str] = None

# Inicializar FastAPI
app = FastAPI(title="Controller Credenciales", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware para logging exhaustivo de todas las peticiones
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log ALL HTTP requests for debugging DIDRoom flow"""
    from fastapi import Request as FastAPIRequest
    
    # Capturar información de la petición
    method = request.method
    url = str(request.url)
    path = request.url.path
    query_params = dict(request.query_params)
    
    # Log especial para endpoints de OpenID4VC
    if "/oid4vc/" in path or "/.well-known/" in path:
        logger.info("=" * 80)
        logger.info(f"📨 HTTP REQUEST: {method} {path}")
        logger.info(f"   Full URL: {url}")
        if query_params:
            logger.info(f"   Query params: {query_params}")
        logger.info("=" * 80)
    
    # Procesar la petición
    response = await call_next(request)
    
    # Log de respuesta para endpoints críticos
    if path == "/oid4vc/authorize" or path == "/oid4vc/par":
        logger.info(f"✅ RESPONSE: {method} {path} → Status {response.status_code}")
        logger.info("=" * 80)
    
    return response


# Incluir router OpenID4VC si está disponible
if OPENID4VC_AVAILABLE:
    app.include_router(oid4vc_router)
    logger.info(f"✅ OpenID4VC router included (mode: {OPENID4VC_MODE})")

# Incluir router QR
app.include_router(qr_router)

# Inicializar clientes
try:
    fabric_client = FabricClient()
except Exception:
    fabric_client = None
    logger.warning("⚠️ FabricClient no disponible")

qr_generator = QRGenerator()

# FUNCIONES AUXILIARES

async def store_pending_credential(connection_id: str, credential_data: StudentCredentialRequest):
    """Almacenar datos de credencial pendiente (En producción: BD)"""
    import tempfile
    temp_file = f"/tmp/pending_credential_{connection_id}.json"
    with open(temp_file, 'w') as f:
        json.dump(credential_data.dict(), f)

async def get_pending_credential(connection_id: str) -> Optional[Dict[str, Any]]:
    """Obtener datos de credencial pendiente"""
    try:
        temp_file = f"/tmp/pending_credential_{connection_id}.json"
        with open(temp_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

async def clear_pending_credential(connection_id: str):
    """Limpiar datos de credencial pendiente"""
    try:
        temp_file = f"/tmp/pending_credential_{connection_id}.json"
        os.remove(temp_file)
    except Exception:
        pass

async def get_credential_definition_id() -> Optional[str]:
    """Obtener ID de Credential Definition"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{ACAPY_ADMIN_URL}/credential-definitions/created")
            if response.status_code == 200:
                cred_defs = response.json()
                if cred_defs.get("credential_definition_ids"):
                    return cred_defs["credential_definition_ids"][0]
        return None
    except Exception:
        return None

async def issue_credential(connection_id: str, credential_data: Optional[Dict[str, Any]] = None):
    """
    Emitir credencial una vez establecida la conexión
    Se llama automáticamente cuando la conexión esté activa
    """
    try:
        logger.info(f"🎓 Emitiendo credencial para conexión: {connection_id}")

        # Obtener datos de credencial pendiente
        credential_data = await get_pending_credential(connection_id)
        if not credential_data:
            raise HTTPException(status_code=404, detail="No hay credencial pendiente para esta conexión")

        # Obtener Credential Definition ID (en producción, almacenar en BD)
        cred_def_id = await get_credential_definition_id()
        if not cred_def_id:
            raise HTTPException(status_code=500, detail="Credential Definition no encontrado")

        # Preparar atributos de la credencial
        credential_attributes = [
            {"name": "student_id", "value": credential_data["student_id"]},
            {"name": "student_name", "value": credential_data["student_name"]},
            {"name": "student_email", "value": credential_data["student_email"]},
            {"name": "course_id", "value": credential_data["course_id"]},
            {"name": "course_name", "value": credential_data["course_name"]},
            {"name": "completion_date", "value": credential_data["completion_date"]},
            {"name": "grade", "value": credential_data["grade"]},
            {"name": "instructor_name", "value": credential_data["instructor_name"]},
            {"name": "issue_date", "value": datetime.utcnow().isoformat()},
            {"name": "university_name", "value": UNIVERSITY_NAME}
        ]

        # Emitir credencial vía ACA-Py
        async with httpx.AsyncClient() as client:
            offer_body = {
                "connection_id": connection_id,
                "credential_definition_id": cred_def_id,
                "credential_preview": {
                    "@type": "issue-credential/2.0/credential-preview",
                    "attributes": credential_attributes
                },
                "auto_issue": True,
                "auto_remove": False,
                "comment": f"Credencial de finalización: {credential_data['course_name']}"
            }

            offer_response = await client.post(
                f"{ACAPY_ADMIN_URL}/issue-credential-2.0/send-offer",
                json=offer_body
            )

            if offer_response.status_code != 200:
                raise HTTPException(status_code=500, detail="Error emitiendo credencial")

            offer_data = offer_response.json()
            logger.info(f"✅ Credencial emitida: {offer_data['cred_ex_id']}")

            # Limpiar datos pendientes
            await clear_pending_credential(connection_id)

            return {
                "status": "credential_issued",
                "credential_exchange_id": offer_data["cred_ex_id"],
                "message": "Credencial emitida exitosamente"
            }

    except Exception as e:
        logger.error(f"❌ Error emitiendo credencial: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def issue_credential_background(connection_id: str):
    """Emitir credencial en background"""
    try:
        await asyncio.sleep(2)  # Esperar un poco para que conexión se estabilice
        await issue_credential(connection_id, None)
    except Exception as e:
        logger.error(f"Error en emisión background: {e}")

# FUNCIONES DE SOLICITUD DE CREDENCIAL

async def request_credential_didcomm(credential_request: StudentCredentialRequest) -> CredentialResponse:
    """
    [LEGACY] Retorna invitación de conexión DIDComm (ACA-Py)
    """
    try:
        logger.info(f"📨 [LEGACY] Solicitud DIDComm para: {credential_request.student_name}")

        # 1. Registrar en Hyperledger Fabric
        if fabric_client:
            try:
                if hasattr(fabric_client, 'register_student'):
                    await fabric_client.register_student(credential_request.student_id)
            except Exception as e:
                logger.error(f"⚠️ Error registrando en Fabric: {e}")

        # 2. Crear invitación de conexión en ACA-Py
        async with httpx.AsyncClient() as client:
            invitation_response = await client.post(
                f"{ACAPY_ADMIN_URL}/connections/create-invitation",
                json={"alias": f"student-{credential_request.student_id}"}
            )

            if invitation_response.status_code != 200:
                raise HTTPException(status_code=500, detail="Error creando invitación ACA-Py")

            invitation_data = invitation_response.json()
            connection_id = invitation_data["connection_id"]
            invitation_url = invitation_data["invitation_url"]

            # 3. Guardar datos para emisión posterior
            await store_pending_credential(connection_id, credential_request)

            # 4. Generar QR
            qr_code_base64 = qr_generator.generate_qr(invitation_url)

            return CredentialResponse(
                connection_id=connection_id,
                invitation_url=invitation_url,
                qr_code_base64=qr_code_base64,
                instructions="Escanea con tu wallet Identity (DIDComm)"
            )

    except Exception as e:
        logger.error(f"❌ Error en request_credential_didcomm: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def request_credential_openid4vc(credential_request: StudentCredentialRequest) -> CredentialResponse:
    """
    [MODERN] Retorna oferta OpenID4VC (Lissi/Walt.id/EUDI/DIDRoom)
    """
    try:
        logger.info(f"📨 [MODERN] Solicitud OpenID4VC para: {credential_request.student_name}")

        if not OPENID4VC_AVAILABLE:
            raise HTTPException(status_code=501, detail="OpenID4VC no disponible")

        # 1. Registrar en Hyperledger Fabric (igual que legacy)
        if fabric_client:
            try:
                if hasattr(fabric_client, 'register_student'):
                    await fabric_client.register_student(credential_request.student_id)
            except Exception as e:
                logger.error(f"⚠️ Error registrando en Fabric: {e}")

        # 2. Generar oferta OpenID4VC
        request_dict = credential_request.dict()
        
        # Usar función importada (modular o legacy)
        offer_result = await generate_openid_offer(request_dict)

        # Generar instrucciones legibles
        compatibility = offer_result.get("compatibility", {})
        flows = compatibility.get("flows_supported", [])
        if flows:
            instructions_text = f"Escanea con wallet compatible OpenID4VC. Soporta: {', '.join(flows)}"
        else:
            instructions_text = "Escanea con wallet compatible OpenID4VC (WaltID, DIDRoom, Lissi, etc.)"
        
        return CredentialResponse(
            qr_code_base64=offer_result["qr_code_base64"],
            invitation_url=offer_result["qr_url"],
            pre_authorized_code=offer_result.get("pre_authorized_code"),
            offer_json=offer_result.get("offer"),
            instructions=instructions_text
        )

    except Exception as e:
        logger.error(f"❌ Error en request_credential_openid4vc: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/request-credential", response_model=CredentialResponse)
async def request_credential(credential_request: StudentCredentialRequest):
    """
    Endpoint principal: Por defecto usa OpenID4VC (Moderno)
    """
    if OPENID4VC_AVAILABLE:
        return await request_credential_openid4vc(credential_request)
    else:
        logger.warning("⚠️ OpenID4VC no disponible, usando fallback a DIDComm")
        return await request_credential_didcomm(credential_request)

# WEBHOOKS de ACA-Py (para automatización)

@app.post("/webhooks/connections")
async def webhook_connections(data: dict):
    """Webhook para eventos de conexión"""
    logger.info(f"🔔 Webhook conexión: {data.get('state', 'unknown')}")

    if data.get("state") == "active":
        connection_id = data.get("connection_id")
        if connection_id:
            logger.info(f"✅ Conexión activa, emitiendo credencial: {connection_id}")
            asyncio.create_task(issue_credential_background(connection_id))

    return {"status": "received"}

@app.post("/webhooks/issue_credential")
async def webhook_issue_credential(data: dict):
    """Webhook para eventos de emisión de credencial"""
    state = data.get("state", "unknown")
    cred_ex_id = data.get("credential_exchange_id", "unknown")

    logger.info(f"🎓 Webhook credencial [{cred_ex_id}]: {state}")

    if state == "credential_acked":
        logger.info(f"✅ Credencial confirmada por el estudiante: {cred_ex_id}")

    return {"status": "received"}

# ENDPOINT COMPATIBILIDAD MOODLE (mantener API anterior)

@app.post("/api/credenciales")
async def legacy_credential_endpoint(data: dict):
    """Endpoint de compatibilidad con Moodle (API anterior)"""
    try:
        credential_request = StudentCredentialRequest(
            student_id=str(data.get("usuarioId", "unknown")),
            student_name=data.get("usuarioNombre", "Usuario"),
            student_email=data.get("usuarioEmail", "email@universidad.edu"),
            course_id=str(data.get("cursoId", "unknown")),
            course_name=data.get("cursoNombre", "Curso"),
            completion_date=data.get("fechaFinalizacion", datetime.utcnow().isoformat()),
            grade=data.get("calificacion", "Aprobado"),
            instructor_name=data.get("instructor", "Instructor")
        )

        # USAR LEGACY EXPLICITAMENTE
        result = await request_credential_didcomm(credential_request)

        return {
            "success": True,
            "message": "Credencial procesada exitosamente",
            "qr_code": result.qr_code_base64,
            "invitation_url": result.invitation_url,
            "connection_id": result.connection_id
        }

    except Exception as e:
        logger.error(f"Error en endpoint legacy: {e}")
        return {
            "success": False,
            "message": str(e)
        }

# METADATA ENDPOINTS (fallback si no hay OpenID4VC)

# METADATA ENDPOINTS (también en raíz para compatibilidad)

@app.get("/.well-known/oauth-authorization-server")
async def root_oauth_metadata():
    """
    OAuth 2.0 Authorization Server Metadata en RAÍZ
    Soporta AMBOS flujos: pre-authorized_code (WaltID) y authorization_code (DIDRoom)
    """
    logger.info("📋 [ROOT] OAuth metadata requested - Dual flow support")
    
    metadata = {
        "issuer": os.getenv("ISSUER_URL", "https://api-credenciales.utnpf.site"),
        "authorization_endpoint": f"{os.getenv('ISSUER_URL', 'https://api-credenciales.utnpf.site')}/oid4vc/authorize",
        "token_endpoint": f"{os.getenv('ISSUER_URL', 'https://api-credenciales.utnpf.site')}/oid4vc/token",
        "jwks_uri": f"{os.getenv('ISSUER_URL', 'https://api-credenciales.utnpf.site')}/oid4vc/.well-known/jwks.json",
        "pushed_authorization_request_endpoint": f"{os.getenv('ISSUER_URL', 'https://api-credenciales.utnpf.site')}/oid4vc/par",
        "grant_types_supported": [
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "authorization_code"
        ],
        "token_endpoint_auth_methods_supported": ["none"],
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "code_challenge_methods_supported": ["S256"]
    }
    
    return JSONResponse(content=metadata)

@app.get("/.well-known/openid-credential-issuer")
async def root_credential_issuer_metadata():
    """Metadata OpenID4VC en raíz (usado por DIDRoom y otras wallets)"""
    logger.info("📋 [ROOT] Credential issuer metadata requested")
    
    issuer_url = os.getenv("ISSUER_URL", "https://api-credenciales.utnpf.site")

    metadata = {
        "credential_issuer": issuer_url,
        "authorization_servers": [issuer_url],
        "authorization_server": issuer_url,
        "credential_endpoint": f"{issuer_url}/oid4vc/credential",
        "token_endpoint": f"{issuer_url}/oid4vc/token",
        "nonce_endpoint": f"{issuer_url}/oid4vc/nonce",
        "jwks_uri": f"{issuer_url}/oid4vc/.well-known/jwks.json",
        "display": [{
            "name": "Sistema de Credenciales UTN",
            "locale": "es-AR"
        }],
        "credential_configurations_supported": {
            "UniversityDegree_JWT": {
                "format": "jwt_vc_json",
                "scope": "UniversityDegreeScope",
                "cryptographic_binding_methods_supported": ["did:key", "did:jwk", "jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                },
                "credential_definition": {
                    "type": ["VerifiableCredential", "UniversityDegree"],
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        f"{issuer_url}/oid4vc/context/v1"
                    ]
                },
                "display": [{
                    "name": "Certificado U. (WaltID/Lissi)",
                    "description": "Credencial oficial que certifica la finalización de un curso (formato JWT).",
                    "locale": "es-AR",
                    "background_color": "#1976d2",
                    "text_color": "#FFFFFF",
                    "logo": {
                        "uri": "https://placehold.co/150x150/1976d2/white?text=UTN",
                        "alt_text": "Logo UTN"
                    }
                }]
            },
            "UniversityDegree_LDP": {
                "format": "ldp_vc",
                "scope": "UniversityDegreeScope",
                "cryptographic_binding_methods_supported": ["did:key", "did:jwk", "jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                },
                "credential_definition": {
                    "type": ["VerifiableCredential", "UniversityDegree"],
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        f"{issuer_url}/oid4vc/context/v1"
                    ]
                },
                "display": [{
                    "name": "Certificado U. (DIDRoom)",
                    "description": "Credencial oficial que certifica la finalización de un curso (formato LDP).",
                    "locale": "es-AR",
                    "background_color": "#1976d2",
                    "text_color": "#FFFFFF",
                    "logo": {
                        "uri": "https://placehold.co/150x150/1976d2/white?text=UTN",
                        "alt_text": "Logo UTN"
                    }
                }]
            }
        }
    }

    return JSONResponse(content=metadata)

@app.get("/health")
async def healthcheck():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "openid4vc": OPENID4VC_MODE,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/debug/last-offer")
async def debug_last_offer():
    """DEBUG: Muestra el último offer generado con su URL completo"""
    # Obtener el último QR del storage
    if not qr_storage:
        return {"error": "No offers generated yet"}
    
    # Ordenar por timestamp y obtener el más reciente
    sorted_offers = sorted(
        qr_storage.items(),
        key=lambda x: x[1].get("timestamp", ""),
        reverse=True
    )
    
    if not sorted_offers:
        return {"error": "No offers found"}
    
    latest_code, latest_offer = sorted_offers[0]
    
    return {
        "intent_url": latest_offer.get("qr_url"),
        "student_name": latest_offer.get("student_name"),
        "course_name": latest_offer.get("course_name"),
        "timestamp": latest_offer.get("timestamp"),
        "session_id": latest_offer.get("session_id"),
        "instructions": "Copia el 'intent_url' y pégalo en DIDRoom web"
    }

if __name__ == "__main__":
    import uvicorn
    logger.info(f"🚀 Iniciando Controller v2.0 en puerto {CONTROLLER_PORT}")
    logger.info(f"📋 OpenID4VC mode: {OPENID4VC_MODE}")
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=CONTROLLER_PORT,
        reload=False,
        log_level="info"
    )
