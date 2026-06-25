#!/usr/bin/env python3
"""
Controller Python — Plataforma de Microcredenciales Blockchain.

Emisión de credenciales W3C Verificables (SD-JWT) via OpenID4VCI,
con anclaje criptográfico en Hyperledger Besu (Smart Contracts EVM).
La capa de blockchain es abstrada por el módulo ``blockchain``
(patrón puerto/adaptador) para mantener el sistema agnóstico al
ledger subyacente.
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
CONTROLLER_PORT = int(os.getenv("CONTROLLER_PORT", "3000"))
UNIVERSITY_NAME = os.getenv("UNIVERSITY_NAME", "Universidad Tecnológica Nacional")
PORTAL_URL = os.getenv("PORTAL_FRONTEND_URL", os.getenv("PORTAL_URL"))

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
    pre_authorized_code: Optional[str] = None

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

# Determinar orígenes de CORS resolviendo problemas por variables vacías o con slashes
allowed_origins = [
    "http://localhost:5173",  # Mantenido únicamente para tu dev local
]

if PORTAL_URL:
    # Sanitización exhaustiva: remueve espacios, comillas simples/dobles y slashes finales
    clean_url = PORTAL_URL.strip().strip("'").strip('"').rstrip('/')
    if clean_url not in allowed_origins:
        allowed_origins.append(clean_url)
    logger.info(f"🛡️ CORS: PORTAL_URL cargado y sanitizado -> '{clean_url}'")
else:
    logger.warning("⚠️ CRÍTICO: La variable de entorno PORTAL_URL no está seteada o está vacía. El frontend de producción será bloqueado por CORS.")

logger.info(f"🛡️ CORS Allowed Origins totales: {allowed_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=".*",
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

# Portal del alumno — rutas autenticadas, públicas y de administración
from portal.router import portal_admin_router, portal_public_router, portal_router

app.include_router(portal_router)
app.include_router(portal_public_router)
app.include_router(portal_admin_router)

qr_generator = QRGenerator()

# FUNCIONES DE SOLICITUD DE CREDENCIAL

async def request_credential_openid4vc(credential_request: StudentCredentialRequest) -> CredentialResponse:
    """
    [MODERN] Retorna oferta OpenID4VC (DIDRoom/Walt.id/EUDI)
    """
    try:
        logger.info(f"📨 [MODERN] Solicitud OpenID4VC para: {credential_request.student_name}")

        if not OPENID4VC_AVAILABLE:
            raise HTTPException(status_code=501, detail="OpenID4VC no disponible")

        # Generar oferta OpenID4VC
        request_dict = credential_request.dict()
        offer_result = await generate_openid_offer(request_dict)

        # Generar instrucciones legibles
        compatibility = offer_result.get("compatibility", {})
        flows = compatibility.get("flows_supported", [])
        if flows:
            instructions_text = f"Escanea con wallet compatible OpenID4VC. Soporta: {', '.join(flows)}"
        else:
            instructions_text = "Escanea con wallet compatible OpenID4VC (DIDRoom, Lissi, etc.)"
        
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
    Endpoint principal: Exclusivamente OpenID4VC (Moderno - SD-JWT)
    """
    return await request_credential_openid4vc(credential_request)

# ENDPOINT COMPATIBILIDAD MOODLE

@app.post("/api/credenciales")
async def legacy_credential_endpoint(data: dict):
    """Endpoint de compatibilidad con Moodle (Actualizado a OpenID4VCI)"""
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

        # Procesamiento OpenID4VCI (Besu + SD-JWT)
        result = await request_credential_openid4vc(credential_request)

        return {
            "success": True,
            "message": "Credencial SD-JWT procesada y anclada exitosamente",
            "qr_code": result.qr_code_base64,
            "invitation_url": result.invitation_url,
            "connection_id": "oid4vci-stateless" # Compatibility field
        }

    except Exception as e:
        logger.error(f"Error en endpoint portal/moodle: {e}")
        return {
            "success": False,
            "message": str(e)
        }

# ============================================================================
# ROOT METADATA ENDPOINTS
# ============================================================================
# Delegación a los handlers modulares de openid4vc.metadata_endpoints.
# Los wallets (Lissi, WaltID, DIDRoom, EUDI) acceden a /.well-known/ en la raíz
# del dominio (RFC 8414 / OID4VCI §12.2.2), mientras que el router modular
# monta sus endpoints bajo el prefijo /oid4vc/.  Para garantizar una Single
# Source of Truth, estos root handlers delegan directamente a las
# implementaciones canónicas del módulo modular.
# ============================================================================

from openid4vc.metadata_endpoints import (
    oauth_authorization_server_metadata as _modular_oauth_metadata,
    get_credential_issuer_metadata as _modular_issuer_metadata,
    vct_metadata_endpoint as _modular_vct_metadata,
    did_document_endpoint as _modular_did_document,
)


@app.get("/.well-known/oauth-authorization-server")
async def root_oauth_metadata():
    """
    OAuth 2.0 Authorization Server Metadata en RAÍZ (RFC 8414).
    Delega al handler modular para mantener una única fuente de verdad.
    """
    return await _modular_oauth_metadata()

@app.get("/.well-known/did.json")
async def root_did_document():
    """
    Resolución criptográfica W3C DID Core para did:web en la RAÍZ del dominio.
    Imprescindible para carteras estrictas de SSI (Paradym, Animo, Credo-TS)
    cuando el Issuer o firmante se declara vía Identificadores Descentralizados.
    """
    return await _modular_did_document()


@app.get("/.well-known/openid-credential-issuer")
async def root_credential_issuer_metadata(request: Request):
    """
    OpenID Credential Issuer Metadata en RAÍZ (OID4VCI §12.2.2).
    Delega al handler modular que incluye notification_endpoint,
    claims definitions y display multi-locale.
    """
    return await _modular_issuer_metadata(request)


@app.get("/.well-known/vct/{vct_id}")
async def root_vct_metadata(vct_id: str):
    """
    VCT Type Metadata en RAÍZ (IETF SD-JWT VC §6.3).
    Delega al handler modular que sirve metadata del tipo de credencial.
    """
    return await _modular_vct_metadata(vct_id)

@app.get("/{vct_id}")
async def alias_vct_metadata(vct_id: str):
    """
    Alias estricto de VCT Type Metadata en RAÍZ pura (IETF SD-JWT VC §6.3 ver. 06).
    Las wallets que siguen el RFC al pie de la letra (e.g. Lissi) intentarán un 
    HTTP GET directo sobre el valor 'vct' (https://api-credenciales.../UniversityDegree)
    sin inyectar sub-paths como .well-known/vct/.
    Validamos explícitamente el ID para evitar falsos positivos con otros paths.
    """
    if vct_id in ("UniversityDegree", "WaltIdDegree"):
        return await _modular_vct_metadata(vct_id)
    # Evitar capturar otros recursos (JS, CSS, static, etc)
    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail="Not Found")

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

@app.on_event("startup")
async def startup_portal_db():
    """Ensure portal tables exist (belt-and-suspenders with Alembic)."""
    from portal.database import portal_engine, Base
    Base.metadata.create_all(bind=portal_engine)


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
