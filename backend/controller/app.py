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

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field
import httpx
import structlog

from fabric_client import FabricClient
from qr_generator import QRGenerator

# Importar diccionario compartido de OpenID4VC
from openid4vc_endpoints import pre_authorized_code_data

# NUEVO: Import OpenID4VC endpoints
try:
    from openid4vc_endpoints import oid4vc_router
    OPENID4VC_AVAILABLE = True
except ImportError:
    OPENID4VC_AVAILABLE = False
    logger.warning("⚠️ OpenID4VC endpoints no disponibles - instalar dependencias")

# Configuración de logging estructurado
logging.basicConfig(level=logging.INFO)
logger = structlog.get_logger()

# Configuración del Controller
ACAPY_ADMIN_URL = os.getenv("ACAPY_ADMIN_URL", "http://acapy-agent:8020")
ACAPY_PUBLIC_URL = os.getenv("ACAPY_PUBLIC_URL", "http://localhost:8021")
CONTROLLER_PORT = int(os.getenv("CONTROLLER_PORT", "3000"))

# Configuraciones de credencial desde variables de entorno
CREDENTIAL_SCHEMA_NAME = os.getenv("CREDENTIAL_SCHEMA_NAME", "UniversidadCredencial")
CREDENTIAL_SCHEMA_VERSION = os.getenv("CREDENTIAL_SCHEMA_VERSION", "1.0")
CREDENTIAL_DEFINITION_TAG = os.getenv("CREDENTIAL_DEFINITION_TAG", "universidad_v1")
UNIVERSITY_NAME = os.getenv("UNIVERSITY_NAME", "Universidad de Ejemplo")

# Almacenamiento temporal de QRs (en producción usar base de datos)
qr_storage: Dict[str, Dict[str, str]] = {}

# Configuración FastAPI
app = FastAPI(
    title="Universidad - Sistema de Credenciales W3C",
    description="Emisor REAL de Credenciales Verificables - Integración Moodle + ACA-Py + Hyperledger Fabric + OpenID4VC",
    version="2.0.0"  # Incrementar versión
)

# NUEVO: Incluir router OpenID4VC si está disponible
if OPENID4VC_AVAILABLE:
    app.include_router(oid4vc_router)
    logger.info("✅ OpenID4VC endpoints habilitados para wallets modernas (Lissi, etc.)")
else:
    logger.warning("⚠️ Solo DIDComm disponible - considera instalar dependencias OpenID4VC")

# CORS para Moodle
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción, especificar dominio de Moodle
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Clientes globales
fabric_client = None
qr_generator = QRGenerator()

# Modelos Pydantic
class StudentCredentialRequest(BaseModel):
    """Solicitud de credencial desde Moodle"""
    student_id: str = Field(..., description="ID del estudiante en Moodle")
    student_name: str = Field(..., description="Nombre completo del estudiante")
    student_email: str = Field(..., description="Email del estudiante")
    course_id: str = Field(..., description="ID del curso en Moodle")
    course_name: str = Field(..., description="Nombre del curso")
    completion_date: str = Field(..., description="Fecha de finalización ISO 8601")
    grade: str = Field(..., description="Calificación obtenida")
    instructor_name: str = Field(..., description="Nombre del instructor")

# COMPATIBILIDAD: Modelo para la estructura original de las Fases 1-3
class MoodleCredentialRequest(BaseModel):
    """Solicitud de credencial desde Moodle (formato original Fases 1-3)"""
    userId: str = Field(..., description="ID del usuario en Moodle")
    userEmail: str = Field(..., description="Email del usuario")
    userName: str = Field(..., description="Nombre completo del usuario")
    courseId: str = Field(..., description="ID del curso en Moodle")
    courseName: str = Field(..., description="Nombre del curso")
    completionDate: str = Field(..., description="Fecha de finalización ISO 8601")
    
class ConnectionInvitationResponse(BaseModel):
    """Respuesta con invitación de conexión"""
    invitation_url: str
    qr_code_base64: str
    connection_id: str
    
class CredentialOfferResponse(BaseModel):
    """Respuesta con oferta de credencial"""
    credential_offer_id: str
    status: str
    credential_definition_id: str

# Eventos de inicialización
@app.on_event("startup")
async def startup_event():
    """Inicialización de servicios"""
    global fabric_client
    
    logger.info("🚀 Iniciando Controller de Credenciales W3C...")
    
    # Verificar conectividad con ACA-Py (no bloqueante en desarrollo)
    if not await check_acapy_connection():
        logger.warning("⚠️ ACA-Py no disponible - continuando en modo desarrollo")
    else:
        logger.info("✅ ACA-Py conectado correctamente")
    
    # Inicializar Fabric Client
    try:
        fabric_client = FabricClient()
        logger.info("✅ Fabric Client inicializado")
    except Exception as e:
        logger.error(f"❌ Error inicializando Fabric: {e}")
        # No detener el servicio, pero registrar el error
    
    # Configurar Schema y Credential Definition
    await setup_credential_schema()
    
    logger.info("✅ Controller inicializado correctamente")

async def check_acapy_connection() -> bool:
    """Verificar conectividad con ACA-Py"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{ACAPY_ADMIN_URL}/status/live")
            return response.status_code == 200
    except Exception as e:
        logger.error(f"Error conectando con ACA-Py: {e}")
        return False

async def setup_credential_schema():
    """Configurar Schema y Credential Definition para credenciales universitarias"""
    try:
        # Definir Schema de Credencial Universitaria
        schema_body = {
            "schema_name": CREDENTIAL_SCHEMA_NAME,
            "schema_version": CREDENTIAL_SCHEMA_VERSION,
            "attributes": [
                "student_id",
                "student_name", 
                "student_email",
                "course_id",
                "course_name",
                "completion_date",
                "grade",
                "instructor_name",
                "issue_date",
                "university_name"
            ]
        }
        
        async with httpx.AsyncClient() as client:
            # Crear Schema
            logger.info("📋 Creando Schema de credencial...")
            schema_response = await client.post(
                f"{ACAPY_ADMIN_URL}/schemas",
                json=schema_body
            )
            
            if schema_response.status_code == 200:
                schema_data = schema_response.json()
                schema_id = schema_data["sent"]["schema_id"]
                logger.info(f"✅ Schema creado: {schema_id}")
                
                # Crear Credential Definition
                cred_def_body = {
                    "schema_id": schema_id,
                    "support_revocation": False,
                    "tag": CREDENTIAL_DEFINITION_TAG
                }
                
                logger.info("🔐 Creando Credential Definition...")
                cred_def_response = await client.post(
                    f"{ACAPY_ADMIN_URL}/credential-definitions",
                    json=cred_def_body
                )
                
                if cred_def_response.status_code == 200:
                    cred_def_data = cred_def_response.json()
                    logger.info(f"✅ Credential Definition creado: {cred_def_data['sent']['credential_definition_id']}")
                else:
                    logger.error(f"❌ Error creando Credential Definition: {cred_def_response.text}")
            else:
                logger.error(f"❌ Error creando Schema: {schema_response.text}")
                
    except Exception as e:
        logger.error(f"❌ Error configurando Schema: {e}")

# ENDPOINTS PRINCIPALES

@app.get("/health")
async def health_check():
    """Health check del Controller"""
    acapy_status = await check_acapy_connection()
    
    return {
        "status": "healthy" if acapy_status else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "acapy": "up" if acapy_status else "down",
            "fabric": "up" if fabric_client else "down"
        }
    }

# COMPATIBILIDAD: Endpoint para Fases 1-3 (estructura original)
@app.post("/api/issue-credential", response_model=ConnectionInvitationResponse)
async def issue_credential_compatible(moodle_request: MoodleCredentialRequest):
    """
    ENDPOINT DE COMPATIBILIDAD: Para Fases 1-3 con estructura original
    Convierte el formato original a la estructura nueva y procesa
    """
    try:
        logger.info(f"📨 [COMPATIBILIDAD] Nueva solicitud de credencial para: {moodle_request.userName}")
        
        # Convertir estructura original a nueva estructura
        credential_request = StudentCredentialRequest(
            student_id=str(moodle_request.userId),
            student_name=moodle_request.userName,
            student_email=moodle_request.userEmail,
            course_id=str(moodle_request.courseId),
            course_name=moodle_request.courseName,
            completion_date=moodle_request.completionDate,
            grade="A",  # Valor por defecto para compatibilidad
            instructor_name="Sistema Moodle"  # Valor por defecto para compatibilidad
        )
        
        # Delegar al endpoint principal
        return await request_credential(credential_request)
        
    except Exception as e:
        logger.error(f"❌ Error en endpoint de compatibilidad: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error procesando solicitud: {str(e)}")

@app.post("/api/credential/request", response_model=ConnectionInvitationResponse)
async def request_credential(credential_request: StudentCredentialRequest):
    """
    ENDPOINT PRINCIPAL: Procesar solicitud de credencial desde Moodle
    Retorna invitación de conexión para que estudiante use su wallet
    """
    try:
        logger.info(f"📨 Nueva solicitud de credencial para: {credential_request.student_name}")
        
        # 1. Registrar en Hyperledger Fabric
        if fabric_client:
            try:
                fabric_result = await fabric_client.register_credential(credential_request.dict())
                logger.info(f"✅ Registrado en Fabric: {fabric_result}")
            except Exception as e:
                logger.warning(f"⚠️ Error registrando en Fabric (continuando): {e}")
        
        # 2. Crear conexión en ACA-Py usando out-of-band
        async with httpx.AsyncClient() as client:
            invitation_response = await client.post(
                f"{ACAPY_ADMIN_URL}/out-of-band/create-invitation",
                json={
                    "alias": f"Estudiante-{credential_request.student_name}",
                    "auto_accept": True,
                    "handshake_protocols": ["https://didcomm.org/didexchange/1.0"],
                    "use_public_did": False
                }
            )
            
            if invitation_response.status_code != 200:
                raise HTTPException(status_code=500, detail="Error creando invitación de conexión")
            
            invitation_data = invitation_response.json()
            connection_id = invitation_data["oob_id"]  # out-of-band usa oob_id en lugar de connection_id
            invitation_url = invitation_data["invitation_url"]
            
            logger.info(f"🔗 Invitación out-of-band creada: {connection_id}")
            
            # 3. Generar QR Code
            qr_code_base64 = qr_generator.generate_qr(invitation_url)
            
            # 4. Almacenar QR temporalmente para visualización web
            qr_storage[connection_id] = {
                "qr_code_base64": qr_code_base64,
                "invitation_url": invitation_url,
                "student_name": credential_request.student_name,
                "course_name": credential_request.course_name,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # 5. Almacenar datos para posterior emisión de credencial
            # (En producción, usar base de datos)
            await store_pending_credential(connection_id, credential_request)
            
            return ConnectionInvitationResponse(
                invitation_url=invitation_url,
                qr_code_base64=qr_code_base64,
                connection_id=connection_id
            )
            
    except Exception as e:
        logger.error(f"❌ Error procesando solicitud: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/credential/issue/{connection_id}")
async def issue_credential(connection_id: str, background_tasks: BackgroundTasks):
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

# WEBHOOKS de ACA-Py (para automatización)

@app.post("/webhooks/connections")
async def webhook_connections(data: dict):
    """Webhook para eventos de conexión"""
    logger.info(f"🔔 Webhook conexión: {data.get('state', 'unknown')}")
    
    if data.get("state") == "active":
        connection_id = data.get("connection_id")
        if connection_id:
            # Emitir credencial automáticamente cuando conexión esté activa
            logger.info(f"✅ Conexión activa, emitiendo credencial: {connection_id}")
            # En background para no bloquear webhook
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

# FUNCIONES AUXILIARES

async def store_pending_credential(connection_id: str, credential_data: StudentCredentialRequest):
    """Almacenar datos de credencial pendiente (En producción: BD)"""
    # Por ahora usar archivo temporal (EN PRODUCCIÓN USAR BASE DE DATOS)
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
        import os
        temp_file = f"/tmp/pending_credential_{connection_id}.json"
        os.remove(temp_file)
    except:
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
    except:
        return None

async def issue_credential_background(connection_id: str):
    """Emitir credencial en background"""
    try:
        await asyncio.sleep(2)  # Esperar un poco para que conexión se estabilice
        await issue_credential(connection_id, None)
    except Exception as e:
        logger.error(f"Error en emisión background: {e}")

# ENDPOINT COMPATIBILIDAD MOODLE (mantener API anterior)

@app.post("/api/credenciales")
async def legacy_credential_endpoint(data: dict):
    """Endpoint de compatibilidad con Moodle (API anterior)"""
    try:
        # Convertir formato anterior al nuevo
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
        
        result = await request_credential(credential_request)
        
        # Formato compatible
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

# ==================== ENDPOINT PARA MOSTRAR QR ====================

@app.get("/qr/{connection_id}", response_class=HTMLResponse)
async def show_qr_page(connection_id: str):
    """
    Mostrar página HTML con QR Code escaneables para conexión DIDComm
    """
    try:
        # Buscar QR en storage temporal
        if connection_id not in qr_storage:
            raise HTTPException(status_code=404, detail="QR Code no encontrado o expirado")
        
        qr_data = qr_storage[connection_id]
        
        # Página HTML simple con QR
        html_content = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Credencial W3C - Universidad</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
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
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    text-align: center;
                    max-width: 500px;
                    width: 100%;
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 10px;
                    font-size: 2em;
                }}
                .subtitle {{
                    color: #666;
                    margin-bottom: 30px;
                    font-size: 1.1em;
                }}
                .qr-container {{
                    background: #f8f9fa;
                    border-radius: 15px;
                    padding: 20px;
                    margin: 20px 0;
                    border: 3px solid #e9ecef;
                }}
                .qr-code {{
                    max-width: 280px;
                    width: 100%;
                    height: auto;
                }}
                .course-info {{
                    background: #e3f2fd;
                    border-radius: 10px;
                    padding: 15px;
                    margin: 20px 0;
                    border-left: 4px solid #2196f3;
                }}
                .student-name {{
                    font-weight: bold;
                    color: #1976d2;
                    font-size: 1.2em;
                }}
                .course-name {{
                    color: #424242;
                    margin-top: 5px;
                }}
                .instructions {{
                    background: #fff3e0;
                    border-radius: 10px;
                    padding: 15px;
                    margin: 20px 0;
                    border-left: 4px solid #ff9800;
                    text-align: left;
                }}
                .instructions h3 {{
                    color: #e65100;
                    margin-top: 0;
                }}
                .instructions ol {{
                    color: #bf360c;
                    line-height: 1.6;
                }}
                .wallet-list {{
                    display: flex;
                    justify-content: center;
                    gap: 10px;
                    margin: 15px 0;
                    flex-wrap: wrap;
                }}
                .wallet {{
                    background: #4caf50;
                    color: white;
                    padding: 5px 12px;
                    border-radius: 20px;
                    font-size: 0.9em;
                    font-weight: bold;
                }}
                .timestamp {{
                    color: #999;
                    font-size: 0.9em;
                    margin-top: 20px;
                }}
                .url-link {{
                    background: #f5f5f5;
                    border-radius: 5px;
                    padding: 10px;
                    margin: 10px 0;
                    font-family: monospace;
                    font-size: 0.8em;
                    word-break: break-all;
                    color: #555;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🎓 Credencial Universitaria</h1>
                <p class="subtitle">Credencial Verificable W3C</p>
                
                <div class="course-info">
                    <div class="student-name">👤 {qr_data['student_name']}</div>
                    <div class="course-name">📚 {qr_data['course_name']}</div>
                </div>
                
                <div class="qr-container">
                    <img src="{qr_data['qr_code_base64']}" 
                         alt="QR Code para Wallet" 
                         class="qr-code">
                </div>
                
                <div class="instructions">
                    <h3>📱 Instrucciones:</h3>
                    <ol>
                        <li>Abre tu wallet de credenciales en tu móvil</li>
                        <li>Busca la opción "Escanear QR" o "Recibir Credencial"</li>
                        <li>Escanea el código QR de arriba</li>
                        <li>Acepta la conexión DIDComm</li>
                        <li>Tu credencial será transferida automáticamente</li>
                    </ol>
                    
                    <div class="wallet-list">
                        <span class="wallet">Lissi</span>
                        <span class="wallet">Trinsic</span>
                        <span class="wallet">Esatus</span>
                    </div>
                </div>
                
                <div class="url-link">
                    <strong>URL de Invitación:</strong><br>
                    {qr_data['invitation_url'][:50]}...
                </div>
                
                <div class="timestamp">
                    ⏰ Generado: {qr_data['timestamp']}<br>
                    🔑 ID: {connection_id}
                </div>
            </div>
        </body>
        </html>
        """
        
        logger.info(f"📱 Página QR solicitada para conexión: {connection_id}")
        return HTMLResponse(content=html_content)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error mostrando QR: {e}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")

# ============================================================================
# ENDPOINT: Metadata OpenID4VC en ruta raíz (requerido por DIDRoom Wallet)
# ============================================================================
@app.get("/.well-known/openid-credential-issuer")
async def root_credential_issuer_metadata():
    """
    Metadata OpenID4VC en ruta raíz
    Compatible con múltiples versiones del estándar
    """
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
    
    return JSONResponse(content=metadata)

@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata():
    """
    OAuth 2.0 Authorization Server Metadata (RFC 8414)
    """
    issuer_url = os.getenv("ISSUER_URL", "https://api-credenciales.utnpf.site")
    
    metadata = {
        "issuer": issuer_url,
        "authorization_endpoint": f"{issuer_url}/oid4vc/authorize",  # ← AGREGAR
        "token_endpoint": f"{issuer_url}/oid4vc/token",
        "jwks_uri": f"{issuer_url}/oid4vc/.well-known/jwks.json",
        "pushed_authorization_request_endpoint": f"{issuer_url}/oid4vc/par",
        "grant_types_supported": [
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "authorization_code"  # ← AGREGAR (para declarar soporte)
        ],
        "token_endpoint_auth_methods_supported": ["none"],
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True,
        "response_types_supported": ["code"],  # ← AGREGAR
        "response_modes_supported": ["query"],  # ← AGREGAR
        "code_challenge_methods_supported": ["S256"],
    }
    
    return JSONResponse(content=metadata)

if __name__ == "__main__":
    import uvicorn
    logger.info(f"🚀 Iniciando Controller en puerto {CONTROLLER_PORT}")
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=CONTROLLER_PORT,
        reload=False,  # En producción
        log_level="info"
    )