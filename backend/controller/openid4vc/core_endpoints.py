#!/usr/bin/env python3
"""
OpenID4VC Core Endpoints — Offer, Auth, Token, Credential

Implementación completa del flujo OID4VCI con soporte dual de grants
(pre-authorized_code y authorization_code) y multi-formato de credenciales
(vc+sd-jwt y jwt_vc_json) vía Strategy Pattern.

Las configuraciones de credenciales provienen del ``credential_registry``.
Los formateadores de credenciales provienen de ``credential_formatters``.
"""

import json
import secrets
import jwt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from urllib.parse import quote
from fastapi import APIRouter, HTTPException, Header, Request, Query
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
import structlog

from session_manager import session_manager
from pkce_validator import PKCEValidator
from storage import qr_storage
from .config import (
    ISSUER_URL,
    ISSUER_DID,
    PRIVATE_KEY,
    CredentialOfferRequest
)
from .credential_registry import get_all_config_ids
from .credential_formatters import (
    resolve_format,
    format_credential,
    build_credential_response,
)
from .helpers import add_security_headers, extract_holder_did_from_proof, extract_issuer_state_from_par

logger = structlog.get_logger()

# Router for core endpoints
core_router = APIRouter()

# Temporary mapping for request_uri -> session_id
request_uri_to_session = {}

# ============================================================================
# CREDENTIAL OFFER GENERATION
# ============================================================================

async def generate_credential_offer(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Genera Credential Offer con DUAL GRANT support.

    Grants incluidos:
        • ``pre-authorized_code`` — Flujo directo, sin browser (Lissi, WaltID)
        • ``authorization_code`` — Flujo con PAR → /authorize → HTML (DIDRoom)

    Las configuraciones de credenciales provienen del ``credential_registry``.
    """
    student_id = request_data.get("student_id")
    student_email = request_data.get("student_email")
    student_name = request_data.get("student_name")
    course_name = request_data.get("course_name")

    logger.info("📨 [DUAL-GRANT] Generando Credential Offer", student=student_name)
    
    # Crear sesión
    session_id = session_manager.create_session(credential_data=request_data, expires_in=600)
    
    # Generar o usar pre_auth_code (Respetar el enviado por Moodle)
    pre_auth_code = request_data.get("pre_authorized_code")
    if not pre_auth_code:
        timestamp = int(datetime.now().timestamp())
        pre_auth_code = f"pre_auth_{student_id}_{timestamp}_{hash(student_email) % 10000}"
    session_manager.link_pre_auth_code(session_id, pre_auth_code)
    
    # ================================================================
    # CREDENTIAL OFFER — Dual Grant + Multi-Format
    # ================================================================
    #
    # Grants incluidos:
    #   • pre-authorized_code — Lissi usa AcceptOffer() (API-only, sin browser)
    #   • authorization_code  — DIDRoom usa InitiateAuthFlow() (PAR → /authorize)
    #
    # Config IDs: Provienen del credential_registry (fuente única de verdad).
    # La metadata incluye credential_definition (jwt_vc_json) Y vct (sd-jwt)
    # en la misma configuración para que cada wallet lea lo que entiende.
    #
    # Nota sobre Lissi y auth_code:
    #   Cuando ambos grants están presentes, Lissi prioriza authorization_code
    #   lo que causa un loop "Processing Request..." por un bug del Activity
    #   lifecycle de Android en la app Lissi (la credencial sí se almacena).
    #   Es un bug de la app Lissi, no del backend.  Se mantiene auth_code
    #   para compatibilidad con DIDRoom.
    # ================================================================
    offer = {
        "credential_issuer": ISSUER_URL,
        "credential_configuration_ids": get_all_config_ids(),
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_auth_code
            },
            "authorization_code": {
                "issuer_state": session_id
            }
        }
    }
    
    # Guardar session_id en metadata para PAR flow (no en el offer)
    # Esto permite que wallets como DIDRoom usen PAR sin confundirse
    
    logger.info(f"✅ Offer creado - Pre-auth: {pre_auth_code[:20]}... Session: {session_id[:20]}...")
    
    # Generar QR
    offer_json = json.dumps(offer, separators=(',', ':'))
    logger.info(f"📤 OFFER JSON GENERADO: {offer_json}")  # DEBUG: Ver qué estamos enviando exactamente
    offer_encoded = quote(offer_json, safe='')
    qr_url = f"openid-credential-offer://?credential_offer={offer_encoded}"
    
    # Generar QR image
    qr_code_base64 = ""
    try:
        from qr_generator import QRGenerator
        qr_gen = QRGenerator()
        qr_code_base64 = qr_gen.generate_qr(qr_url) or ""
        logger.info("✅ QR generado")
    except Exception as e:
        logger.error(f"❌ Error generando QR: {e}")
    
    # Almacenar para display web
    qr_storage[pre_auth_code] = {
        "qr_code_base64": qr_code_base64,
        "qr_url": qr_url,
        "student_name": student_name,
        "course_name": course_name,
        "timestamp": datetime.now().isoformat(),
        "expires_at": (datetime.now() + timedelta(minutes=10)).isoformat(),
        "type": "openid4vc_dual_grant",
        "session_id": session_id
    }

    return {
        "qr_url": qr_url,
        "qr_code_base64": qr_code_base64,
        "pre_authorized_code": pre_auth_code,
        "session_id": session_id,
        "offer": offer,
        "web_qr_url": f"{ISSUER_URL}/oid4vc/qr/{pre_auth_code}",
        "compatibility": {
            "walt_id": True,
            "didroom": True,
            "lissi": True,
            "flows_supported": ["pre-authorized", "authorization_code"]
        }
    }

@core_router.post("/credential-offer")
async def create_credential_offer_endpoint(request: CredentialOfferRequest):
    """Endpoint para crear Credential Offer"""
    try:
        logger.info(f"🆕 Creating Credential Offer for: {request.student_name}")
        
        if len(request.student_id) < 3:
            raise HTTPException(status_code=400, detail="Student ID debe tener al menos 3 caracteres")
        
        response_data = await generate_credential_offer(request.dict())
        response = JSONResponse(content=response_data)
        return await add_security_headers(response)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error creating offer: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@core_router.get("/test-credential")
async def test_credential_endpoint():
    """
    Endpoint de prueba: Genera una credencial de test y redirige a la página del QR
    Útil para testing rápido del flujo OpenID4VCI con diferentes wallets
    """
    try:
        logger.info("🧪 Generando credencial de PRUEBA")
        
        # Datos de prueba
        test_data = {
            "student_id": f"test_{int(datetime.now().timestamp())}",
            "student_name": "Estudiante de Prueba",
            "student_email": "prueba@utn.edu.ar",
            "course_id": "TEST001",
            "course_name": "Curso de Prueba OpenID4VCI",
            "completion_date": datetime.now().isoformat(),
            "grade": "10",
            "instructor_name": "Prof. Test"
        }
        
        # Generar oferta
        offer_result = await generate_credential_offer(test_data)
        
        pre_auth_code = offer_result.get("pre_authorized_code")
        
        # Redirigir a la página del QR
        return RedirectResponse(url=f"/oid4vc/qr/{pre_auth_code}", status_code=303)
        
    except Exception as e:
        logger.error(f"❌ Error generando credencial de prueba: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# PAR ENDPOINT
# ============================================================================

@core_router.post("/par")
async def par_endpoint(request: Request):
    """
    Pushed Authorization Request (PAR) endpoint - RFC 9126
    Usado por DIDRoom y otras wallets para iniciar flujo de autorización
    """
    try:
        form_data = await request.form()
        form_dict = dict(form_data)
        
        logger.info("=" * 80)
        logger.info("🔐 PAR endpoint llamado")
        logger.info(f"   Client ID: {form_dict.get('client_id', 'Unknown')[:50]}...")
        logger.info("=" * 80)
        
        issuer_state = form_dict.get("issuer_state")
        session = None
        
        if issuer_state:
            logger.info(f"   Issuer State: {issuer_state[:20]}...")
            session = session_manager.get_session(issuer_state)
            
        if not session:
            logger.warning("⚠️ No valid issuer_state found in PAR, falling back to most recent session")
            session = session_manager.get_most_recent_session()
        
        if not session:
            logger.error("❌ No active sessions found")
            raise HTTPException(status_code=400, detail="No active credential offer session found")
        
        session_id = session["session_id"]
        logger.info(f"✅ Using session: {session_id[:20]}... for student: {session['credential_data'].get('student_name')}")
        
        # Vincular datos PAR a la sesión
        session_manager.link_authorization_request(session_id, form_dict)
        
        # Generar request_uri
        request_uri = f"urn:ietf:params:oauth:request_uri:{secrets.token_urlsafe(32)}"
        session_manager.link_request_uri(request_uri, session_id)
        
        logger.info(f"✅ PAR request_uri generado: {request_uri[:50]}...")
        logger.info("=" * 80)
        
        response_data = {
            "request_uri": request_uri,
            "expires_in": 300
        }
        
        response = JSONResponse(content=response_data, status_code=201)
        response.headers["Cache-Control"] = "no-store"
        return await add_security_headers(response)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error in PAR endpoint: {e}")
        import traceback
        logger.error(traceback.format_exc())
        
        error_response = {
            "error": "server_error",
            "error_description": str(e)
        }
        return JSONResponse(content=error_response, status_code=500)

# ============================================================================
# AUTHORIZE CONFIRM ENDPOINT (Para HTML Browser fallback)
# ============================================================================

from fastapi import Form
from fastapi.responses import RedirectResponse

@core_router.post("/authorize/confirm")
async def authorize_confirm_endpoint(redirect_url: str = Form(...)):
    """
    Transmisión de consentimiento puenteada por backend.
    Cuando el usuario presiona "Aceptar" en la página de consentimiento HTML,
    este endpoint recibe la URL de redirect y la ejecuta.
    
    Para wallets nativas (custom URI scheme): sirve trampoline HTML con JS.
    Para wallets web (HTTP/HTTPS redirect): usa 302 redirect estándar.
    """
    from urllib.parse import urlparse
    
    parsed = urlparse(redirect_url)
    is_native_scheme = parsed.scheme not in ("http", "https", "")
    
    if is_native_scheme:
        logger.info(f"⚡ [HTML Consent] Click recibido. Sirviendo deep-link trampoline -> {redirect_url[:80]}...")
        return _build_deep_link_trampoline(redirect_url)
    else:
        logger.info(f"⚡ [HTML Consent] Click recibido. Ejecutando Redirect 302 -> {redirect_url[:80]}...")
        return RedirectResponse(url=redirect_url, status_code=302)

# ============================================================================
# DEEP-LINK TRAMPOLINE (cierra correctamente Chrome Custom Tabs)
# ============================================================================

def _build_deep_link_trampoline(deep_link_url: str) -> HTMLResponse:
    """
    Genera una página HTML "trampoline" que redirige al custom URI scheme
    de la wallet nativa mediante JavaScript.
    
    ¿Por qué no un simple 302?
    Chrome Custom Tabs bloquea los redirects HTTP (302/303) a URI schemes
    no-HTTP (ej: id.lissi.mobile://) por política de seguridad "user gesture
    requirement". Esto deja el Custom Tab abierto encima de la wallet.
    
    Un window.location.href en JavaScript SÍ es aceptado por Chrome como
    navegación válida, lo que permite:
    1. Que el Intent de Android se dispare correctamente
    2. Que el Custom Tab se cierre al perder el foco
    3. Que la wallet reciba el authorization code y complete el flujo
    
    Incluye un link de fallback por si JavaScript está deshabilitado.
    """
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redirigiendo a tu Wallet...</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                         Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 100%;
            padding: 40px 30px;
            text-align: center;
        }}
        .spinner {{
            width: 48px;
            height: 48px;
            border: 4px solid #e0e0e0;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        h2 {{
            color: #333;
            font-size: 20px;
            margin-bottom: 12px;
        }}
        p {{
            color: #666;
            font-size: 14px;
            line-height: 1.5;
        }}
        .fallback-link {{
            display: inline-block;
            margin-top: 20px;
            padding: 12px 28px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 15px;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }}
        .fallback-link:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="spinner"></div>
        <h2>Redirigiendo a tu Wallet...</h2>
        <p>Si no se abre automáticamente, presiona el botón:</p>
        <a href="{deep_link_url}" class="fallback-link">Abrir Wallet</a>
    </div>
    <script>
        // Navegar al deep link usando JS — Chrome Custom Tabs acepta esto 
        // como navegación válida (a diferencia de 302 HTTP).
        window.location.href = "{deep_link_url}";
    </script>
</body>
</html>"""
    return HTMLResponse(content=html)

# ============================================================================
# AUTHORIZE ENDPOINT
# ============================================================================

@core_router.get("/authorize")
async def authorize_endpoint(
    request: Request,
    client_id: Optional[str] = Query(None),
    response_type: Optional[str] = Query(None),
    redirect_uri: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    code_challenge: Optional[str] = Query(None),
    code_challenge_method: Optional[str] = Query(None),
    issuer_state: Optional[str] = Query(None),
    authorization_details: Optional[str] = Query(None),
    scope: Optional[str] = Query(None),
    request_uri: Optional[str] = Query(None)
):
    """
    OAuth 2.0 Authorization Endpoint con AUTO-APROBACIÓN para usuarios pre-autenticados
    
    En nuestro caso de uso, el usuario YA VIENE AUTENTICADO desde Moodle,
    por lo que no necesitamos una pantalla de consentimiento.
    Este endpoint aprueba automáticamente la solicitud y redirige a la wallet.
    
    Acepta AMBOS flujos:
    - Directo con issuer_state (flujo directo sin PAR)
    - Con request_uri (flujo PAR - DIDRoom, WaltID, etc.)
    """
    logger.info("=" * 80)
    logger.info("🔓 AUTHORIZE ENDPOINT LLAMADO [AUTO-APPROVAL MODE]")
    logger.info("=" * 80)
    
    # LOG COMPLETO de todos los parámetros recibidos
    logger.info(f"📥 client_id: {client_id}")
    logger.info(f"📥 response_type: {response_type}")
    logger.info(f"📥 redirect_uri: {redirect_uri}")
    logger.info(f"📥 state (wallet): {state}")
    logger.info(f"📥 code_challenge: {code_challenge[:20] if code_challenge else 'None'}...")
    logger.info(f"📥 code_challenge_method: {code_challenge_method}")
    logger.info(f"📥 issuer_state (session_id): {issuer_state}")
    logger.info(f"📥 authorization_details: {authorization_details}")
    logger.info(f"📥 scope: {scope}")
    logger.info(f"📥 request_uri: {request_uri}")
    
    # Log de query params completos
    query_params = dict(request.query_params)
    logger.info(f"📋 Query params completos: {list(query_params.keys())}")
    
    try:
        # Estrategia 1: Buscar por issuer_state directo (flujo sin PAR)
        session = None
        session_id = None
        par_data_from_session = None
        
        if issuer_state:
            logger.info(f"✅ [FLUJO DIRECTO] issuer_state recibido: {issuer_state[:30]}...")
            session = session_manager.get_session(issuer_state)
            if session:
                session_id = issuer_state
                logger.info(f"✅ Sesión encontrada por issuer_state")
            else:
                logger.error(f"❌ Sesión NO encontrada para issuer_state: {issuer_state[:30]}...")
                raise HTTPException(status_code=400, detail="Invalid issuer_state - session not found or expired")
        
        # Estrategia 2: Buscar por request_uri (flujo con PAR - DIDRoom)
        elif request_uri:
            logger.info(f"🔍 [FLUJO PAR] request_uri recibido: {request_uri[:50]}...")
            session = session_manager.get_session_by_request_uri(request_uri)
            if session:
                session_id = session["session_id"]
                logger.info(f"✅ Sesión encontrada por request_uri")
                
                # Obtener datos PAR que fueron guardados previamente
                auth_flow = session.get("flows", {}).get("authorization")
                if auth_flow and auth_flow.get("par_data"):
                    par_data_from_session = auth_flow["par_data"]
                    logger.info(f"📋 PAR data recuperado de la sesión")
                    logger.info(f"   - redirect_uri: {par_data_from_session.get('redirect_uri')}")
                    logger.info(f"   - client_id: {par_data_from_session.get('client_id', '')[:50]}...")
                    logger.info(f"   - code_challenge presente: {bool(par_data_from_session.get('code_challenge'))}")
            else:
                logger.error(f"❌ Sesión NO encontrada para request_uri: {request_uri[:50]}...")
                raise HTTPException(status_code=400, detail="Invalid request_uri")
        
        else:
            logger.error("❌ No issuer_state NI request_uri recibidos")
            logger.error(f"   Parámetros disponibles: {list(query_params.keys())}")
            raise HTTPException(
                status_code=400,
                detail="Missing issuer_state or request_uri - cannot identify session"
            )
        
        # Si tenemos PAR data de la sesión, usarlo como fuente de verdad
        # (DIDRoom envía estos datos en PAR, no en /authorize)
        if par_data_from_session:
            logger.info("🔄 Usando datos del PAR request almacenados en la sesión")
            redirect_uri = redirect_uri or par_data_from_session.get("redirect_uri")
            code_challenge = code_challenge or par_data_from_session.get("code_challenge")
            code_challenge_method = code_challenge_method or par_data_from_session.get("code_challenge_method")
            client_id = client_id or par_data_from_session.get("client_id")
            state = state or par_data_from_session.get("state")
        
        # Validaciones
        if not redirect_uri:
            logger.error("❌ redirect_uri faltante")
            raise HTTPException(status_code=400, detail="redirect_uri required")
        
        if not code_challenge:
            logger.warning("⚠️ code_challenge NO disponible - PKCE podría fallar en /token")
        
        # Vincular o actualizar code_challenge en la sesión si existe
        if code_challenge and session_id:
            logger.info(f"🔐 Vinculando PKCE challenge a sesión")
            # Actualizar sesión con datos de autorización
            auth_data = {
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method or "S256",
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "state": state,
                "authorization_details": authorization_details,
                "scope": scope
            }
            session_manager.link_authorization_request(session_id, auth_data)
        
        #  🎯 GENERAR Authorization Code pero MOSTRAR HTML CON BOTÓN
        # DIDRoom abre este endpoint en un webview y necesita ver HTML
        logger.info("🎯 Generando authorization code y mostrando página de consentimiento")
        
        auth_code = f"auth_code_{secrets.token_urlsafe(32)}"
        session_manager.link_authorization_code(session_id, auth_code)
        
        logger.info(f"✅ Authorization code generado: {auth_code[:20]}...")
        logger.info(f"🔗 Vinculado a session: {session_id[:20]}...")
        logger.info(f"👤 Usuario: {session['credential_data'].get('student_name', 'Unknown')}")
        
        # Construir URL de redirect
        from urllib.parse import urlencode
        params = {
            "code": auth_code,
            "state": state or ""
        }
        redirect_url = f"{redirect_uri}?{urlencode(params)}"
        
        logger.info(f"↩️ URL de redirect preparado: {redirect_url[:100]}...")
        logger.info("📄 Devolviendo HTML con botón de consentimiento")
        logger.info("=" * 80)
        
        # Devolver HTML con botón de consentimiento
        logger.info(f"↩️ URL de redirect preparado: {redirect_url}")
        
        # ⚡ DETECCIÓN INTELIGENTE DE WALLET NATIVA
        # Las wallets nativas (Lissi, Sphereon, etc.) registran custom URI schemes
        # como deep links (ej: "id.lissi.mobile://", "openid4vci://"). Cuando
        # Android abre un Custom Tab para /authorize, un simple 302 redirect a
        # un custom scheme es BLOQUEADO por la política de seguridad de Chrome
        # ("user gesture requirement"). Esto deja el Custom Tab abierto encima
        # de la wallet, causando el loop "Processing Request...".
        #
        # La solución correcta es servir una "trampoline page" HTML minimalista
        # que use JavaScript (window.location.href) para navegar al deep link.
        # Chrome trata la navegación JS como válida y permite que el Intent
        # se dispare, cerrando el Custom Tab correctamente.
        #
        # Las wallets web (DIDRoom, etc.) usan redirect_uri HTTP y SÍ necesitan
        # ver el HTML con formulario de consentimiento porque ejecutan el flujo
        # dentro de un webview/iframe.
        import os
        from urllib.parse import urlparse
        
        bypass_env = os.getenv("BYPASS_CONSENT_SCREEN", "auto").lower()
        
        if bypass_env == "true":
            # Override explícito: siempre usar trampoline sin pantalla de consentimiento
            logger.info("⚡ Realizando deep-link trampoline (BYPASS_CONSENT_SCREEN=true)")
            return _build_deep_link_trampoline(redirect_url)
        
        if bypass_env == "false":
            # Override explícito: siempre mostrar pantalla de consentimiento
            logger.info("📄 Mostrando pantalla de consentimiento (BYPASS_CONSENT_SCREEN=false)")
        elif bypass_env == "auto" and redirect_uri:
            # Detección automática: redirect_uri con custom scheme → wallet nativa
            parsed_redirect = urlparse(redirect_uri)
            is_native_wallet = parsed_redirect.scheme not in ("http", "https", "")
            
            if is_native_wallet:
                logger.info(f"⚡ Wallet nativa detectada (scheme: {parsed_redirect.scheme}). "
                            f"Sirviendo deep-link trampoline HTML.")
                return _build_deep_link_trampoline(redirect_url)
            
        student_name = session['credential_data'].get('student_name', 'Usuario')
        course_name = session['credential_data'].get('course_name', 'Curso')
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Autorizar Credencial</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                .container {{
                    background: white;
                    border-radius: 16px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    max-width: 480px;
                    width: 100%;
                    padding: 40px 30px;
                    text-align: center;
                }}
                .icon {{
                    font-size: 64px;
                    margin-bottom: 20px;
                }}
                h1 {{
                    color: #333;
                    font-size: 24px;
                    margin-bottom: 16px;
                }}
                .credential-info {{
                    background: #f8f9fa;
                    border-radius: 12px;
                    padding: 20px;
                    margin: 20px 0 30px 0;
                    border-left: 4px solid #667eea;
                }}
                .label {{
                    color: #666;
                    font-size: 12px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    margin-bottom: 4px;
                }}
                .value {{
                    color: #333;
                    font-size: 16px;
                    font-weight: 600;
                    margin-bottom: 12px;
                }}
                .value:last-child {{
                    margin-bottom: 0;
                }}
                .btn {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    padding: 16px 40px;
                    font-size: 16px;
                    font-weight: 600;
                    border-radius: 8px;
                    cursor: pointer;
                    width: 100%;
                    transition: transform 0.2s, box-shadow 0.2s;
                    box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
                }}
                .btn:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
                }}
                .btn:active {{
                    transform: translateY(0);
                }}
                .info-text {{
                    color: #666;
                    font-size: 14px;
                    margin-top: 20px;
                    line-height: 1.5;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">🎓</div>
                <h1>Recibir Credencial Universitaria</h1>
                
                <div class="credential-info">
                    <div>
                        <div class="label">Estudiante</div>
                        <div class="value">{student_name}</div>
                    </div>
                    <div>
                        <div class="label">Curso</div>
                        <div class="value">{course_name}</div>
                    </div>
                </div>
                
                <form action="/oid4vc/authorize/confirm" method="POST">
                    <input type="hidden" name="redirect_url" value="{redirect_url}">
                    <button type="submit" class="btn" style="width: 100%; display: block;">
                        ✓ Aceptar y Recibir Credencial
                    </button>
                </form>
                
                <p class="info-text">
                    Al aceptar, recibirás una credencial verificable en tu wallet digital.
                </p>
            </div>
        </body>
        </html>
        """
        
        return HTMLResponse(content=html_content)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("=" * 80)
        logger.error(f"❌ ERROR CRÍTICO en authorize endpoint: {e}")
        import traceback
        logger.error(traceback.format_exc())
        logger.error("=" * 80)
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "error_description": str(e)}
        )

# ============================================================================
# TOKEN ENDPOINT
# ============================================================================

@core_router.post("/token")
async def token_endpoint(request: Request):
    """
    OAuth 2.0 Token Endpoint con PKCE validation
    Soporta AMBOS flujos: pre-authorized y authorization_code
    """
    logger.info("🔍 Token endpoint llamado")
    
    try:
        form_data = await request.form()
        form_dict = dict(form_data)
        
        grant_type = form_dict.get("grant_type", "")
        logger.info(f"🎯 Grant type: {grant_type}")
        
        session = None
        
        # 🔀 CORRECCIÓN ESPECIAL PARA DIDROOM
        # DIDRoom a veces envía grant_type=pre-authorized_code pero con un "code" (authorization_code)
        # Detectamos esto y corregimos el grant_type
        has_code = "code" in form_dict and form_dict["code"].startswith("auth_code_")
        has_pre_auth = "pre-authorized_code" in form_dict or "pre_authorized_code" in form_dict
        
        if grant_type == "urn:ietf:params:oauth:grant-type:pre-authorized_code" and has_code and not has_pre_auth:
            logger.warning("⚠️ DIDRoom quirk detected: grant_type says 'pre-authorized_code' but sending 'code'")
            logger.warning("   Auto-correcting to authorization_code flow")
            grant_type = "authorization_code"
        
        # === FLUJO 1: Pre-Authorized Code (WaltID) ===
        if grant_type == "urn:ietf:params:oauth:grant-type:pre-authorized_code":
            logger.info("   ℹ️  Flujo PRE-AUTHORIZED")
            
            pre_auth_code = form_dict.get("pre-authorized_code") or form_dict.get("pre_authorized_code")
            if not pre_auth_code:
                raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "Missing pre-authorized_code"})
            
            session = session_manager.get_by_pre_auth_code(pre_auth_code)
            if not session:
                logger.error(f"❌ Pre-auth code not found: {pre_auth_code[:20]}...")
                raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Code not found or expired"})
            
            logger.info(f"✅ Pre-auth code válido")
        
        # === FLUJO 2: Authorization Code (DIDRoom) ===
        elif grant_type == "authorization_code":
            logger.info("   ℹ️  Flujo AUTHORIZATION CODE")
            
            code = form_dict.get("code")
            code_verifier = form_dict.get("code_verifier")
            
            if not code:
                raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "Missing code"})
            
            session = session_manager.get_by_auth_code(code)
            if not session:
                logger.error(f"❌ Authorization code not found: {code[:20]}...")
                raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Code not found or expired"})
            
            # ✅ VALIDAR PKCE
            if code_verifier:
                if not session_manager.validate_pkce(session["session_id"], code_verifier):
                    logger.error("❌ PKCE validation FAILED")
                    raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Invalid code_verifier"})
                
                logger.info("✅ PKCE validation SUCCESS")
            else:
                logger.warning("⚠️ No code_verifier provided")
        
        else:
            raise HTTPException(status_code=400, detail={"error": "unsupported_grant_type"})
        
        # === GENERAR ACCESS TOKEN ===
        access_token = f"access_{secrets.token_urlsafe(32)}"
        c_nonce = secrets.token_urlsafe(32)
        
        session_manager.link_access_token(session["session_id"], access_token, c_nonce)
        
        logger.info(f"✅ Access token generado: {access_token[:20]}...")
        
        response_data = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 600,
            "c_nonce": c_nonce,
            "c_nonce_expires_in": 300,
            "authorization_details": [
                {
                    "type": "openid_credential",
                    "credential_configuration_id": config_id,
                }
                for config_id in get_all_config_ids()
            ]
        }
        
        response = JSONResponse(content=response_data)
        return await add_security_headers(response)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error in token endpoint: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": str(e)})

# ============================================================================
# CREDENTIAL ENDPOINT
# ============================================================================

from fastapi import BackgroundTasks

@core_router.post("/credential")
async def credential_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: Optional[str] = Header(None, alias="Authorization")
):
    """
    Credential Issuance Endpoint — OID4VCI §7

    Emite la credencial firmada en el formato que la wallet solicita.
    El formato se resuelve automáticamente desde el request body de la
    wallet (campo ``format`` o ``credential_configuration_id``) y se
    despacha al formateador correcto via Strategy Pattern.

    Formatos soportados:
        • ``vc+sd-jwt``   — SD-JWT VC (Lissi, EUDI, Paradym)
        • ``jwt_vc_json`` — W3C VC JWT (DIDRoom, WaltID)
    """
    logger.info("🎓 Credential endpoint llamado")

    try:
        # ─── Extraer access token del header Authorization ───
        auth_header = authorization or request.headers.get("authorization")

        if not auth_header or " " not in auth_header:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_token", "error_description": "Authorization header required"},
            )

        parts = auth_header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_token", "error_description": "Invalid format"},
            )

        access_token = parts[1]
        logger.info(f"🔑 Token: {access_token[:20]}...")

        # ─── Buscar sesión vinculada al token ───
        session = session_manager.get_by_access_token(access_token)
        if not session:
            logger.error("❌ Token no encontrado")
            raise HTTPException(status_code=401, detail={"error": "invalid_token"})

        credential_data = session["credential_data"]
        logger.info(f"✅ Credential data recuperada para: {credential_data.get('student_name')}")

        # ─── Parse request body ───
        try:
            json_data = await request.json()
            logger.info(f"📄 Request body keys: {list(json_data.keys())}")
        except Exception:
            json_data = {}

        # ─── Extraer DID del holder desde proof JWT ───
        proof = json_data.get("proof", {})
        proof_jwt_str = proof.get("jwt")
        proof_jwk = None
        holder_did = None

        if proof_jwt_str:
            try:
                proof_header = jwt.get_unverified_header(proof_jwt_str)
                proof_payload = jwt.decode(proof_jwt_str, options={"verify_signature": False})
                proof_jwk = proof_header.get("jwk")
                proof_kid = proof_header.get("kid")

                holder_did = extract_holder_did_from_proof(proof_jwt_str, proof_header, proof_payload)

                if holder_did:
                    logger.info(f"✅ Holder DID: {holder_did[:60]}...")
                else:
                    logger.error("❌ No se pudo extraer DID del holder")
                    raise HTTPException(
                        status_code=400,
                        detail={"error": "invalid_request", "error_description": "Could not determine Holder DID"},
                    )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"❌ Error validando proof: {e}")
                raise HTTPException(
                    status_code=400,
                    detail={"error": "invalid_proof", "error_description": str(e)},
                )
        else:
            logger.error("❌ No proof JWT provided")
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_request", "error_description": "Proof required"},
            )

        user_agent = request.headers.get("user-agent", "").lower()
        is_mobile = any(kw in user_agent for kw in ("dalvik", "cfnetwork", "ios", "android", "lissi", "okhttp", "darwin"))
        requires_absolute_vct = not is_mobile

        formatter_kwargs = dict(
            credential_data=credential_data,
            holder_did=holder_did,
            proof_jwk=proof_jwk,
            proof_kid=proof_kid,
            access_token=access_token,
            private_key=PRIVATE_KEY,
            issuer_url=ISSUER_URL,
            issuer_did=ISSUER_DID,
            requires_absolute_vct=requires_absolute_vct,
        )

        resolved_format = resolve_format(json_data)

        if holder_did and holder_did.startswith("did:dyne"):
            logger.info("⚠️ Compatibilidad activada: Forzando jwt_vc_json para DIDRoom (did:dyne)")
            resolved_format = "jwt_vc_json"

        # Generar UNA ÚNICA credencial en el formato exacto requerido
        credential, format_name = format_credential(resolved_format, **formatter_kwargs)

        logger.info(
            f"✅ Credencial emitida para: {credential_data.get('student_name')} "
            f"| Formato Único: {format_name}"
        )

        # ─── Anclaje Web3 y Notificación a Moodle ───
        import httpx
        import os
        from blockchain.web3_client import besu_client
        from utils.hashing import compute_credential_hash

        async def anchor_and_notify(
            conn_id: str,
            cred_data: dict,
            c_name: str,
        ):
            """Background job: anchor the portal hash on-chain and notify Moodle.

            The hash anchored on Besu is the **same** canonical SHA-256 digest
            displayed in the student portal and used for public verification.
            This guarantees a single cryptographic identity end-to-end.
            """
            logger.info("⚙️ Iniciando Job en Background: Blockchain Anchor + Webhook")

            # PASO 1: Calcular el Portal Hash canónico
            _sid = str(cred_data.get("student_id", ""))
            _cid = str(cred_data.get("course_id", ""))
            _cd  = cred_data.get("completion_date", "")
            _gr  = cred_data.get("grade", "Aprobado")
            logger.info(
                f"🔍 HASH INPUTS: student_id={repr(_sid)} "
                f"course_id={repr(_cid)} "
                f"completion_date={repr(_cd)} "
                f"grade={repr(_gr)}"
            )
            logger.info(f"🔍 RAW CONCAT: {repr(_sid + _cid + _cd + _gr)}")
            portal_hash = compute_credential_hash(
                student_id=_sid,
                course_id=_cid,
                completion_date=_cd,
                grade=_gr,
            )
            logger.info(f"🔗 Portal Hash calculado: {portal_hash}")

            # PASO 2: Anclar el Portal Hash en Besu
            tx_hash = await besu_client.anchor_credential_hash(portal_hash, c_name)

            # PASO 3: Persistir el anchor (con tx_hash) en la DB del portal
            if tx_hash:
                try:
                    from portal.database import PortalSessionLocal
                    from portal.models import CredentialAnchor as CredentialAnchorModel

                    db = PortalSessionLocal()
                    try:
                        # Upsert: update if hash exists, insert otherwise
                        existing = (
                            db.query(CredentialAnchorModel)
                            .filter(CredentialAnchorModel.credential_hash == portal_hash)
                            .first()
                        )
                        issuer_did = (
                            f"did:ethr:{besu_client.admin_account.address}"
                            if besu_client.admin_account
                            else None
                        )

                        if existing:
                            existing.txn_id = tx_hash
                            existing.issuer_did = issuer_did
                        else:
                            anchor = CredentialAnchorModel(
                                credential_hash=portal_hash,
                                moodle_user_id=int(cred_data.get("student_id", 0)),
                                moodle_course_id=int(cred_data.get("course_id", 0)),
                                txn_id=tx_hash,
                                issuer_did=issuer_did,
                            )
                            db.add(anchor)

                        db.commit()
                        logger.info(f"💾 Anchor persistido: hash={portal_hash[:16]}... tx={tx_hash}")
                    finally:
                        db.close()
                except Exception as db_err:
                    logger.warning(f"⚠️ Error persistiendo anchor en DB: {db_err}")

            # PASO 4: Mandar Webhook al LMS
            moodle_internal_url = os.getenv("MOODLE_INTERNAL_URL", "http://moodle-app")
            webhook_url = f"{moodle_internal_url}/blocks/credenciales/webhook.php"
            moodle_domain = os.getenv("MOODLE_DOMAIN", "moodle.utnpf.site")

            payload = {"connection_id": conn_id, "status": "claimed"}
            if tx_hash:
                payload["tx_hash"] = tx_hash
                logger.info(f"🪙 Adjuntando Hash de Transacción On-Chain al Webhook: {tx_hash}")

            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        webhook_url,
                        json=payload,
                        headers={"Host": moodle_domain, "X-Forwarded-Proto": "https", "X-Forwarded-Port": "443"},
                        timeout=10.0,
                        follow_redirects=True
                    )
                logger.info(f"✅ Webhook enviado a Moodle. Status: {response.status_code}")
            except Exception as w_e:
                logger.warning(f"⚠️ Alerta: El Webhook de Moodle falló: {w_e}")

        # Sacar el connection_id (pre-auth_code) de la sesión
        conn_id = session.get("credential_data", {}).get("pre_authorized_code")
        if not conn_id and session.get("flows"):
            pre_auth_flow = session["flows"].get("pre_authorized")
            if pre_auth_flow:
                conn_id = pre_auth_flow.get("code")
        
        c_name = credential_data.get("course_name", "Curso Desconocido")

        if conn_id:
            background_tasks.add_task(anchor_and_notify, conn_id, credential_data, c_name)
            logger.info("🟢 Job 'Anchor on-chain & Notify Moodle' registrado en BackgroundTasks.")
        
        # ─── Construir respuesta para la Wallet ───
        response_data = build_credential_response(
            credential, format_name
        )

        response = JSONResponse(content=response_data)
        return await add_security_headers(response)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error emitiendo credencial: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=500,
            detail={"error": "server_error", "error_description": str(e)},
        )

# ============================================================================
# NOTIFICATION ENDPOINT (Cierra el ciclo en wallets estrictas)
# ============================================================================

from fastapi import Response

@core_router.post("/notification")
async def notification_endpoint(request: Request):
    """
    Endpoint para que la Wallet notifique el éxito de la recepción de credencial.
    Para algunas wallets como Lissi, este ACK es el disparador final 
    para cerrar la ruedita de carga (Processing Request) en la interfaz gráfica.
    Devuelve 204 No Content.
    """
    logger.info("================================================================================")
    logger.info("📥 NOTIFICATION ENDPOINT LLAMADO (La Wallet confirma la transacción!)")
    logger.info("================================================================================")
    
    try:
        data = await request.json()
        logger.info(f"✅ Notificación del dispositivo: {data}")
    except Exception:
        logger.info("ℹ️ Payload sin formato o vacío recibido en notification.")
        
    # La especificación OpenID4VCI exige que este endpoint devuelva HTTP 204 No Content
    return Response(status_code=204)

# ============================================================================
# QR CODE PAGE ENDPOINT
# ============================================================================

@core_router.get("/qr/{connection_id}", response_class=HTMLResponse)
async def show_qr_page(connection_id: str):
    """
    Mostrar página HTML con QR Code escaneable para wallets OpenID4VC
    """
    from storage import qr_storage
    
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
                    font-size: 0.75em;
                    word-break: break-all;
                    color: #555;
                    cursor: pointer;
                    max-height: 100px;
                    overflow-y: auto;
                }}
                .url-link:hover {{
                    background: #e0e0e0;
                }}
                .copy-btn {{
                    background: #2196f3;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 5px;
                    cursor: pointer;
                    margin-top: 10px;
                    font-size: 0.9em;
                }}
                .copy-btn:hover {{
                    background: #1976d2;
                }}
                .copy-btn:active {{
                    background: #0d47a1;
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
                        <li>O copia el enlace debajo y pégalo en la wallet web</li>
                    </ol>
                    
                    <div class="wallet-list">
                        <span class="wallet">WaltID</span>
                        <span class="wallet">DIDRoom</span>
                        <span class="wallet">Lissi</span>
                        <span class="wallet">EUDI</span>
                    </div>
                </div>
                
                <div class="url-link" id="offerUrl" onclick="copyToClipboard()">
                    {qr_data.get('qr_url', 'N/A')}
                </div>
                <button class="copy-btn" onclick="copyToClipboard()">📋 Copiar URL</button>
                
                <div class="timestamp">
                    ⏰ Generado: {qr_data['timestamp']}<br>
                    🔑 ID: {connection_id}
                </div>
            </div>
            
            <script>
                function copyToClipboard() {{
                    const urlText = document.getElementById('offerUrl').innerText;
                    navigator.clipboard.writeText(urlText).then(() => {{
                        const btn = document.querySelector('.copy-btn');
                        const originalText = btn.innerText;
                        btn.innerText = '✅ Copiado!';
                        setTimeout(() => {{
                            btn.innerText = originalText;
                        }}, 2000);
                    }}).catch(err => {{
                        console.error('Error copiando:', err);
                    }});
                }}
            </script>
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
