#!/usr/bin/env python3
"""
OpenID4VC Core Endpoints - Offer, Auth, Token, Credential
Complete implementation with session manager and PKCE support
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
    Genera Credential Offer con DUAL GRANT support
    Flujo 1: Pre-Authorized Code (WaltID)
    Flujo 2: Authorization Code (DIDRoom)
    """
    student_id = request_data.get("student_id")
    student_email = request_data.get("student_email")
    student_name = request_data.get("student_name")
    course_name = request_data.get("course_name")
    
    logger.info("📨 [DUAL-GRANT] Generando Credential Offer", student=student_name)
    
    # Crear sesión
    session_id = session_manager.create_session(credential_data=request_data, expires_in=600)
    
    # Generar pre_auth_code
    timestamp = int(datetime.now().timestamp())
    pre_auth_code = f"pre_auth_{student_id}_{timestamp}_{hash(student_email) % 10000}"
    session_manager.link_pre_auth_code(session_id, pre_auth_code)
    
    # Crear offer con SINGLE GRANT (Pre-Authorized Code Only)
    # Forzamos este flujo para evitar problemas con DIDRoom y PAR,
    # y porque el usuario ya está autenticado.
    offer = {
        "credential_issuer": ISSUER_URL,
        "credential_configuration_ids": ["UniversityDegree"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_auth_code
            }
        }
    }
    
    logger.info(f"✅ Offer creado - Pre-auth: {pre_auth_code[:20]}... Session: {session_id[:20]}...")
    
    # Generar QR
    offer_json = json.dumps(offer, separators=(',', ':'))
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

# ============================================================================
# PAR ENDPOINT
# ============================================================================

@core_router.post("/par")
async def par_endpoint(request: Request):
    """
    Pushed Authorization Request (PAR) endpoint - RFC 9126
    Usado por DIDRoom para iniciar flujo de autorización
    """
    try:
        form_data = await request.form()
        form_dict = dict(form_data)
        
        logger.info("🔐 PAR endpoint llamado", client_id=form_dict.get("client_id", "Unknown")[:50])
        logger.info(f"   form_data keys: {list(form_dict.keys())}")
        
        # DEBUG: Log completo de authorization_details y state
        auth_details = form_dict.get("authorization_details")
        state = form_dict.get("state")
        
        logger.info(f"🔍 DEBUG PAR - state field: {state}")
        logger.info(f"🔍 DEBUG PAR - authorization_details type: {type(auth_details)}")
        logger.info(f"🔍 DEBUG PAR - authorization_details content: {auth_details}")
        
        # Extraer issuer_state (session_id)
        issuer_state = extract_issuer_state_from_par(form_dict)
        
        if not issuer_state:
            logger.error("❌ No issuer_state found in PAR request")
            logger.error(f"   Available fields: {form_dict.keys()}")
            logger.error(f"   State value: {state}")
            logger.error(f"   Authorization details: {auth_details}")
            raise HTTPException(status_code=400, detail="Missing issuer_state")
        
        # Validar que la sesión existe
        session = session_manager.get_session(issuer_state)
        if not session:
            logger.error(f"❌ Session not found: {issuer_state[:20]}...")
            raise HTTPException(status_code=400, detail="Invalid issuer_state - session not found")
        
        # Vincular datos PAR a la sesión
        session_manager.link_authorization_request(issuer_state, form_dict)
        
        # Generar request_uri
        request_uri = f"urn:ietf:params:oauth:request_uri:{secrets.token_urlsafe(32)}"
        
        # Mapear request_uri -> session_id
        request_uri_to_session[request_uri] = issuer_state
        session_manager.link_request_uri(request_uri, issuer_state)
        
        logger.info(f"✅ PAR request_uri generado: {request_uri[:50]}...")
        
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
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": str(e)})

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
    OAuth 2.0 Authorization Endpoint con soporte completo para DIDRoom
    
    Acepta AMBOS flujos:
    - Directo con issuer_state (DIDRoom después de deshabilitar PAR)
    - Con request_uri (wallets que usen PAR si lo habilitamos)
    """
    logger.info("=" * 80)
    logger.info("🔓 AUTHORIZE ENDPOINT LLAMADO")
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
        # Estrategia 1: Buscar por issuer_state directo (flujo sin PAR - DIDRoom)
        session = None
        session_id = None
        
        if issuer_state:
            logger.info(f"✅ [FLUJO DIRECTO] issuer_state recibido: {issuer_state[:30]}...")
            session = session_manager.get_session(issuer_state)
            if session:
                session_id = issuer_state
                logger.info(f"✅ Sesión encontrada por issuer_state")
            else:
                logger.error(f"❌ Sesión NO encontrada para issuer_state: {issuer_state[:30]}...")
                raise HTTPException(status_code=400, detail="Invalid issuer_state - session not found or expired")
        
        # Estrategia 2: Buscar por request_uri (flujo con PAR - fallback)
        elif request_uri:
            logger.info(f"🔍 [FLUJO PAR] request_uri recibido: {request_uri[:50]}...")
            session = session_manager.get_session_by_request_uri(request_uri)
            if session:
                session_id = session["session_id"]
                logger.info(f"✅ Sesión encontrada por request_uri")
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
        
        # Validaciones
        if not redirect_uri:
            logger.error("❌ redirect_uri faltante")
            raise HTTPException(status_code=400, detail="redirect_uri required")
        
        if not code_challenge:
            logger.warning("⚠️ code_challenge NO recibido - PKCE podría fallar en /token")
        
        # Vincular code_challenge al session si existe
        if code_challenge and session_id:
            logger.info(f"🔐 Vinculando PKCE challenge a sesión")
            # Actualizar sesión con datos de autorización
            par_data = {
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method or "S256",
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "state": state,
                "authorization_details": authorization_details,
                "scope": scope
            }
            session_manager.link_authorization_request(session_id, par_data)
        
        # Generar authorization code
        auth_code = f"auth_code_{secrets.token_urlsafe(32)}"
        session_manager.link_authorization_code(session_id, auth_code)
        
        logger.info(f"✅ Authorization code generado: {auth_code[:20]}...")
        logger.info(f"🔗 Vinculado a session: {session_id[:20]}...")
        
        # Construir URL de redirect
        from urllib.parse import urlencode
        params = {
            "code": auth_code,
            "state": state or ""
        }
        redirect_url = f"{redirect_uri}?{urlencode(params)}"
        
        logger.info(f"↩️ Redirigiendo a: {redirect_url[:100]}...")
        logger.info("=" * 80)
        
        return RedirectResponse(url=redirect_url, status_code=302)
        
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
            "c_nonce_expires_in": 300
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

@core_router.post("/credential")
async def credential_endpoint(
    request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization")
):
    """
    Credential Issuance Endpoint
    Emite la credencial W3C firmada en formato JWT
    """
    logger.info("🎓 Credential endpoint llamado")
    
    try:
        # Extraer access token
        auth_header = authorization or request.headers.get("authorization")
        
        if not auth_header or " " not in auth_header:
            raise HTTPException(status_code=401, detail={"error": "invalid_token", "error_description": "Authorization header required"})
        
        parts = auth_header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(status_code=401, detail={"error": "invalid_token", "error_description": "Invalid format"})
        
        access_token = parts[1]
        logger.info(f"🔑 Token: {access_token[:20]}...")
        
        # Buscar sesión
        session = session_manager.get_by_access_token(access_token)
        if not session:
            logger.error("❌ Token no encontrado")
            raise HTTPException(status_code=401, detail={"error": "invalid_token"})
        
        credential_data = session["credential_data"]
        logger.info(f"✅ Credential data recuperada para: {credential_data.get('student_name')}")
        
        # Parse JSON body para obtener proof
        try:
            json_data = await request.json()
            logger.info(f"📄 Request body: {list(json_data.keys())}")
        except:
            json_data = {}
        
        # Extraer DID del holder desde proof JWT
        proof = json_data.get("proof", {})
        proof_jwt = proof.get("jwt")
        holder_did = None
        
        if proof_jwt:
            try:
                proof_header = jwt.get_unverified_header(proof_jwt)
                proof_payload = jwt.decode(proof_jwt, options={"verify_signature": False})
                
                holder_did = extract_holder_did_from_proof(proof_jwt, proof_header, proof_payload)
                
                if holder_did:
                    logger.info(f"✅ Holder DID: {holder_did[:60]}...")
                else:
                    logger.error("❌ No se pudo extraer DID del holder")
                    raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "Could not determine Holder DID"})
            except Exception as e:
                logger.error(f"❌ Error validando proof: {e}")
                raise HTTPException(status_code=400, detail={"error": "invalid_proof", "error_description": str(e)})
        else:
            logger.error("❌ No proof JWT provided")
            raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "Proof required"})
        
        # Crear W3C Verifiable Credential
        now = datetime.now()
        now_timestamp = int(now.timestamp())
        exp_timestamp = now_timestamp + (365 * 24 * 60 * 60)
        
        now_iso = datetime.fromtimestamp(now_timestamp).isoformat() + "Z"
        exp_iso = datetime.fromtimestamp(exp_timestamp).isoformat() + "Z"
        
        vc_payload = {
            "iss": ISSUER_DID,
            "sub": holder_did,
            "iat": now_timestamp - 5,
            "exp": exp_timestamp,
            "jti": f"urn:credential:{access_token[:16]}",
            "vc": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    f"{ISSUER_URL}/oid4vc/context/v1"
                ],
                "type": ["VerifiableCredential", "UniversityDegree"],
                "id": f"urn:credential:{access_token[:16]}",
                "issuer": {
                    "id": ISSUER_DID,
                    "name": "Sistema de Credenciales UTN",
                    "url": ISSUER_URL
                },
                "issuanceDate": now_iso,
                "expirationDate": exp_iso,
                "credentialSubject": {
                    "id": holder_did,
                    "student_name": credential_data.get("student_name", "Unknown"),
                    "student_email": credential_data.get("student_email", "unknown@example.com"),
                    "student_id": credential_data.get("student_id", "unknown"),
                    "course_name": credential_data.get("course_name", "N/A"),
                    "completion_date": credential_data.get("completion_date", "N/A"),
                    "grade": credential_data.get("grade", "N/A"),
                    "university": "UTN"
                }
            }
        }
        
        # Firmar credencial
        vc_jwt = jwt.encode(
            vc_payload,
            PRIVATE_KEY,
            algorithm="ES256",
            headers={"kid": f"{ISSUER_DID}#key-1"}
        )
        
        logger.info(f"✅ Credencial emitida para: {credential_data.get('student_name')}")
        
        # Generar nuevo c_nonce
        next_c_nonce = secrets.token_urlsafe(32)
        
        response_data = {
            "credential": vc_jwt,
            "c_nonce": next_c_nonce,
            "c_nonce_expires_in": 86400
        }
        
        response = JSONResponse(content=response_data)
        return await add_security_headers(response)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error emitiendo credencial: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail={"error": "server_error", "error_description": str(e)})
