#!/usr/bin/env python3
"""
OpenID4VC Helper Functions
Utility functions for DID extraction, security headers, etc.
"""

import json
import base64
from typing import Dict, Any, Optional
import structlog
from fastapi.responses import JSONResponse

from .config import SSL_SECURITY_HEADERS

logger = structlog.get_logger()

# ============================================================================
# SECURITY HEADERS
# ============================================================================

async def add_security_headers(response: JSONResponse) -> JSONResponse:
    """
    Añade headers de seguridad SSL/TLS requeridos por Lissi Wallet y Android
    
    Args:
        response: JSONResponse to add headers to
        
    Returns:
        Modified JSONResponse with security headers
    """
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

# ============================================================================
# DID EXTRACTION FUNCTIONS
# ============================================================================

def create_did_jwk_from_jwk(jwk_dict: Dict[str, Any]) -> str:
    """
    Crea un did:jwk desde un JWK según la especificación did:jwk
    https://github.com/quartzjer/did-jwk
    
    Format: did:jwk:{base64url(json(jwk))}
    
    Args:
        jwk_dict: JWK dictionary
        
    Returns:
        did:jwk string
    """
    try:
        # Normalizar JWK: solo campos públicos, orden canónico
        normalized_jwk = {}
        
        if jwk_dict.get('kty') == 'EC':
            normalized_jwk = {
                'kty': jwk_dict['kty'],
                'crv': jwk_dict['crv'],
                'x': jwk_dict['x'],
                'y': jwk_dict['y']
            }
        elif jwk_dict.get('kty') == 'RSA':
            normalized_jwk = {
                'kty': jwk_dict['kty'],
                'n': jwk_dict['n'],
                'e': jwk_dict['e']
            }
        else:
            normalized_jwk = {k: v for k, v in jwk_dict.items() 
                            if k in ['kty', 'crv', 'x', 'y', 'n', 'e']}
        
        # Ordenar alfabéticamente
        sorted_jwk = dict(sorted(normalized_jwk.items()))
        
        # Serializar sin espacios
        jwk_json = json.dumps(sorted_jwk, separators=(',', ':'))
        
        # Base64url encode
        jwk_bytes = jwk_json.encode('utf-8')
        jwk_b64 = base64.urlsafe_b64encode(jwk_bytes).decode('ascii').rstrip('=')
        
        did_jwk = f"did:jwk:{jwk_b64}"
        
        logger.info(f"✅ Generated did:jwk: {did_jwk[:50]}...")
        return did_jwk
        
    except Exception as e:
        logger.error(f"❌ Error creating did:jwk: {e}")
        raise

def create_did_key_from_jwk(jwk_dict: Dict[str, Any]) -> str:
    """
    Crea un did:key desde un JWK según la especificación did:key
    https://w3c-ccg.github.io/did-method-key/
    
    Format: did:key:{multibase(multicodec(pubkey))}
    Para P-256: multicodec prefix = 0x1200 (secp256r1-pub)
    
    Args:
        jwk_dict: JWK dictionary
        
    Returns:
        did:key string
    """
    try:
        if jwk_dict.get('kty') != 'EC':
            raise ValueError("did:key generation only supports EC keys currently")
        
        if jwk_dict.get('crv') != 'P-256':
            raise ValueError("did:key generation only supports P-256 curve currently")
        
        # Obtener coordenadas x, y
        x_b64 = jwk_dict['x']
        y_b64 = jwk_dict['y']
        
        # Decodificar base64url (agregar padding si es necesario)
        def decode_b64url(s):
            padding = 4 - (len(s) % 4)
            if padding != 4:
                s += '=' * padding
            return base64.urlsafe_b64decode(s)
        
        x_bytes = decode_b64url(x_b64)
        y_bytes = decode_b64url(y_b64)
        
        # Formato uncompressed public key: 0x04 || x || y
        pubkey_bytes = b'\x04' + x_bytes + y_bytes
        
        # Multicodec prefix para secp256r1-pub (P-256): 0x1200
        multicodec_prefix = bytes([0x80, 0x24])
        multicodec_pubkey = multicodec_prefix + pubkey_bytes
        
        # Multibase encoding: base58btc (prefix 'z')
        import base58
        multibase_encoded = base58.b58encode(multicodec_pubkey).decode('ascii')
        
        did_key = f"did:key:z{multibase_encoded}"
        
        logger.info(f"✅ Generated did:key: {did_key[:50]}...")
        return did_key
        
    except ImportError:
        logger.warning("⚠️ base58 library not available, cannot generate did:key")
        raise ValueError("base58 library required for did:key generation")
    except Exception as e:
        logger.error(f"❌ Error creating did:key: {e}")
        raise

def extract_holder_did_from_proof(
    proof_jwt: str,
    proof_header: Dict[str, Any],
    proof_payload: Dict[str, Any]
) -> Optional[str]:
    """
    Extrae el DID del holder desde el proof JWT usando múltiples estrategias
    según el estándar OpenID4VCI.
    
    Estrategias (en orden de prioridad):
    1. payload.iss - Issuer del proof JWT (recomendado por spec)
    2. header.kid - Si es un DID con fragment (#)
    3. Derivar did:jwk desde header.jwk
    4. Derivar did:key desde header.jwk (fallback)
    
    Args:
        proof_jwt: The proof JWT string
        proof_header: Decoded JWT header
        proof_payload: Decoded JWT payload
        
    Returns:
        DID del holder o None si no se puede extraer
    """
    
    # ESTRATEGIA 1: Desde payload.iss
    issuer = proof_payload.get('iss')
    if issuer and isinstance(issuer, str) and issuer.startswith('did:'):
        logger.info(f"✅ [Strategy 1] DID extraído desde payload.iss: {issuer}")
        return issuer
    
    # ESTRATEGIA 2: Desde header.kid (si es un DID)
    kid = proof_header.get('kid')
    if kid and isinstance(kid, str) and kid.startswith('did:'):
        # Extraer DID base (antes del fragment #)
        base_did = kid.split('#')[0]
        logger.info(f"✅ [Strategy 2] DID extraído desde header.kid: {base_did}")
        return base_did
    
    # ESTRATEGIA 3: Derivar did:jwk desde header.jwk
    jwk = proof_header.get('jwk')
    if jwk and isinstance(jwk, dict):
        try:
            did_jwk = create_did_jwk_from_jwk(jwk)
            logger.info(f"✅ [Strategy 3] DID derivado como did:jwk: {did_jwk[:60]}...")
            return did_jwk
        except Exception as e:
            logger.warning(f"⚠️ [Strategy 3] Falló derivación de did:jwk: {e}")
    
    # ESTRATEGIA 4: Derivar did:key desde header.jwk (fallback)
    if jwk and isinstance(jwk, dict):
        try:
            did_key = create_did_key_from_jwk(jwk)
            logger.info(f"✅ [Strategy 4] DID derivado como did:key: {did_key[:60]}...")
            return did_key
        except Exception as e:
            logger.warning(f"⚠️ [Strategy 4] Falló derivación de did:key: {e}")
    
    # No se pudo extraer el DID con ninguna estrategia
    logger.error("❌ No se pudo extraer DID del holder con ninguna estrategia")
    logger.error(f"   - payload.iss: {proof_payload.get('iss', 'AUSENTE')}")
    logger.error(f"   - header.kid: {proof_header.get('kid', 'AUSENTE')}")
    logger.error(f"   - header.jwk: {'PRESENTE' if jwk else 'AUSENTE'}")
    
    return None

# ============================================================================
# PAR HELPERS
# ============================================================================

def extract_issuer_state_from_par(par_data: Dict[str, Any]) -> Optional[str]:
    """
    Extrae issuer_state de los datos PAR
    
    El issuer_state puede venir en varios lugares según el wallet:
    1. Directamente en el campo 'state'
    2. Dentro de 'authorization_details' parseado
    
    Args:
        par_data: Dict con los datos del PAR request
        
    Returns:
        issuer_state (session_id) o None
    """
    # Método 1: Directamente en 'state'
    state = par_data.get('state')
    if state and state.startswith('session_'):
        logger.info(f"✅ Issuer state encontrado en 'state': {state[:30]}...")
        return state
    
    # Método 2: Buscar en authorization_details
    auth_details_str = par_data.get('authorization_details')
    if auth_details_str:
        try:
            auth_details = json.loads(auth_details_str) if isinstance(auth_details_str, str) else auth_details_str
            if isinstance(auth_details, list) and len(auth_details) > 0:
                for detail in auth_details:
                    if isinstance(detail, dict):
                        issuer_state = detail.get('issuer_state')
                        if issuer_state:
                            logger.info(f"✅ Issuer state encontrado en authorization_details: {issuer_state[:30]}...")
                            return issuer_state
        except (json.JSONDecodeError, TypeError) as e:
            logger.warning(f"⚠️ Error parseando authorization_details: {e}")
    
    logger.warning("⚠️ No se encontró issuer_state en PAR data")
    return None
