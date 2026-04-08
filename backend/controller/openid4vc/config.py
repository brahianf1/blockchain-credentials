#!/usr/bin/env python3
"""
OpenID4VC Configuration Module
Contains all configuration, constants, and Pydantic models
"""

import os
import base64
from typing import Optional
from pydantic import BaseModel, Field
import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

logger = structlog.get_logger()

# ============================================================================
# CONFIGURATION - From environment variables
# ============================================================================

ISSUER_URL = os.getenv("ISSUER_URL", "http://localhost:3000")
ISSUER_BASE_URL = f"{ISSUER_URL}/oid4vc"
ISSUER_DID = f"did:web:{ISSUER_URL.replace('https://', '').replace('http://', '')}"

# ============================================================================
# SSL/TLS CONFIGURATION
# ============================================================================

SSL_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
}

TLS_PROTOCOLS_SUPPORTED = ["TLSv1.2", "TLSv1.3"]
CIPHER_SUITES_ANDROID = [
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
]

# ============================================================================
# CRYPTOGRAPHIC KEYS
# ============================================================================

def get_or_generate_es256_key():
    """
    Obtiene una clave ES256 válida desde variables de entorno.
    
    La función busca en las variables de entorno en el siguiente orden:
    1. OPENID_PRIVATE_KEY y OPENID_PUBLIC_KEY (contenido directo de la clave).
    2. OPENID_PRIVATE_KEY_PATH y OPENID_PUBLIC_KEY_PATH (ruta a los archivos .pem).
    
    Si no se encuentra ninguna, lanza una excepción.
    
    Returns:
        tuple: (private_key_pem, public_key_pem)
    """
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

# Load keys
PRIVATE_KEY, PUBLIC_KEY = get_or_generate_es256_key()

# Convert public key to JWK for DID Document
if isinstance(PUBLIC_KEY, str):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    public_key_obj = load_pem_public_key(PUBLIC_KEY.encode(), backend=default_backend())
else:
    public_key_obj = PUBLIC_KEY

public_numbers = public_key_obj.public_numbers()

PUBLIC_KEY_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": base64.urlsafe_b64encode(
        public_numbers.x.to_bytes(32, 'big')
    ).decode().rstrip('='),
    "y": base64.urlsafe_b64encode(
        public_numbers.y.to_bytes(32, 'big')
    ).decode().rstrip('=')
}

logger.info(f"✅ Clave pública convertida a JWK para DID Document")

# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class OpenIDCredentialRequest(BaseModel):
    """Request model for OpenID credential issuance"""
    pre_authorized_code: str = Field(..., min_length=10, max_length=200, 
                                     description="Pre-authorized code for credential issuance")
    tx_code: Optional[str] = Field(None, max_length=50, 
                                   description="Transaction code (optional)")

class CredentialOfferRequest(BaseModel):
    """Request model for creating a credential offer"""
    student_id: str = Field(..., min_length=1, max_length=100, 
                           description="Student identification")
    student_name: str = Field(..., min_length=1, max_length=200, 
                             description="Student full name")
    student_email: str = Field(..., pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$', 
                              description="Student email address")
    course_id: str = Field(..., description="Course ID")
    course_name: str = Field(..., min_length=1, max_length=300, 
                            description="Course name")
    completion_date: str = Field(..., description="Course completion date")
    grade: str = Field(..., min_length=1, max_length=10, 
                      description="Final grade")
    instructor_name: str = Field(..., description="Instructor name")
