#!/usr/bin/env python3
"""
PKCE Validator - RFC 7636 Compliant
Validates Proof Key for Code Exchange for OAuth 2.0 Public Clients
"""

import hashlib
import base64
import structlog

logger = structlog.get_logger()


class PKCEValidator:
    """
    PKCE Validator según RFC 7636
    
    Soporta:
    - S256 (SHA-256, recomendado)
    - plain (no recomendado, solo para debugging)
    """
    
    SUPPORTED_METHODS = ["S256", "plain"]
    
    @staticmethod
    def validate(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
        """
        Valida que el code_verifier corresponda al code_challenge
        
        Args:
            code_verifier: String enviado por el cliente en /token
            code_challenge: String enviado por el cliente en PAR/authorize
            method: "S256" o "plain"
        
        Returns:
            True si la validación es exitosa
        
        Raises:
            ValueError si el método no es soportado
        """
        logger.info("🔐 Validando PKCE",
                   method=method,
                   verifier_length=len(code_verifier) if code_verifier else 0,
                   challenge_length=len(code_challenge) if code_challenge else 0)
        
        if not code_verifier or not code_challenge:
            logger.error("❌ PKCE validation failed - missing verifier or challenge")
            return False
        
        if method not in PKCEValidator.SUPPORTED_METHODS:
            logger.error(f"❌ Unsupported PKCE method: {method}")
            raise ValueError(f"Unsupported PKCE method: {method}. Supported: {PKCEValidator.SUPPORTED_METHODS}")
        
        try:
            if method == "S256":
                # RFC 7636 Section 4.6:
                # BASE64URL(SHA256(ASCII(code_verifier))) == code_challenge
                
                # 1. Convert code_verifier to ASCII bytes
                verifier_bytes = code_verifier.encode('ascii')
                
                # 2. Compute SHA256 hash
                hash_digest = hashlib.sha256(verifier_bytes).digest()
                
                # 3. Base64url encode (sin padding '=')
                computed_challenge = base64.urlsafe_b64encode(hash_digest).decode('ascii').rstrip('=')
                
                # 4. Compare
                is_valid = computed_challenge == code_challenge
                
                logger.info("🔍 PKCE S256 validation",
                          computed=computed_challenge[:20] + "...",
                          received=code_challenge[:20] + "...",
                          match=is_valid)
                
                return is_valid
                
            elif method == "plain":
                # Plain method: code_verifier == code_challenge
                is_valid = code_verifier == code_challenge
                
                logger.warning("⚠️ PKCE plain method used (not recommended)")
                logger.info("🔍 PKCE plain validation", match=is_valid)
                
                return is_valid
                
        except Exception as e:
            logger.error(f"❌ PKCE validation error: {e}")
            return False
    
    @staticmethod
    def generate_code_challenge(code_verifier: str, method: str = "S256") -> str:
        """
        Genera un code_challenge desde un code_verifier
        Útil para testing
        
        Args:
            code_verifier: El verifier original
            method: "S256" o "plain"
            
        Returns:
            El code_challenge correspondiente
        """
        if method == "S256":
            verifier_bytes = code_verifier.encode('ascii')
            hash_digest = hashlib.sha256(verifier_bytes).digest()
            code_challenge = base64.urlsafe_b64encode(hash_digest).decode('ascii').rstrip('=')
            return code_challenge
        elif method == "plain":
            return code_verifier
        else:
            raise ValueError(f"Unsupported method: {method}")
