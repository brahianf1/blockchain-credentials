#!/usr/bin/env python3
"""
Session Manager - Unified Session Management for OpenID4VCI
Manages sessions for both Pre-Authorized Code and Authorization Code flows
"""

import secrets
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import structlog

logger = structlog.get_logger()


class SessionManager:
    """
    Unified Session Manager for OpenID4VCI flows
    
    Manages sessions that support BOTH:
    1. Pre-Authorized Code Flow (WaltID)
    2. Authorization Code Flow with PKCE (DIDRoom)
    
    Architecture:
    - Each session has a unique session_id
    - Sessions store credential_data (the actual certificate info)
    - Sessions can be linked to pre_auth_code, auth_code, or access_token
    - Sessions expire automatically
    """
    
    def __init__(self):
        """Initialize in-memory session storage"""
        self._sessions = {}  # session_id -> session_data
        self._pre_auth_index = {}  # pre_auth_code -> session_id
        self._auth_code_index = {}  # auth_code -> session_id
        self._access_token_index = {}  # access_token -> session_id
        self._request_uri_index = {}  # request_uri -> session_id
        
        logger.info("✅ SessionManager initialized")
    
    def create_session(self, credential_data: Dict[str, Any], expires_in: int = 600) -> str:
        """
        Crea una nueva sesión con credential data
        
        Args:
            credential_data: Los datos de la credencial (student info, course, etc.)
            expires_in: Tiempo de expiración en segundos (default: 10 min)
            
        Returns:
            session_id único
        """
        session_id = f"session_{secrets.token_urlsafe(32)}"
        
        now = datetime.now()
        expires_at = now + timedelta(seconds=expires_in)
        
        session_data = {
            "session_id": session_id,
            "credential_data": credential_data,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "flows": {
                "pre_authorized": None,  # Will store pre_auth_code if used
                "authorization": None,  # Will store auth flow data if used
            },
            "tokens": {
                "access_token": None,
                "c_nonce": None
            }
        }
        
        self._sessions[session_id] = session_data
        
        logger.info("🆕 Session created",
                   session_id=session_id[:20] + "...",
                   student=credential_data.get("student_name", "Unknown"),
                   expires_in=expires_in)
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Recupera una sesión por ID
        
        Returns:
            session_data o None si no existe o expiró
        """
        session = self._sessions.get(session_id)
        
        if not session:
            logger.warning(f"⚠️ Session not found: {session_id[:20]}...")
            return None
        
        # Verificar expiración
        expires_at = datetime.fromisoformat(session["expires_at"])
        if datetime.now() > expires_at:
            logger.warning(f"⏰ Session expired: {session_id[:20]}...")
            self._cleanup_session(session_id)
            return None
        
        logger.debug(f"✅ Session retrieved: {session_id[:20]}...")
        return session
    
    def link_pre_auth_code(self, session_id: str, pre_auth_code: str) -> None:
        """
        Vincula un pre-authorized code a una sesión (flujo WaltID)
        """
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")
        
        session["flows"]["pre_authorized"] = {
            "code": pre_auth_code,
            "created_at": datetime.now().isoformat()
        }
        
        self._pre_auth_index[pre_auth_code] = session_id
        
        logger.info("🔗 Pre-auth code linked to session",
                   pre_auth_code=pre_auth_code[:20] + "...",
                   session_id=session_id[:20] + "...")
    
    def link_authorization_request(self, session_id: str, par_data: Dict[str, Any]) -> None:
        """
        Vincula datos de PAR a una sesión (inicio flujo DIDRoom)
        
        Args:
            session_id: ID de la sesión
            par_data: Datos del Pushed Authorization Request
        """
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")
        
        session["flows"]["authorization"] = {
            "par_data": par_data,
            "par_timestamp": datetime.now().isoformat(),
            "auth_code": None,  # Se llenará después
            "state": par_data.get("state")
        }
        
        logger.info("🔗 PAR data linked to session",
                   session_id=session_id[:20] + "...",
                   client_id=par_data.get("client_id", "Unknown")[:30] + "...",
                   redirect_uri=par_data.get("redirect_uri", "Unknown"))
    
    def link_request_uri(self, request_uri: str, session_id: str) -> None:
        """
        Mapea request_uri (del PAR) a session_id
        """
        self._request_uri_index[request_uri] = session_id
        
        logger.info("🔗 Request URI linked to session",
                   request_uri=request_uri[:50] + "...",
                   session_id=session_id[:20] + "...")
    
    def get_session_by_request_uri(self, request_uri: str) -> Optional[Dict[str, Any]]:
        """
        Recupera sesión usando el request_uri del PAR
        """
        session_id = self._request_uri_index.get(request_uri)
        if not session_id:
            logger.warning(f"⚠️ No session found for request_uri: {request_uri[:50]}...")
            return None
        
        return self.get_session(session_id)
    
    def link_authorization_code(self, session_id: str, auth_code: str) -> None:
        """
        Vincula un authorization code a una sesión (después de /authorize)
        """
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")
        
        if not session["flows"]["authorization"]:
            raise ValueError(f"Session {session_id} has no authorization flow data")
        
        session["flows"]["authorization"]["auth_code"] = auth_code
        session["flows"]["authorization"]["auth_code_timestamp"] = datetime.now().isoformat()
        
        self._auth_code_index[auth_code] = session_id
        
        logger.info("🔗 Authorization code linked to session",
                   auth_code=auth_code[:20] + "...",
                   session_id=session_id[:20] + "...")
    
    def validate_pkce(self, session_id: str, code_verifier: str) -> bool:
        """
        Valida PKCE para una sesión
        
        Args:
            session_id: ID de la sesión
            code_verifier: El verifier enviado por el wallet en /token
            
        Returns:
            True si la validación es exitosa
        """
        from pkce_validator import PKCEValidator
        
        session = self.get_session(session_id)
        if not session:
            logger.error(f"❌ PKCE validation failed - session not found: {session_id[:20]}...")
            return False
        
        auth_flow = session["flows"].get("authorization")
        if not auth_flow or not auth_flow.get("par_data"):
            logger.error(f"❌ PKCE validation failed - no authorization flow data")
            return False
        
        par_data = auth_flow["par_data"]
        code_challenge = par_data.get("code_challenge")
        code_challenge_method = par_data.get("code_challenge_method", "S256")
        
        if not code_challenge:
            logger.error(f"❌ PKCE validation failed - no code_challenge in PAR data")
            return False
        
        logger.info("🔐 Validating PKCE for session",
                   session_id=session_id[:20] + "...",
                   method=code_challenge_method)
        
        is_valid = PKCEValidator.validate(code_verifier, code_challenge, code_challenge_method)
        
        if is_valid:
            logger.info(f"✅ PKCE validation successful for session {session_id[:20]}...")
        else:
            logger.error(f"❌ PKCE validation FAILED for session {session_id[:20]}...")
        
        return is_valid
    
    def link_access_token(self, session_id: str, access_token: str, c_nonce: str) -> None:
        """
        Vincula un access token a una sesión (después de /token)
        """
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")
        
        session["tokens"]["access_token"] = access_token
        session["tokens"]["c_nonce"] = c_nonce
        session["tokens"]["issued_at"] = datetime.now().isoformat()
        
        self._access_token_index[access_token] = session_id
        
        logger.info("🔗 Access token linked to session",
                   access_token=access_token[:20] + "...",
                   session_id=session_id[:20] + "...")
    
    def get_by_pre_auth_code(self, pre_auth_code: str) -> Optional[Dict[str, Any]]:
        """
        Recupera sesión usando pre-authorized code
        """
        session_id = self._pre_auth_index.get(pre_auth_code)
        if not session_id:
            logger.warning(f"⚠️ No session found for pre_auth_code: {pre_auth_code[:20]}...")
            return None
        
        return self.get_session(session_id)
    
    def get_by_auth_code(self, auth_code: str) -> Optional[Dict[str, Any]]:
        """
        Recupera sesión usando authorization code
        """
        session_id = self._auth_code_index.get(auth_code)
        if not session_id:
            logger.warning(f"⚠️ No session found for auth_code: {auth_code[:20]}...")
            return None
        
        return self.get_session(session_id)
    
    def get_by_access_token(self, access_token: str) -> Optional[Dict[str, Any]]:
        """
        Recupera sesión usando access token
        """
        session_id = self._access_token_index.get(access_token)
        if not session_id:
            logger.warning(f"⚠️ No session found for access_token: {access_token[:20]}...")
            return None
        
        return self.get_session(session_id)
    
    def _cleanup_session(self, session_id: str) -> None:
        """
        Limpia una sesión y todos sus índices
        """
        session = self._sessions.get(session_id)
        if not session:
            return
        
        # Limpiar índices
        pre_auth_code = session["flows"]["pre_authorized"].get("code") if session["flows"]["pre_authorized"] else None
        if pre_auth_code and pre_auth_code in self._pre_auth_index:
            del self._pre_auth_index[pre_auth_code]
        
        auth_code = session["flows"]["authorization"].get("auth_code") if session["flows"]["authorization"] else None
        if auth_code and auth_code in self._auth_code_index:
            del self._auth_code_index[auth_code]
        
        access_token = session["tokens"].get("access_token")
        if access_token and access_token in self._access_token_index:
            del self._access_token_index[access_token]
        
        # Eliminar sesión
        del self._sessions[session_id]
        
        logger.info(f"🗑️ Session cleaned up: {session_id[:20]}...")
    
    def cleanup_expired_sessions(self) -> int:
        """
        Limpia todas las sesiones expiradas
        
        Returns:
            Número de sesiones limpiadas
        """
        now = datetime.now()
        expired_sessions = []
        
        for session_id, session in self._sessions.items():
            expires_at = datetime.fromisoformat(session["expires_at"])
            if now > expires_at:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self._cleanup_session(session_id)
        
        if expired_sessions:
            logger.info(f"🗑️ Cleaned up {len(expired_sessions)} expired sessions")
        
        return len(expired_sessions)


# Singleton global instance
session_manager = SessionManager()
