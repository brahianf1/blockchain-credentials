from typing import Generator

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from portal.database import PortalSessionLocal, MoodleSessionLocal
from portal.auth import decode_portal_jwt
from portal.models import PortalStudent

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/portal/auth/login")


def get_portal_db() -> Generator[Session, None, None]:
    """Yield a portal database session, ensuring proper cleanup."""
    db = PortalSessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_moodle_db() -> Generator[Session, None, None]:
    """Yield a Moodle database session (read-only), ensuring proper cleanup."""
    db = MoodleSessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_portal_db),
) -> PortalStudent:
    """Resolve the currently authenticated portal student from the Bearer token."""
    payload = decode_portal_jwt(token)
    student_id = int(payload["sub"])

    student = db.query(PortalStudent).filter(PortalStudent.id == student_id).first()
    if not student or not student.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado o cuenta desactivada",
        )

    return student


def require_admin(
    current_user: PortalStudent = Depends(get_current_user),
) -> PortalStudent:
    """Authorize an admin-only operation.

    Relies on the ``role`` field synced from Moodle's ``is_siteadmin()``
    claim during the JWT authentication flow.  This guard NEVER grants
    admin access based on static configuration — the identity provider
    (Moodle) is the single source of truth.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado: se requieren permisos de administrador",
        )
    return current_user
