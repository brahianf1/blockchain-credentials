from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func

from portal.database import Base


class PortalStudent(Base):
    __tablename__ = "portal_students"

    id = Column(Integer, primary_key=True, index=True)
    moodle_user_id = Column(Integer, unique=True, nullable=False, index=True)
    email = Column(String(254), unique=True, nullable=False, index=True)
    full_name = Column(String(200), nullable=False)
    password_hash = Column(String(128), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_login_at = Column(DateTime(timezone=True), nullable=True)
