from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from portal.config import PORTAL_DB_URL, MOODLE_DB_READONLY_URL

# --- Portal DB (read/write) ---
portal_engine = create_engine(
    PORTAL_DB_URL,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
)
PortalSessionLocal = sessionmaker(bind=portal_engine, autocommit=False, autoflush=False)

# --- Moodle DB (read-only) ---
moodle_engine = create_engine(
    MOODLE_DB_READONLY_URL,
    pool_size=3,
    max_overflow=5,
    pool_pre_ping=True,
    execution_options={"postgresql_readonly": True},
)
MoodleSessionLocal = sessionmaker(bind=moodle_engine, autocommit=False, autoflush=False)

# --- ORM Base for portal models ---
Base = declarative_base()
