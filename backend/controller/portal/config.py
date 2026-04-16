import os

# --- Portal Database ---
PORTAL_DB_URL = os.getenv("PORTAL_DB_URL", "postgresql://portal_user:password@portal-db:5432/portal_db")

# --- Moodle Database (read-only) ---
MOODLE_DB_READONLY_URL = os.getenv("MOODLE_DB_READONLY_URL", "postgresql://moodle_readonly:password@moodle-db:5432/moodle_db")
MOODLE_DB_PREFIX = "mdl_"

# --- Portal JWT (session tokens for portal users) ---
PORTAL_JWT_SECRET = os.getenv("PORTAL_JWT_SECRET", "")
PORTAL_JWT_ALGORITHM = "HS256"
PORTAL_JWT_EXPIRE_MINUTES = int(os.getenv("PORTAL_JWT_EXPIRE_MINUTES", "1440"))

# --- Moodle-to-Portal JWT (redirect tokens from Moodle) ---
MOODLE_PORTAL_JWT_SECRET = os.getenv("MOODLE_PORTAL_JWT_SECRET", "")

# --- Frontend ---
PORTAL_FRONTEND_URL = os.getenv("PORTAL_FRONTEND_URL", "http://localhost:5173")

# --- Issuer info ---
ISSUER_NAME = os.getenv("UNIVERSITY_NAME", "Universidad Tecnologica Nacional")


def validate_config() -> None:
    """Validate that required secrets are configured. Called at startup."""
    missing = []
    if not PORTAL_JWT_SECRET:
        missing.append("PORTAL_JWT_SECRET")
    if not MOODLE_PORTAL_JWT_SECRET:
        missing.append("MOODLE_PORTAL_JWT_SECRET")
    if missing:
        raise RuntimeError(f"Portal configuration error: missing environment variables: {', '.join(missing)}")
