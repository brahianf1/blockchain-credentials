#!/usr/bin/env python3
"""
OpenID4VC Router - Main entry point
Combines all modular routers into single FastAPI router
"""

from fastapi import APIRouter
import structlog

from .metadata_endpoints import metadata_router
from .core_endpoints import core_router

logger = structlog.get_logger()

# Create main router with prefix
oid4vc_router = APIRouter(prefix="/oid4vc", tags=["OpenID4VC"])

# Include all sub-routers
oid4vc_router.include_router(metadata_router)
oid4vc_router.include_router(core_router)

logger.info("✅ OpenID4VC Router initialized with modular architecture")

__all__ = ["oid4vc_router"]
