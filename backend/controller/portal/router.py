from fastapi import APIRouter

from portal.auth_endpoints import auth_router
from portal.credential_endpoints import credential_router
from portal.stats_endpoints import stats_router
from portal.public_endpoints import public_router

# Authenticated portal routes → /api/portal/*
portal_router = APIRouter(prefix="/api/portal")
portal_router.include_router(auth_router)
portal_router.include_router(credential_router)
portal_router.include_router(stats_router)

# Public routes (no auth) → /api/public/*
portal_public_router = APIRouter(prefix="/api")
portal_public_router.include_router(public_router)
