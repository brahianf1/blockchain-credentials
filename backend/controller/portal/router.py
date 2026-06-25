from fastapi import APIRouter

from portal.admin_endpoints import admin_router
from portal.auth_endpoints import auth_router
from portal.blockchain_endpoints import blockchain_public_router
from portal.credential_endpoints import credential_router
from portal.public_endpoints import public_router
from portal.revocation_endpoints import admin_credential_router
from portal.stats_endpoints import stats_router

# Authenticated portal routes → /api/portal/*
portal_router = APIRouter(prefix="/api/portal")
portal_router.include_router(auth_router)
portal_router.include_router(credential_router)
portal_router.include_router(stats_router)

# Public routes (no auth) → /api/public/*
portal_public_router = APIRouter(prefix="/api")
portal_public_router.include_router(public_router)
portal_public_router.include_router(blockchain_public_router)

# Admin routes → /api/admin/*
portal_admin_router = APIRouter(prefix="/api")
portal_admin_router.include_router(admin_router)
portal_admin_router.include_router(admin_credential_router)
