"""
API v1 Router — aggregates all v1 endpoint routers.
"""

from fastapi import APIRouter

from app.api.v1.health import router as health_router
from app.api.v1.auth import router as auth_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.assets import router as assets_router
from app.api.v1.applications import router as applications_router
from app.api.v1.policies import router as policies_router
from app.api.v1.access_requests import router as access_requests_router
from app.api.v1.approvals import router as approvals_router

# Main v1 router
api_router = APIRouter()

# Include sub-routers
api_router.include_router(auth_router)
api_router.include_router(dashboard_router)
api_router.include_router(assets_router)
api_router.include_router(applications_router)
api_router.include_router(policies_router)
api_router.include_router(access_requests_router)
api_router.include_router(approvals_router)

# Health is mounted at root level, not under /api/v1
