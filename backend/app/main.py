"""
SecurePAM — FastAPI Application Entry Point.

This is the main application factory that:
1. Configures CORS, middleware, and security headers
2. Mounts health check endpoints (no auth required)
3. Mounts API v1 endpoints (auth required)
4. Runs database initialization and seeding on startup
"""

import time
import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.health import router as health_router
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.database.session import close_db, engine

configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle — startup and shutdown."""
    logger.info(
        "app_starting",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        dev_mode=settings.DEV_MODE,
    )

    # Initialize database tables (in dev mode, create tables directly)
    if settings.DEV_MODE:
        from app.models import Base
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("db_tables_created", mode="DEV_MODE")

        # Seed default data
        await _seed_default_data()

    yield

    # Shutdown
    await close_db()
    logger.info("app_shutdown", app=settings.APP_NAME)


app = FastAPI(
    title=settings.APP_NAME,
    description="Risk-Adaptive Privileged Access Management Platform",
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.DEV_MODE else None,
    redoc_url="/redoc" if settings.DEV_MODE else None,
    lifespan=lifespan,
)


# --- Middleware ---

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    """
    Assign a request ID, bind it (plus method/path) to structlog's
    contextvars so every log line emitted while handling this request
    carries it, expose it back to the client via X-Request-ID, and log
    one structured line per request with status/duration.
    """
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
    )

    start = time.monotonic()
    try:
        response: Response = await call_next(request)
    except Exception:
        duration_ms = round((time.monotonic() - start) * 1000, 2)
        logger.error("request_failed", duration_ms=duration_ms, exc_info=True)
        raise

    duration_ms = round((time.monotonic() - start) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "request_completed",
        status_code=response.status_code,
        duration_ms=duration_ms,
    )
    return response


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # This is a pure JSON API — no inline scripts/styles are ever served, so
    # the policy can stay maximally restrictive.
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    if not settings.DEV_MODE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# --- Exception Handlers ---
#
# Every error response — validation failures, raised HTTPExceptions, and
# unhandled exceptions alike — shares the same envelope:
#   {"detail": "<message>", "error_code": "<MACHINE_CODE>", "errors": [...] | null}
# so frontend error handling has exactly one shape to deal with. Internals
# (stack traces, exception class names, SQL) are logged server-side and
# never put in the response body.


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Pydantic/FastAPI request validation failures — 422."""
    logger.info("validation_failed", errors=exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Request validation failed.",
            "error_code": "VALIDATION_ERROR",
            "errors": [
                {"loc": list(e.get("loc", [])), "msg": e.get("msg"), "type": e.get("type")}
                for e in exc.errors()
            ],
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Any explicitly raised HTTPException (401/403/404/409/503/...)."""
    logger.info("http_exception", status_code=exc.status_code, detail=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error_code": None, "errors": None},
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all for unhandled exceptions. Never expose stack traces to users —
    log the real error server-side and return a generic 500.
    """
    logger.error("unhandled_exception", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal error occurred. Please try again later.",
            "error_code": "INTERNAL_ERROR",
            "errors": None,
        },
    )


# --- Routes ---

# Health endpoints — no auth, no prefix
app.include_router(health_router)

# API v1 endpoints — auth required
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


# --- Database Seeding ---

async def _seed_default_data():
    """Seed default roles, permissions, and dev users."""
    from app.database.session import async_session_factory
    from app.models.role import Permission, Role
    from app.models.user import User, UserRole
    from app.core.security import hash_password
    from sqlalchemy import select

    async with async_session_factory() as db:
        # Check if already seeded
        result = await db.execute(select(Role).limit(1))
        if result.scalar_one_or_none():
            logger.info("Database already seeded")
            return

        logger.info("Seeding default data...")

        # --- Create Permissions ---
        permission_defs = [
            # Users
            ("users:read", "users", "read", "View users"),
            ("users:create", "users", "create", "Create users"),
            ("users:update", "users", "update", "Update users"),
            ("users:delete", "users", "delete", "Delete users"),
            # Assets
            ("assets:read", "assets", "read", "View assets"),
            ("assets:create", "assets", "create", "Create assets"),
            ("assets:update", "assets", "update", "Update assets"),
            ("assets:delete", "assets", "delete", "Delete assets"),
            # Applications
            ("applications:read", "applications", "read", "View applications"),
            ("applications:create", "applications", "create", "Create applications"),
            ("applications:update", "applications", "update", "Update applications"),
            ("applications:delete", "applications", "delete", "Delete applications"),
            # Access Requests
            ("access_requests:read", "access_requests", "read", "View access requests"),
            ("access_requests:create", "access_requests", "create", "Create access requests"),
            ("access_requests:read_own", "access_requests", "read_own", "View own requests"),
            # Approvals
            ("approvals:read", "approvals", "read", "View approvals"),
            ("approvals:approve", "approvals", "approve", "Approve requests"),
            ("approvals:reject", "approvals", "reject", "Reject requests"),
            # Sessions
            ("sessions:read", "sessions", "read", "View all sessions"),
            ("sessions:read_own", "sessions", "read_own", "View own sessions"),
            ("sessions:create", "sessions", "create", "Start sessions"),
            ("sessions:terminate", "sessions", "terminate", "Terminate sessions"),
            # Recordings
            ("recordings:read", "recordings", "read", "View recordings"),
            ("recordings:download", "recordings", "download", "Download recordings"),
            ("recordings:delete", "recordings", "delete", "Delete recordings"),
            # Audit
            ("audit:read", "audit", "read", "View audit logs"),
            ("audit:export", "audit", "export", "Export audit logs"),
            # Policies
            ("policies:read", "policies", "read", "View policies"),
            ("policies:create", "policies", "create", "Create policies"),
            ("policies:update", "policies", "update", "Update policies"),
            ("policies:delete", "policies", "delete", "Delete policies"),
            # Vault
            ("vault:read", "vault", "read", "View vault references"),
            ("vault:manage", "vault", "manage", "Manage vault entries"),
            # Risk
            ("risk:read", "risk", "read", "View risk data"),
            # Dashboard
            ("dashboard:read", "dashboard", "read", "View dashboard"),
            # Settings
            ("settings:read", "settings", "read", "View settings"),
            ("settings:update", "settings", "update", "Update settings"),
        ]

        permissions = {}
        for name, resource, action, description in permission_defs:
            perm = Permission(
                name=name,
                resource=resource,
                action=action,
                description=description,
            )
            db.add(perm)
            permissions[name] = perm

        await db.flush()

        # --- Create Roles ---
        admin_role = Role(
            name="ADMIN",
            description="Full system administrator with all privileges",
            is_system=True,
        )
        admin_role.permissions = list(permissions.values())

        operator_role = Role(
            name="OPERATOR",
            description="Standard operator who can request and use privileged access",
            is_system=True,
        )
        operator_role.permissions = [
            permissions["assets:read"],
            permissions["applications:read"],
            permissions["access_requests:create"],
            permissions["access_requests:read_own"],
            permissions["sessions:read_own"],
            permissions["sessions:create"],
            permissions["dashboard:read"],
        ]

        approver_role = Role(
            name="APPROVER",
            description="Can review and approve/reject access requests",
            is_system=True,
        )
        approver_role.permissions = [
            permissions["assets:read"],
            permissions["applications:read"],
            permissions["access_requests:read"],
            permissions["approvals:read"],
            permissions["approvals:approve"],
            permissions["approvals:reject"],
            permissions["risk:read"],
            permissions["dashboard:read"],
        ]

        auditor_role = Role(
            name="AUDITOR",
            description="Can view audit logs, recordings, and generate reports",
            is_system=True,
        )
        auditor_role.permissions = [
            permissions["audit:read"],
            permissions["audit:export"],
            permissions["recordings:read"],
            permissions["sessions:read"],
            permissions["access_requests:read"],
            permissions["risk:read"],
            permissions["dashboard:read"],
        ]

        db.add_all([admin_role, operator_role, approver_role, auditor_role])
        await db.flush()

        # --- Create Dev Users (DEV_MODE only) ---
        dev_users = [
            {
                "username": "admin",
                "email": "admin@securepam.local",
                "full_name": "System Administrator",
                "password": "admin123",
                "mfa_enabled": True,
                "role": admin_role,
            },
            {
                "username": "operator",
                "email": "operator@securepam.local",
                "full_name": "John Operator",
                "password": "operator123",
                "mfa_enabled": True,
                "role": operator_role,
            },
            {
                "username": "approver",
                "email": "approver@securepam.local",
                "full_name": "Jane Approver",
                "password": "approver123",
                "mfa_enabled": True,
                "role": approver_role,
            },
            {
                "username": "auditor",
                "email": "auditor@securepam.local",
                "full_name": "Bob Auditor",
                "password": "auditor123",
                "mfa_enabled": False,
                "role": auditor_role,
            },
        ]

        for user_data in dev_users:
            user = User(
                username=user_data["username"],
                email=user_data["email"],
                full_name=user_data["full_name"],
                hashed_password=hash_password(user_data["password"]),
                mfa_enabled=user_data["mfa_enabled"],
                is_active=True,
            )
            db.add(user)
            await db.flush()

            user_role = UserRole(
                user_id=user.id,
                role_id=user_data["role"].id,
            )
            db.add(user_role)

        # --- Seed Sample Assets ---
        from app.models.asset import Asset

        sample_assets = [
            Asset(
                name="WIN-PROD-01",
                hostname="win-prod-01.internal",
                ip_address="10.0.1.10",
                port=3389,
                protocol="RDP",
                asset_type="WINDOWS",
                environment="PRODUCTION",
                criticality="HIGH",
                description="Production Windows Server — Domain Controller",
                status="ACTIVE",
                owner="Infrastructure Team",
                recording_required=True,
                approval_required=True,
                jit_required=True,
            ),
            Asset(
                name="WIN-DEV-01",
                hostname="win-dev-01.internal",
                ip_address="10.0.2.10",
                port=3389,
                protocol="RDP",
                asset_type="WINDOWS",
                environment="DEVELOPMENT",
                criticality="LOW",
                description="Development Windows Workstation",
                status="ACTIVE",
                owner="Development Team",
                recording_required=False,
                approval_required=False,
                jit_required=True,
            ),
            Asset(
                name="LINUX-PROD-01",
                hostname="linux-prod-01.internal",
                ip_address="10.0.1.20",
                port=22,
                protocol="SSH",
                asset_type="LINUX",
                environment="PRODUCTION",
                criticality="HIGH",
                description="Production Linux Server — Application Host",
                status="ACTIVE",
                owner="DevOps Team",
                recording_required=True,
                approval_required=True,
                jit_required=True,
            ),
            Asset(
                name="LINUX-DEV-01",
                hostname="linux-dev-01.internal",
                ip_address="10.0.2.20",
                port=22,
                protocol="SSH",
                asset_type="LINUX",
                environment="DEVELOPMENT",
                criticality="MEDIUM",
                description="Development Ubuntu Server",
                status="ACTIVE",
                owner="Development Team",
                recording_required=False,
                approval_required=False,
                jit_required=True,
            ),
            Asset(
                name="LINUX-STAGING-01",
                hostname="linux-staging-01.internal",
                ip_address="10.0.3.20",
                port=22,
                protocol="SSH",
                asset_type="LINUX",
                environment="STAGING",
                criticality="MEDIUM",
                description="Staging Linux Server",
                status="ACTIVE",
                owner="QA Team",
                recording_required=True,
                approval_required=False,
                jit_required=True,
            ),
        ]
        db.add_all(sample_assets)

        # --- Seed Sample Applications ---
        from app.models.application import Application

        sample_apps = [
            Application(
                name="Admin Portal",
                description="Internal administration dashboard — HIGH risk",
                target_url="https://admin.internal:8443",
                protocol="HTTPS",
                target_host="admin.internal",
                target_port=8443,
                risk_level="HIGH",
                proxy_mode="ISOLATED_BROWSER",
                approval_required=True,
                mfa_required=True,
                recording_required=True,
                download_allowed=False,
                upload_allowed=False,
                clipboard_allowed=False,
                session_timeout=30,
                status="ACTIVE",
            ),
            Application(
                name="Monitoring Dashboard",
                description="Grafana monitoring dashboard",
                target_url="http://monitoring.internal:3000",
                protocol="HTTP",
                target_host="monitoring.internal",
                target_port=3000,
                risk_level="LOW",
                proxy_mode="STANDARD_PROXY",
                approval_required=False,
                mfa_required=False,
                recording_required=False,
                download_allowed=True,
                upload_allowed=False,
                clipboard_allowed=True,
                session_timeout=60,
                status="ACTIVE",
            ),
            Application(
                name="CI/CD Pipeline",
                description="Jenkins CI/CD server",
                target_url="https://jenkins.internal:8080",
                protocol="HTTPS",
                target_host="jenkins.internal",
                target_port=8080,
                risk_level="MEDIUM",
                proxy_mode="STANDARD_PROXY",
                approval_required=False,
                mfa_required=True,
                recording_required=False,
                download_allowed=True,
                upload_allowed=True,
                clipboard_allowed=True,
                session_timeout=60,
                status="ACTIVE",
            ),
        ]
        db.add_all(sample_apps)

        # --- Seed Default Policies ---
        from app.models.policy import Policy

        default_policies = [
            Policy(
                name="Standard Access",
                description="Default policy for low-risk access",
                risk_threshold="LOW",
                min_risk_score=0,
                approval_required=False,
                jit_required=True,
                mfa_required=False,
                recording_required=False,
                session_timeout=60,
                download_allowed=True,
                upload_allowed=True,
                clipboard_allowed=True,
                auto_approve=True,
                deny_access=False,
                is_active=True,
            ),
            Policy(
                name="Enhanced Security",
                description="Policy for medium-risk access requiring MFA",
                risk_threshold="MEDIUM",
                min_risk_score=30,
                approval_required=False,
                jit_required=True,
                mfa_required=True,
                recording_required=False,
                session_timeout=30,
                download_allowed=True,
                upload_allowed=True,
                clipboard_allowed=True,
                auto_approve=False,
                deny_access=False,
                is_active=True,
            ),
            Policy(
                name="High Security",
                description="Policy for high-risk access requiring approval, JIT, MFA, and recording",
                risk_threshold="HIGH",
                min_risk_score=60,
                approval_required=True,
                jit_required=True,
                mfa_required=True,
                recording_required=True,
                session_timeout=30,
                download_allowed=False,
                upload_allowed=False,
                clipboard_allowed=False,
                auto_approve=False,
                deny_access=False,
                is_active=True,
            ),
            Policy(
                name="Critical Lockdown",
                description="Policy for critical-risk — deny or require elevated approval",
                risk_threshold="CRITICAL",
                min_risk_score=80,
                approval_required=True,
                jit_required=True,
                mfa_required=True,
                recording_required=True,
                session_timeout=15,
                download_allowed=False,
                upload_allowed=False,
                clipboard_allowed=False,
                auto_approve=False,
                deny_access=True,
                is_active=True,
            ),
        ]
        db.add_all(default_policies)

        await db.commit()
        logger.info("Default data seeded successfully")
