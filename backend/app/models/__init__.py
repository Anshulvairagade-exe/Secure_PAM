"""
SecurePAM Models — Central import for all database models.

Import all models here so Alembic can discover them for migrations.
"""

from app.database.base import Base

from app.models.user import User, UserRole
from app.models.role import Role, Permission, role_permissions
from app.models.asset import Asset
from app.models.application import Application
from app.models.policy import Policy
from app.models.access_request import AccessRequest
from app.models.approval import Approval
from app.models.jit_grant import JITGrant
from app.models.session import Session, SessionEvent
from app.models.recording import Recording
from app.models.audit import AuditLog, RiskEvent
from app.models.vault_ref import VaultRef
from app.models.notification import Notification
from app.models.app_setting import AppSetting
from app.models.risk_finding import RiskFinding

__all__ = [
    "RiskFinding",
    "Base",
    "User",
    "UserRole",
    "Role",
    "Permission",
    "role_permissions",
    "Asset",
    "Application",
    "Policy",
    "AccessRequest",
    "Approval",
    "JITGrant",
    "Session",
    "SessionEvent",
    "Recording",
    "AuditLog",
    "RiskEvent",
    "VaultRef",
    "Notification",
    "AppSetting",
]
