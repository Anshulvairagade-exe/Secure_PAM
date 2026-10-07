"""
Shared enums for Asset/Application/Policy schemas.

These validate at the API boundary (FastAPI/Pydantic rejects an invalid
value with a 422 automatically) — the DB columns themselves stay plain
String/ARRAY(String), consistent with every other model in this codebase
(see app/models/user.py etc.), which documents allowed values via column
comments rather than DB-level CHECK constraints or native enum types.
"""

from enum import Enum


class AssetType(str, Enum):
    WINDOWS_SERVER = "WINDOWS_SERVER"
    WINDOWS_WORKSTATION = "WINDOWS_WORKSTATION"
    LINUX_SERVER = "LINUX_SERVER"
    UNIX_SERVER = "UNIX_SERVER"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    OTHER = "OTHER"


class Environment(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    TEST = "TEST"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class Criticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Protocol(str, Enum):
    RDP = "RDP"
    SSH = "SSH"
    HTTPS = "HTTPS"
    HTTP = "HTTP"


class AccessMode(str, Enum):
    STANDARD_PROXY = "STANDARD_PROXY"
    ISOLATED_BROWSER = "ISOLATED_BROWSER"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RoleName(str, Enum):
    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    APPROVER = "APPROVER"
    AUDITOR = "AUDITOR"


class DayOfWeek(str, Enum):
    MON = "MON"
    TUE = "TUE"
    WED = "WED"
    THU = "THU"
    FRI = "FRI"
    SAT = "SAT"
    SUN = "SUN"
