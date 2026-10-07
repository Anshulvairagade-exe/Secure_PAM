"""
Explainable, deterministic risk engine.

NOT machine learning, NOT an external model — every factor is a plain
rule over data already in the request/target/user, and the same inputs
always produce the same score (pure function, no hidden state beyond the
explicit `context`). This is deliberate: a risk score that can't be
explained to the person it was applied to isn't acceptable for a PAM
decision.

IMPORTANT: the weights below (RISK_WEIGHTS) are THIS PROJECT'S choices,
not an industry standard, not derived from any external framework, and
not validated against real incident data. They exist to make Phase 4's
decision flow demonstrable and adjustable in one place — tune them for
a real deployment.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Union

from app.core.business_hours import is_business_hours
from app.models.application import Application
from app.models.asset import Asset
from app.models.user import User

# --- Weights: project-specific, see module docstring ---
RISK_WEIGHTS = {
    "PRODUCTION_ASSET": 30,
    "CRITICAL_ASSET": 25,
    "HIGH_CRITICALITY": 15,
    "SENSITIVE_APPLICATION": 20,
    "HIGH_PRIVILEGE_ROLE": 20,
    "OUTSIDE_BUSINESS_HOURS": 20,
    "UNKNOWN_CONTEXT": 20,
    "REPEATED_AUTH_FAILURE": 20,
    "UNUSUAL_ACCESS_PATTERN": 20,
    "LONG_DURATION": 10,
}

# A target's own `environment`/`criticality` and the requester's role
# already exist as data — these constants are the only genuinely
# arbitrary judgment calls in the engine, kept here (not buried in
# conditionals) so they're easy to find and justify.
HIGH_PRIVILEGE_ROLES = {"ADMIN"}
LONG_DURATION_THRESHOLD_MINUTES = 60

# (minimum_score, level) — highest threshold that the score meets or
# exceeds wins. Matches the spec exactly: 0-29 LOW, 30-59 MEDIUM,
# 60-79 HIGH, 80+ CRITICAL.
RISK_LEVEL_THRESHOLDS = (
    (80, "CRITICAL"),
    (60, "HIGH"),
    (30, "MEDIUM"),
    (0, "LOW"),
)


@dataclass(frozen=True)
class RiskFactor:
    code: str
    points: int
    reason: str


@dataclass(frozen=True)
class RiskResult:
    score: int
    level: str
    factors: List[RiskFactor]

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "factors": [{"code": f.code, "points": f.points, "reason": f.reason} for f in self.factors],
        }


@dataclass
class RiskContext:
    """
    Inputs the engine cannot derive from the target/user rows alone.
    `now` is injectable so time-dependent factors (business hours) are
    actually testable/reproducible rather than depending on wall-clock
    time at test-run time.
    """
    now: Optional[datetime] = None
    source_ip: Optional[str] = None
    # Number of PRIOR access requests this user has made (any target),
    # not counting the one currently being evaluated. None means "not
    # computed" — callers that can cheaply query it should; it's never
    # inferred to be either 0 or nonzero when omitted.
    prior_request_count: Optional[int] = None


def _level_for(score: int) -> str:
    for threshold, level in RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "LOW"  # unreachable — the 0 threshold always matches first


def evaluate_risk(
    *,
    user: User,
    target: Union[Asset, Application],
    requested_duration: int,
    context: Optional[RiskContext] = None,
) -> RiskResult:
    """
    Pure function: same user/target/duration/context always produces the
    same RiskResult. Does not touch the database or any mutable state —
    callers (app/services/access_decision.py) are responsible for
    gathering `context.prior_request_count` beforehand.
    """
    context = context or RiskContext()
    now = context.now or datetime.now(timezone.utc)
    factors: List[RiskFactor] = []
    is_application = isinstance(target, Application)

    if target.environment == "PRODUCTION":
        factors.append(RiskFactor(
            "PRODUCTION_ASSET", RISK_WEIGHTS["PRODUCTION_ASSET"],
            "Target environment is PRODUCTION",
        ))

    # Asset and Application criticality are scored under distinct codes —
    # "sensitive application" reads more naturally than "critical asset"
    # for a web app, and keeps the two target kinds from silently double
    # counting if a future change adds both an asset_id and application_id
    # concept to one request.
    if is_application:
        if target.criticality in ("HIGH", "CRITICAL"):
            factors.append(RiskFactor(
                "SENSITIVE_APPLICATION", RISK_WEIGHTS["SENSITIVE_APPLICATION"],
                f"Application criticality is {target.criticality}",
            ))
    else:
        if target.criticality == "CRITICAL":
            factors.append(RiskFactor(
                "CRITICAL_ASSET", RISK_WEIGHTS["CRITICAL_ASSET"],
                "Target asset criticality is CRITICAL",
            ))
        elif target.criticality == "HIGH":
            factors.append(RiskFactor(
                "HIGH_CRITICALITY", RISK_WEIGHTS["HIGH_CRITICALITY"],
                "Target asset criticality is HIGH",
            ))

    user_role_names = {ur.role.name for ur in user.roles if ur.role}
    high_priv_held = user_role_names & HIGH_PRIVILEGE_ROLES
    if high_priv_held:
        factors.append(RiskFactor(
            "HIGH_PRIVILEGE_ROLE", RISK_WEIGHTS["HIGH_PRIVILEGE_ROLE"],
            f"Requester holds a high-privilege role ({', '.join(sorted(high_priv_held))})",
        ))

    if not is_business_hours(now):
        factors.append(RiskFactor(
            "OUTSIDE_BUSINESS_HOURS", RISK_WEIGHTS["OUTSIDE_BUSINESS_HOURS"],
            "Request made outside business hours (09:00-17:00 UTC, Mon-Fri)",
        ))

    if not context.source_ip:
        factors.append(RiskFactor(
            "UNKNOWN_CONTEXT", RISK_WEIGHTS["UNKNOWN_CONTEXT"],
            "Request source IP could not be determined",
        ))

    if user.failed_login_count and user.failed_login_count > 0:
        factors.append(RiskFactor(
            "REPEATED_AUTH_FAILURE", RISK_WEIGHTS["REPEATED_AUTH_FAILURE"],
            f"{user.failed_login_count} recent failed login attempt(s) on this account",
        ))

    if context.prior_request_count == 0:
        factors.append(RiskFactor(
            "UNUSUAL_ACCESS_PATTERN", RISK_WEIGHTS["UNUSUAL_ACCESS_PATTERN"],
            "This is the requester's first-ever access request — no established pattern to compare against",
        ))

    if requested_duration > LONG_DURATION_THRESHOLD_MINUTES:
        factors.append(RiskFactor(
            "LONG_DURATION", RISK_WEIGHTS["LONG_DURATION"],
            f"Requested duration ({requested_duration}m) exceeds {LONG_DURATION_THRESHOLD_MINUTES}m",
        ))

    score = sum(f.points for f in factors)
    return RiskResult(score=score, level=_level_for(score), factors=factors)
