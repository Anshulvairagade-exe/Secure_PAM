"""
Safe, actionable responses for session launches that fail at credential
checkout or at the gateway.

The reason codes come from CredentialService (and the secret providers)
and from the SSH gateway. Configuration and infrastructure problems get a
specific message, because an operator or administrator can act on them;
none of them reveals a secret, token or internal address. Authorization
failures stay deliberately coarse so callers cannot probe which check
failed (the precise reason is in the audit log).
"""

from fastapi import HTTPException, status

# reason -> (HTTP status, message shown to the user)
_CREDENTIAL_ERRORS = {
    "NO_CREDENTIAL_REFERENCE": (
        status.HTTP_409_CONFLICT,
        "No credential is configured for this target. An administrator must set its credential reference.",
    ),
    "AMBIGUOUS_CREDENTIAL_REFERENCE": (
        status.HTTP_409_CONFLICT,
        "This target has more than one active credential reference. An administrator must resolve it.",
    ),
    "SECRET_NOT_FOUND": (
        status.HTTP_409_CONFLICT,
        "The target's credential reference points to a secret that does not exist in the secret store. "
        "An administrator must store the secret or correct the reference.",
    ),
    "MALFORMED_SECRET": (
        status.HTTP_409_CONFLICT,
        "The stored secret for this target is not in the expected format (for example, it has no password field).",
    ),
    "INVALID_SECRET_REFERENCE": (
        status.HTTP_409_CONFLICT,
        "The target's credential reference is invalid. An administrator must correct it.",
    ),
    "PROVIDER_ACCESS_DENIED": (
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "The gateway's secret-store identity is not permitted to read this credential. "
        "An administrator must check its read policy.",
    ),
    "PROVIDER_UNAVAILABLE": (
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "The secret store is unreachable. Try again shortly.",
    ),
    "PROVIDER_MISCONFIGURED": (
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "The secret store is not configured correctly on the server.",
    ),
}
_DEFAULT_UNAVAILABLE = (status.HTTP_503_SERVICE_UNAVAILABLE, "The credential could not be retrieved; session not started.")

# Reasons from CredentialAccessDenied that are configuration, not authorization.
_CONFIGURATION_DENIALS = {"NO_CREDENTIAL_REFERENCE", "AMBIGUOUS_CREDENTIAL_REFERENCE"}

_GATEWAY_ERRORS = {
    "HOST_KEY_UNTRUSTED": (
        status.HTTP_502_BAD_GATEWAY,
        "The target's SSH host key is not trusted or has changed. Connection refused to prevent impersonation.",
    ),
    "TARGET_AUTH_FAILED": (
        status.HTTP_502_BAD_GATEWAY,
        "The target rejected the stored credential. An administrator must update the secret.",
    ),
    "TARGET_UNREACHABLE": (
        status.HTTP_502_BAD_GATEWAY,
        "The target could not be reached from the gateway.",
    ),
    "GATEWAY_UNAVAILABLE": (
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "The session gateway for this protocol is not deployed; no session was started.",
    ),
    "CREDENTIAL_UNSUPPORTED": (
        status.HTTP_409_CONFLICT,
        "The stored credential type is not supported for this protocol.",
    ),
}
_DEFAULT_GATEWAY = (status.HTTP_502_BAD_GATEWAY, "The session gateway could not start the session.")


def credential_unavailable_error(reason: str) -> HTTPException:
    code, message = _CREDENTIAL_ERRORS.get(reason, _DEFAULT_UNAVAILABLE)
    return HTTPException(code, message)


def credential_denied_error(reason: str) -> HTTPException:
    if reason in _CONFIGURATION_DENIALS:
        code, message = _CREDENTIAL_ERRORS[reason]
        return HTTPException(code, message)
    return HTTPException(status.HTTP_403_FORBIDDEN, "Credential access was denied for this session.")


def gateway_error(code: str) -> HTTPException:
    status_code, message = _GATEWAY_ERRORS.get(code, _DEFAULT_GATEWAY)
    return HTTPException(status_code, message)


def failure_message(reason: str) -> str:
    """Short user-facing text for a failure reason (WebSocket close, session list)."""
    for table in (_CREDENTIAL_ERRORS, _GATEWAY_ERRORS):
        if reason in table:
            return table[reason][1]
    return {
        "TICKET_REQUIRED": "A connection ticket is required.",
        "TICKET_INVALID": "The connection ticket is invalid or has expired.",
        "SESSION_NOT_CONNECTABLE": "This session can no longer be connected.",
        "JIT_GRANT_INVALID": "The just-in-time grant is expired or invalid.",
        "AUTHORIZATION_REVOKED": "User or target is no longer active.",
        "ACCESS_REQUEST_NOT_ACTIVE": "This access request is not active.",
        "ASSET_DISABLED": "This target is not available.",
        "RECORDING_START_FAILED": "Session recording could not start; access denied.",
        "RECORDING_WRITE_FAILED": "Session recording failed; the session was ended.",
    }.get(reason, "The session could not be started.")
