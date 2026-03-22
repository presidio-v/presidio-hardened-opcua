"""Certificate validation, security policy enforcement, and session hardening."""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger("presidio_opcua.security")


class PresidioSecurityError(Exception):
    """Raised when a Presidio security policy is violated."""


class SecurityMode(str, Enum):
    SIGN_AND_ENCRYPT = "SignAndEncrypt"
    SIGN = "Sign"
    NONE = "None"


@dataclass
class SecurityPolicy:
    """Presidio security policy configuration."""

    allow_self_signed: bool = False
    allow_no_security: bool = False
    min_security_mode: SecurityMode = SecurityMode.SIGN_AND_ENCRYPT
    session_timeout_ms: int = 30_000
    secure_channel_timeout_ms: int = 60_000
    rejected_policies: list[str] = field(default_factory=lambda: ["NoSecurity"])

    def is_mode_allowed(self, mode_name: str) -> bool:
        if mode_name in ("None", "None_") and not self.allow_no_security:
            return False
        return True


def validate_certificate(
    cert_path: str | Path,
    *,
    allow_self_signed: bool = False,
) -> dict:
    """
    Validate an X.509 certificate file.

    Returns a dict with certificate details. Raises ValueError for invalid certs.
    """
    cert_path = Path(cert_path)
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate file not found: {cert_path}")

    try:
        from cryptography import x509
    except ImportError as exc:
        raise ImportError("Certificate validation requires the 'cryptography' package.") from exc

    raw = cert_path.read_bytes()

    try:
        cert = x509.load_der_x509_certificate(raw)
    except Exception:
        try:
            cert = x509.load_pem_x509_certificate(raw)
        except Exception as exc:
            raise ValueError(f"Cannot parse certificate: {cert_path}") from exc

    now = datetime.datetime.now(datetime.timezone.utc)

    # Handle both old (not_valid_after) and new (_utc) cryptography APIs
    try:
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
    except AttributeError:
        not_after = cert.not_valid_after
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=datetime.timezone.utc)
        not_before = cert.not_valid_before
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=datetime.timezone.utc)

    if not_after < now:
        raise ValueError(f"Certificate expired on {not_after}: {cert_path}")

    if not_before > now:
        raise ValueError(f"Certificate not yet valid (starts {not_before}): {cert_path}")

    is_self_signed = cert.issuer == cert.subject
    if is_self_signed and not allow_self_signed:
        raise ValueError(
            f"Self-signed certificate rejected by Presidio policy: {cert_path}. "
            "Set allow_self_signed=True to override."
        )

    info = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": str(not_before),
        "not_after": str(not_after),
        "self_signed": is_self_signed,
        "serial_number": cert.serial_number,
    }

    logger.info("Certificate validated: %s (self_signed=%s)", cert_path, is_self_signed)
    return info


def enforce_security_mode(mode_name: str, *, allow_none: bool = False) -> None:
    """Raise if the security mode is None and not explicitly allowed."""
    if mode_name in ("None", "None_") and not allow_none:
        raise PresidioSecurityError(
            f"Security mode '{mode_name}' rejected by Presidio hardening. "
            "Use allow_no_security=True to override (not recommended)."
        )
    logger.debug("Security mode '%s' accepted", mode_name)
