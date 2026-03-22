"""Hardened OPC UA Client with Presidio security extensions."""

from __future__ import annotations

import logging
from typing import Any

from opcua import Client as _BaseClient
from opcua import ua

from presidio_opcua.anomaly import AnomalyDetector
from presidio_opcua.dep_check import check_dependencies
from presidio_opcua.sanitization import sanitize_node_id
from presidio_opcua.security import (
    PresidioSecurityError,
    SecurityPolicy,
    enforce_security_mode,
    validate_certificate,
)

logger = logging.getLogger("presidio_opcua.client")


class HardenedClient(_BaseClient):
    """
    Drop-in replacement for ``opcua.Client`` with Presidio security hardening.

    Enforces certificate validation, strict security policies, input sanitization,
    anomaly detection, and secure session defaults.
    """

    def __init__(
        self,
        url: str,
        timeout: int = 4,
        *,
        security_policy: SecurityPolicy | None = None,
    ) -> None:
        super().__init__(url, timeout=timeout)
        self.presidio_policy = security_policy or SecurityPolicy()
        self._security_configured = False
        self._anomaly_detector = AnomalyDetector()

        dep_issues = check_dependencies()
        if dep_issues:
            logger.warning("Dependency issues found: %s", dep_issues)

        logger.info("Presidio hardening applied to OPC UA client session (url=%s)", url)

    def set_security(
        self,
        policy: Any,
        certificate_path: str,
        private_key_path: str,
        server_certificate_path: str | None = None,
        mode: Any = None,
    ) -> None:
        """Set security with Presidio validation on top of opcua's ``set_security``."""
        if mode is None:
            mode = ua.MessageSecurityMode.SignAndEncrypt

        mode_name = mode.name if hasattr(mode, "name") else str(mode)
        enforce_security_mode(mode_name, allow_none=self.presidio_policy.allow_no_security)

        if not self.presidio_policy.allow_self_signed:
            validate_certificate(
                certificate_path,
                allow_self_signed=self.presidio_policy.allow_self_signed,
            )
            if server_certificate_path:
                validate_certificate(
                    server_certificate_path,
                    allow_self_signed=self.presidio_policy.allow_self_signed,
                )

        self._security_configured = True
        logger.info("Security configured: policy=%s, mode=%s", policy, mode_name)
        super().set_security(
            policy, certificate_path, private_key_path, server_certificate_path, mode
        )

    def set_security_string(self, string: str) -> None:
        """Parse security string and validate the security mode component."""
        parts = string.split(",")
        if len(parts) >= 2:
            mode_str = parts[1].strip()
            enforce_security_mode(mode_str, allow_none=self.presidio_policy.allow_no_security)
        self._security_configured = True
        logger.info("Security configured from string")
        super().set_security_string(string)

    def connect(self) -> None:
        """Connect with Presidio-enforced security checks."""
        if not self._security_configured and not self.presidio_policy.allow_no_security:
            raise PresidioSecurityError(
                "Cannot connect without security configuration. "
                "Call set_security() first or set allow_no_security=True (not recommended)."
            )

        self.session_timeout = self.presidio_policy.session_timeout_ms
        self.secure_channel_timeout = self.presidio_policy.secure_channel_timeout_ms

        logger.info("Establishing Presidio-hardened connection...")
        super().connect()
        logger.info("Presidio-hardened secure connection established")

    def get_node(self, nodeid: Any) -> Any:
        """Get a node with input sanitization and anomaly tracking."""
        sanitized = sanitize_node_id(nodeid)
        self._anomaly_detector.record_access(sanitized)
        return super().get_node(sanitized)

    @property
    def anomaly_detector(self) -> AnomalyDetector:
        """Access the anomaly detector for inspection and configuration."""
        return self._anomaly_detector
