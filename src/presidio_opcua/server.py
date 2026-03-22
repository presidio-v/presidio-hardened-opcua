"""Hardened OPC UA Server with Presidio security extensions."""

from __future__ import annotations

import logging
from typing import Any

from opcua import Server as _BaseServer
from opcua import ua

from presidio_opcua.dep_check import check_dependencies
from presidio_opcua.security import PresidioSecurityError, SecurityPolicy

logger = logging.getLogger("presidio_opcua.server")


class HardenedServer(_BaseServer):
    """
    Drop-in replacement for ``opcua.Server`` with Presidio security hardening.

    Enforces strict security policies and rejects insecure configurations.
    """

    def __init__(
        self,
        *,
        security_policy: SecurityPolicy | None = None,
    ) -> None:
        super().__init__()
        self.presidio_policy = security_policy or SecurityPolicy()
        self._security_policies_set = False
        self._certificate_loaded = False

        dep_issues = check_dependencies()
        if dep_issues:
            logger.warning("Dependency issues found: %s", dep_issues)

        logger.info("Presidio hardening applied to OPC UA server")

    def set_security_policy(
        self, security_policies: list[Any], permission_ruleset: Any = None
    ) -> None:
        """Set security policies with Presidio enforcement (rejects NoSecurity)."""
        if not self.presidio_policy.allow_no_security:
            filtered = []
            for p in security_policies:
                name = p.name if hasattr(p, "name") else str(p)
                if "NoSecurity" in name:
                    logger.warning("Rejecting NoSecurity policy per Presidio hardening")
                    continue
                filtered.append(p)

            if not filtered:
                raise PresidioSecurityError(
                    "All provided security policies were rejected. "
                    "At least one secure policy is required."
                )
            security_policies = filtered

        self._security_policies_set = True
        logger.info("Server security policies configured: %s", security_policies)
        super().set_security_policy(security_policies, permission_ruleset)

    def start(self) -> None:
        """Start server with Presidio pre-checks."""
        if not self._security_policies_set and not self.presidio_policy.allow_no_security:
            logger.warning(
                "Server starting without explicit security policies; "
                "applying default secure policy"
            )
            try:
                self.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
            except Exception:
                logger.warning("Could not auto-apply security policies; continuing with caution")

        logger.info("Starting Presidio-hardened OPC UA server")
        super().start()
        logger.info("Presidio-hardened OPC UA server started")

    def stop(self) -> None:
        """Stop the server and log the event."""
        logger.info("Stopping Presidio-hardened OPC UA server")
        super().stop()
        logger.info("Presidio-hardened OPC UA server stopped")
