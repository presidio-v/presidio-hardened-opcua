"""Presidio-Hardened OPC UA – secure wrapper around python-opcua."""

from __future__ import annotations

__version__ = "0.1.0"

from presidio_opcua.anomaly import AnomalyDetector
from presidio_opcua.client import HardenedClient as Client
from presidio_opcua.dep_check import check_dependencies
from presidio_opcua.sanitization import sanitize_browse_path, sanitize_node_id, sanitize_variant
from presidio_opcua.security import (
    PresidioSecurityError,
    SecurityMode,
    SecurityPolicy,
    validate_certificate,
)
from presidio_opcua.server import HardenedServer as Server

try:
    from opcua import ua
    from opcua.common.node import Node
except ImportError as exc:
    raise ImportError(
        "presidio-hardened-opcua requires the 'opcua' package. Install it with: pip install opcua"
    ) from exc

__all__ = [
    "Client",
    "Server",
    "ua",
    "Node",
    "SecurityPolicy",
    "SecurityMode",
    "PresidioSecurityError",
    "validate_certificate",
    "sanitize_node_id",
    "sanitize_browse_path",
    "sanitize_variant",
    "AnomalyDetector",
    "check_dependencies",
    "__version__",
]
