"""Input sanitization for OPC UA node IDs, browse paths, and variant values."""

from __future__ import annotations

import logging
import re

logger = logging.getLogger("presidio_opcua.sanitization")

_NODE_ID_NUMERIC = re.compile(r"^(ns=\d+;)?i=\d+$")
_NODE_ID_STRING = re.compile(r"^(ns=\d+;)?s=[\w\-./: ]+$")
_NODE_ID_GUID = re.compile(
    r"^(ns=\d+;)?g=[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_NODE_ID_OPAQUE = re.compile(r"^(ns=\d+;)?b=[A-Za-z0-9+/=]+$")

_DANGEROUS_CHARS = re.compile(r"[&|`$(){}!\\\x00-\x08\x0e-\x1f]")
_SQL_INJECTION = re.compile(
    r"(?:--|'|\"|\b(?:DROP|DELETE|INSERT|UPDATE|SELECT|UNION|ALTER|EXEC)\b)",
    re.IGNORECASE,
)
_PATH_TRAVERSAL = re.compile(r"\.\.[/\\]")

MAX_NODE_ID_LENGTH = 2048
MAX_BROWSE_PATH_LENGTH = 4096
MAX_VARIANT_STRING_LENGTH = 65536


def sanitize_node_id(node_id: object) -> object:
    """
    Validate and sanitize an OPC UA node ID.

    Accepts int, ``ua.NodeId``, or string representations.
    Raises ValueError for malformed or suspicious input.
    """
    if isinstance(node_id, int):
        return node_id

    if not isinstance(node_id, str):
        return node_id

    if len(node_id) > MAX_NODE_ID_LENGTH:
        raise ValueError(f"Node ID exceeds maximum length ({MAX_NODE_ID_LENGTH}): {len(node_id)}")

    stripped = node_id.strip()

    # Path traversal is always dangerous, even inside syntactically valid node IDs.
    if _PATH_TRAVERSAL.search(stripped):
        logger.warning("Path traversal detected in node ID: %r", stripped[:100])
        raise ValueError(f"Path traversal detected in node ID: {node_id!r}")

    # Recognise well-formed OPC UA node IDs early — their use of ';' as a
    # namespace separator is standard and must not trigger injection heuristics.
    if _NODE_ID_NUMERIC.match(stripped):
        return stripped
    if _NODE_ID_STRING.match(stripped):
        return stripped
    if _NODE_ID_GUID.match(stripped):
        return stripped
    if _NODE_ID_OPAQUE.match(stripped):
        return stripped

    # Only apply remaining heuristic checks to non-standard formats.
    if _SQL_INJECTION.search(stripped):
        logger.warning("Potential injection detected in node ID: %r", stripped[:100])
        raise ValueError(f"Suspicious pattern detected in node ID: {node_id!r}")

    if _DANGEROUS_CHARS.search(stripped):
        raise ValueError(f"Illegal characters in node ID: {node_id!r}")

    logger.debug("Non-standard node ID format accepted: %r", stripped[:100])
    return stripped


def sanitize_browse_path(path: str) -> str:
    """
    Validate and sanitize a browse path.

    Raises ValueError for paths with injection patterns or traversal attempts.
    """
    if not isinstance(path, str):
        raise TypeError(f"Browse path must be a string, got {type(path).__name__}")

    if len(path) > MAX_BROWSE_PATH_LENGTH:
        raise ValueError(
            f"Browse path exceeds maximum length ({MAX_BROWSE_PATH_LENGTH}): {len(path)}"
        )

    if _PATH_TRAVERSAL.search(path):
        raise ValueError(f"Path traversal detected in browse path: {path!r}")

    if _SQL_INJECTION.search(path):
        logger.warning("Potential injection in browse path: %r", path[:100])
        raise ValueError(f"Suspicious pattern detected in browse path: {path!r}")

    if _DANGEROUS_CHARS.search(path):
        raise ValueError(f"Illegal characters in browse path: {path!r}")

    return path.strip()


def sanitize_variant(value: object) -> object:
    """
    Sanitize a variant value before sending to an OPC UA server.

    Checks string values for injection patterns and enforces size limits.
    """
    if isinstance(value, str):
        if len(value) > MAX_VARIANT_STRING_LENGTH:
            raise ValueError(
                f"Variant string exceeds maximum length ({MAX_VARIANT_STRING_LENGTH})"
            )
        if _SQL_INJECTION.search(value):
            logger.warning("Potential injection in variant value: %r", value[:100])
            raise ValueError("Suspicious pattern detected in variant value")
    elif isinstance(value, bytes):
        if len(value) > MAX_VARIANT_STRING_LENGTH:
            raise ValueError(f"Variant bytes exceeds maximum length ({MAX_VARIANT_STRING_LENGTH})")
    elif isinstance(value, (list, tuple)):
        return type(value)(sanitize_variant(v) for v in value)

    return value
