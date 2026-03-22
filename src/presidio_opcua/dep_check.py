"""Dependency and CVE quick-check for opcua and cryptography."""

from __future__ import annotations

import importlib.metadata
import logging
import re
import warnings
from dataclasses import dataclass

logger = logging.getLogger("presidio_opcua.dep_check")


@dataclass(frozen=True)
class VulnerableRange:
    package: str
    description: str
    max_affected: str


KNOWN_VULNERABILITIES: list[VulnerableRange] = [
    VulnerableRange(
        package="opcua",
        description="Insecure default session handling in python-opcua < 0.98.13",
        max_affected="0.98.12",
    ),
    VulnerableRange(
        package="cryptography",
        description="CVE-2023-49083: NULL-pointer dereference in cryptography < 41.0.6",
        max_affected="41.0.5",
    ),
]


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple of ints."""
    parts: list[int] = []
    for part in version_str.split("."):
        digits = re.match(r"(\d+)", part)
        if digits:
            parts.append(int(digits.group(1)))
        else:
            break
    return tuple(parts)


def _version_lte(a: str, b: str) -> bool:
    return _parse_version(a) <= _parse_version(b)


def check_dependencies() -> list[str]:
    """
    Check installed dependencies for known vulnerabilities.

    Returns a list of warning messages (empty if all clean).
    """
    issues: list[str] = []

    for vuln in KNOWN_VULNERABILITIES:
        try:
            installed = importlib.metadata.version(vuln.package)
        except importlib.metadata.PackageNotFoundError:
            msg = f"Required package '{vuln.package}' is not installed"
            logger.warning(msg)
            issues.append(msg)
            continue

        if _version_lte(installed, vuln.max_affected):
            msg = (
                f"SECURITY: {vuln.package}=={installed} is affected by "
                f"{vuln.description}. "
                f"Upgrade to a version newer than {vuln.max_affected}."
            )
            logger.warning(msg)
            warnings.warn(msg, stacklevel=2)
            issues.append(msg)
        else:
            logger.debug(
                "%s==%s is not affected by known vulnerabilities",
                vuln.package,
                installed,
            )

    if not issues:
        logger.info("Dependency CVE check passed – no known vulnerabilities found")

    return issues
