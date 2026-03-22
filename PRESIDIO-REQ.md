# Presidio-Hardened OPC UA – Top-Level Requirements

## Overview
Build a production-ready Python package `presidio-hardened-opcua` that acts as a hardened wrapper around the popular `opcua` library (python-opcua).
Users write: `from presidio_opcua import Client, Server` (and similar re-exports) instead of `from opcua import ...`, and their existing OPC UA code mostly works unchanged while receiving strong security defaults via config overrides, secure defaults, and middleware-like hooks.

## Mandatory Presidio Security Extensions
- Enforce mutual authentication and certificate validation by default (reject self-signed unless explicitly allowed)
- Strict security policy enforcement: prefer SignAndEncrypt, reject None security mode
- Message-level anomaly detection/logging (unexpected node access, malformed requests)
- Input sanitization for node IDs, browse paths, and variant values (prevent injection-like attacks)
- Automatic dependency/CVE quick-check on startup for opcua and cryptography deps
- Secure session timeout and token renewal hardening
- Security event logging ("Presidio hardening applied to OPC UA session")
- Full GitHub security files: SECURITY.md, .github/dependabot.yml, .github/workflows/codeql.yml + pytest + ruff workflow

## Technical Requirements
- Python 3.9+
- Modern pyproject.toml + hatchling/uv
- src/presidio_opcua/__init__.py layout with re-exports, custom Client/Server subclasses, and auto-applied secure configs
- Do NOT copy opcua source; wrap/extend via subclassing Client/Server, overriding connect methods, and secure defaults
- 85%+ test coverage with pytest (mock opcua where possible, include secure connection tests)
- Black + ruff enforced
- README.md with side-by-side examples: plain opcua vs presidio-hardened-opcua showing security improvements (e.g. enforced encryption, cert validation)
- LICENSE = MIT
- Version = 0.1.0

