# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory
(via the "Security" tab → "Report a vulnerability") rather than a public issue.

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgement within 5 business days. We aim to release a patch
within 30 days of a confirmed vulnerability.

## Security Design

### Hardening Layers

`presidio-hardened-opcua` wraps the `opcua` (python-opcua) library with the following security layers:

| Layer | Description |
|-------|-------------|
| **Certificate Validation** | Validates X.509 certificates on connect; rejects self-signed by default |
| **Security Mode Enforcement** | Requires `SignAndEncrypt` mode; blocks `None` security mode |
| **Input Sanitization** | Validates node IDs, browse paths, and variant values against injection and traversal patterns |
| **Anomaly Detection** | Monitors access patterns for rate anomalies and node scanning behaviour |
| **Dependency CVE Check** | Checks `opcua` and `cryptography` versions against known vulnerabilities at startup |
| **Session Hardening** | Enforces configurable session and secure channel timeouts |
| **Security Event Logging** | Logs all security-relevant events under `presidio_opcua.*` loggers |

### Threat Model

This package mitigates the following threats common in OPC UA deployments:

- **Eavesdropping**: Enforced encryption via `SignAndEncrypt` mode
- **Man-in-the-Middle**: Certificate validation prevents impersonation
- **Injection Attacks**: Input sanitization blocks malformed node IDs and browse paths
- **Reconnaissance**: Anomaly detection flags rapid node scanning
- **Supply Chain**: Dependency CVE checks warn about known vulnerabilities
- **Session Hijack**: Strict timeouts limit session exposure window

### Secure Defaults

All security features are **enabled by default**. To relax any policy, you must set explicit flags:

```python
from presidio_opcua import SecurityPolicy

# Default: maximum security
policy = SecurityPolicy()

# Relaxed (NOT recommended for production):
policy = SecurityPolicy(
    allow_self_signed=True,
    allow_no_security=True,
)
```

## Dependencies

| Dependency | Purpose | Minimum Version |
|------------|---------|-----------------|
| `opcua` | OPC UA protocol implementation | 0.98.13 |
| `cryptography` | Certificate parsing and validation | 41.0.0 |

## Automated Security Checks

- **GitHub CodeQL**: Static analysis on every push and PR
- **Dependabot**: Automated dependency update PRs
- **CI Pipeline**: ruff linting + full test suite on every commit

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
