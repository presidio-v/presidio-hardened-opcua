# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in `presidio-hardened-opcua`, please report it responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email your report to **security@presidio.example.com** with:
   - A description of the vulnerability
   - Steps to reproduce (if applicable)
   - Impact assessment
   - Suggested fix (optional)
3. You will receive an acknowledgement within **48 hours**.
4. We aim to release a patch within **7 days** for critical issues.

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
