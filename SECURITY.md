# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

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
| **Message Limits** | Caps chunk size, chunks per message and message size on every received message (CVE-2022-25304) |
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
- **Memory Exhaustion**: Message limits bound what a peer can make the process buffer

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

## Known Issues

### CVE-2022-25304 — mitigated, not fixed

Advisory: [GHSA-mfpj-3qhm-976m](https://github.com/advisories/GHSA-mfpj-3qhm-976m)
(also PYSEC-2026-888). python-opcua trusts the `body_size` field of each message header
and appends every Intermediate chunk to the message being assembled without a limit, so a
single forged header or an endless chunk stream exhausts memory. python-opcua is
unmaintained and no fixed release exists, so vulnerability scanners will keep reporting
`opcua==0.98.13`.

Since 0.2.0, importing `presidio_opcua` replaces the affected receive paths with bounded
versions (`presidio_opcua/limits.py`):

| Limit | Default | Override |
|-------|---------|----------|
| Chunk body size (checked from the header, before buffering) | 64 MiB | `max_chunk_size=` / `PRESIDIO_OPCUA_MAX_CHUNK_SIZE` |
| Chunks per message | 1601 | `max_chunk_count=` / `PRESIDIO_OPCUA_MAX_CHUNK_COUNT` |
| Total message size | 100 MiB | `max_message_size=` / `PRESIDIO_OPCUA_MAX_MESSAGE_SIZE` |

A breach raises `MessageLimitError` (a `ua.UaError`), discards the partial message and
closes the connection, on the server and on the client. The server also closes the
connection on any other parse error, which upstream only logged.

Scope and caveats:

- The guards patch upstream classes and are **process-wide**: every `opcua` client and
  server in the process is bounded once `presidio_opcua` is imported, including plain
  `opcua.Client`/`opcua.Server`. Keyword arguments on `Server`/`Client` set limits per
  instance; everything else uses the environment variables or the defaults.
- The negotiated buffer sizes are not used as the cap: python-opcua's server echoes the
  peer's Hello values, so they are attacker-chosen.
- The guards depend on python-opcua internals, so `opcua` is pinned to `==0.98.13`.
  Import fails with an explicit `ImportError` if a patched attribute is missing.
- A peer can still make the process hold up to the configured limits per connection.
  Pair the limits with a connection cap at the network layer.

Long-term fix: migrate to [asyncua](https://github.com/FreeOpcUa/opcua-asyncio), the
maintained successor, which enforces chunk and message limits itself. Its synchronous
wrapper `asyncua.sync` keeps a blocking API close to python-opcua's.

## Dependencies

| Dependency | Purpose | Version |
|------------|---------|---------|
| `opcua` | OPC UA protocol implementation | ==0.98.13 (pinned, see Known Issues) |
| `cryptography` | Certificate parsing and validation | >=41.0.0 |

## Automated Security Checks

- **GitHub CodeQL**: Static analysis on every push and PR
- **Dependabot**: Automated dependency update PRs
- **CI Pipeline**: ruff linting + full test suite on every commit

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
