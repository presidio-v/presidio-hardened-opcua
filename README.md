# presidio-hardened-opcua

**Hardened OPC UA wrapper with Presidio security extensions.**

[![CI](https://github.com/presidio-v/presidio-hardened-opcua/actions/workflows/ci.yml/badge.svg)](https://github.com/presidio-v/presidio-hardened-opcua/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Drop-in replacement for [python-opcua](https://github.com/FreeOpcUa/python-opcua) that adds **strong security defaults**, **certificate validation**, **anomaly detection**, and **input sanitization** — all without changing your existing OPC UA code.

> **Security notice — CVE-2022-25304.** The underlying `opcua` (python-opcua 0.98.13) is
> unmaintained and has no fix for this memory-exhaustion issue. Since 0.2.0 this package
> bounds chunk size, chunk count and message size process-wide on import, so scanners will
> still flag `opcua` but the attack is mitigated. See [SECURITY.md](SECURITY.md#known-issues).

## Installation

```bash
pip install presidio-hardened-opcua
```

## Quick Start

Replace your existing import:

```python
# Before (plain opcua)
from opcua import Client, Server

# After (Presidio-hardened)
from presidio_opcua import Client, Server
```

That's it. Your existing code gains security hardening automatically.

## Side-by-Side Comparison

### Plain opcua — no security enforced

```python
from opcua import Client

client = Client("opc.tcp://10.0.0.5:4840")
client.connect()  # ← connects with NO encryption
node = client.get_node("ns=2;i=1")  # ← no input sanitization
value = node.get_value()
client.disconnect()
```

**Problems:** No certificate validation, no encryption requirement, no anomaly detection, no input sanitization. An attacker on the network can eavesdrop, tamper, or inject malicious node IDs.

### presidio-hardened-opcua — secure by default

```python
from presidio_opcua import Client, SecurityPolicy

policy = SecurityPolicy(
    allow_self_signed=False,  # reject self-signed certs
    session_timeout_ms=30_000,  # tight session timeout
)

client = Client("opc.tcp://10.0.0.5:4840", security_policy=policy)

# Security is enforced — this will FAIL without calling set_security() first:
# client.connect()  → raises PresidioSecurityError

# Configure mutual authentication:
client.set_security(
    "Basic256Sha256",
    certificate_path="client_cert.der",
    private_key_path="client_key.pem",
    server_certificate_path="server_cert.der",
    # mode defaults to SignAndEncrypt — cannot be set to None
)

client.connect()  # ✓ encrypted, authenticated, hardened timeouts

# Node IDs are automatically sanitized:
node = client.get_node("ns=2;i=1")  # ✓ validated
value = node.get_value()

# Anomaly detection runs in the background:
print(client.anomaly_detector.stats)

client.disconnect()
```

### Server — insecure policies automatically rejected

```python
from presidio_opcua import Server
from opcua import ua

server = Server()

# NoSecurity is silently filtered out:
server.set_security_policy(
    [
        ua.SecurityPolicyType.NoSecurity,  # ← rejected
        ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,  # ← kept
    ]
)

server.start()
```

## Security Features

| Feature | Description |
|---------|-------------|
| **Certificate Validation** | Rejects self-signed certs by default; validates expiry and format |
| **Strict Security Mode** | Enforces `SignAndEncrypt`; rejects `None` security mode |
| **Input Sanitization** | Validates node IDs, browse paths, and variant values against injection patterns |
| **Anomaly Detection** | Monitors access rate and unique-node counts; logs warnings on suspicious activity |
| **Dependency CVE Check** | Checks installed versions of `opcua` and `cryptography` against known vulnerabilities |
| **Message Limits** | Bounds chunk size, chunk count and message size (CVE-2022-25304) |
| **Session Hardening** | Configurable session and channel timeouts (defaults: 30s / 60s) |
| **Security Event Logging** | All security decisions logged via Python `logging` under `presidio_opcua.*` |

## Configuration

```python
from presidio_opcua import SecurityPolicy

policy = SecurityPolicy(
    allow_self_signed=False,  # reject self-signed certificates
    allow_no_security=False,  # reject None security mode
    session_timeout_ms=30_000,  # session timeout in milliseconds
    secure_channel_timeout_ms=60_000,  # secure channel timeout
)
```

### Message limits (CVE-2022-25304)

```python
from presidio_opcua import Client, Server

server = Server(max_chunk_count=256, max_message_size=16 * 1024 * 1024)
client = Client("opc.tcp://10.0.0.5:4840", max_chunk_size=1024 * 1024)
```

Defaults: 64 MiB per chunk, 1601 chunks per message, 100 MiB per message. Environment
overrides: `PRESIDIO_OPCUA_MAX_CHUNK_SIZE`, `PRESIDIO_OPCUA_MAX_CHUNK_COUNT`,
`PRESIDIO_OPCUA_MAX_MESSAGE_SIZE`. The guards apply to every `opcua` connection in the
process; the keyword arguments set limits for that instance only.

## Logging

Enable security event logging:

```python
import logging

logging.basicConfig(level=logging.INFO)

# All Presidio security events are logged under:
#   presidio_opcua.client
#   presidio_opcua.server
#   presidio_opcua.security
#   presidio_opcua.anomaly
#   presidio_opcua.dep_check
#   presidio_opcua.limits
```

## Development

```bash
git clone https://github.com/presidio-v/presidio-hardened-opcua.git
cd presidio-hardened-opcua
pip install -e ".[dev]"
pytest --cov=presidio_opcua
ruff check .
```

## License

MIT — see [LICENSE](LICENSE).

---

## SDLC

This repository is on the **open-source baseline** of the PRESIDIO hardened-family SDLC
([report](https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md) ·
[PDF](https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.pdf)).
The controls measured for it, and any open gaps, are its row in the
[applicability matrix](https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/applicability.md).
