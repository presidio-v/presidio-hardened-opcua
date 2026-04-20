# Presidio-Hardened OPC UA — Requirements

## Overview

`presidio-hardened-opcua` is a hardened wrapper around
[`python-opcua`](https://github.com/FreeOpcUa/python-opcua) that adds
certificate validation, encryption enforcement, anomaly detection, and
input sanitisation to existing OPC UA client and server code through a
single import swap. It serves a dual role:

- **Courseware** for **PRES-EDU-SEC-METHODS Experiment 1** (OPC-UA Security
  Modes), where it is used to demonstrate plain-vs-hardened OPC UA flows on
  a lab network.
- **Production industrial wrapper** supplied on customer request for
  OT-network hardening where `python-opcua` is already in place.

## Mandatory Presidio Security Extensions

- Certificate validation — self-signed certificates are rejected unless
  explicitly allowed via the `SecurityPolicy` object
- Encryption enforcement — `client.connect()` raises
  `PresidioSecurityError` unless a security policy has been set
- Tight session timeouts — default `session_timeout_ms=30_000` (configurable
  down to the customer's requirement)
- Anomaly detection on authentication failures, unexpected disconnects, and
  unusual read/write patterns
- Input sanitisation for node IDs, browse paths, and method-call arguments
- Structured security event logging (`presidio_opcua` logger)
- Full GitHub security files: `SECURITY.md`, `.github/dependabot.yml`,
  `.github/workflows/codeql.yml`, `.github/workflows/ci.yml`

## Technical Requirements

- Python 3.10+
- `opcua` (upstream — not wrapped; wrapping happens at the client / server
  class level)
- `src/presidio_opcua/` layout
- pytest with ≥ 85 % line coverage
- ruff lint + format enforced in CI
- MIT License, version 0.1.0

## Out of scope

- Address-space design for customer OPC UA servers
- Certificate issuance / PKI — handled by the customer's OT CA, not by the
  library

## Version Deliberation Log

### v0.1.0 — Initial release

**Scope decision:** Wrap `python-opcua` rather than `asyncua`. The customer
brief specified their existing integration uses the synchronous
`python-opcua` API; requiring a migration to `asyncua` as a prerequisite
for hardening would have blocked adoption. The library therefore targets
the same synchronous surface.

**Scope decision:** Encryption enforcement raises rather than warns.
`python-opcua`'s default lets `connect()` succeed with no encryption;
preserving that behaviour with a warning was judged unsafe given the
customer's OT threat model, where a missing `SecurityPolicy` is itself the
finding.

**Scope decision:** Dual-role positioning (courseware + production). The
teaching use-case requires the plain-vs-hardened contrast to be visible in
slide-ready code snippets; the production use-case requires the hardening
to be the default when imported as `presidio_opcua`. Both are served by
exposing the upstream class names from `presidio_opcua` — the import swap
is the demonstration.

## Roadmap

- **v0.2.0 — asyncua migration path.** Add an `asyncua`-compatible API
  surface (`presidio_opcua.aio`) alongside the existing synchronous one.
  The synchronous surface remains the default until the customer's
  integration migrates. Deprecation of the synchronous surface is not
  planned at this stage; both will be supported in parallel.

## SDLC

These requirements are delivered under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
