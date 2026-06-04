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

The library evolves in three sequenced layers. The ordering is deliberate:
a normative hardening profile and its conformance tests come first, because
they are what keep every implementation surface (sync, async, and a future
Rust gateway) enforcing *identical* security semantics rather than drifting
apart. Dependency arrows: the profile (Phase A) unblocks the async surface
(Phase B) and the gateway decision (Phase D); the feasibility spike (Phase C)
gates the gateway. B and C can run in parallel once A exists.

### Phase A — Hardening Profile + conformance tests

Extract the security rules that are currently *implicit in Python behaviour*
into a normative `HARDENING-PROFILE.md`, and back it with a conformance test
suite asserted against the profile (not merely against current code). This is
the source of truth every surface implements. The profile covers six domains,
all of which already exist in code today:

1. **Transport & security mode** — reject `MessageSecurityMode.None` unless
   `allow_no_security`; default to `SignAndEncrypt`; server strips
   `NoSecurity` policies and fails closed if none remain; auto-apply
   `Basic256Sha256_SignAndEncrypt` when started with no policy set.
2. **Certificate validation** — reject expired / not-yet-valid and (by
   default) self-signed certificates; validate the server certificate when
   supplied. Chain-to-anchor and revocation remain delegated to the
   customer's OT CA (see *Out of scope*).
3. **Input sanitisation** — node IDs, browse paths, and method/variant
   arguments: length caps, path-traversal rejection, well-formed-node-ID
   whitelisting ahead of injection heuristics.
4. **Anomaly detection** — access-rate and unique-node (scan) thresholds
   over a sliding window, emitting `high_rate` / `node_scan` alerts.
5. **Dependency / CVE posture** — import-time version-floor checks for the
   upstream OPC UA stack and `cryptography`.
6. **Logging schema** — namespaced `presidio_opcua.*` loggers; INFO for
   security decisions, WARNING for rejections. This schema is the contract a
   future Rust gateway emits too, so one SIEM ingests both identically.

**Open profile decisions (to be resolved when the profile is written):**

- **Cipher floor.** The profile names `Basic256Sha256` as the floor but does
  not yet *forbid* the deprecated `Basic128Rsa15` / `Basic256` suites. Decide
  whether to ban them explicitly.
- **Trust boundary.** Validation today is expiry + self-signed only; `asyncua`
  performs its own trust-store plumbing. The profile must state exactly where
  the trust boundary sits so the sync and async surfaces cannot silently
  disagree on what "validated" means.
- **Anomaly recording point.** Access is currently recorded at `get_node`.
  Under `asyncua`, `get_node` is pure object construction with no I/O, so a
  node handle built once and read many times would be undercounted. The
  profile should fix the recording point at the **read/write call**, and both
  surfaces should be (re)wired to that point.

### Phase B — v0.2.0: parallel `aio` surface

Add an `asyncua`-compatible API surface (`presidio_opcua.aio`) **alongside**
the existing synchronous one. The synchronous surface remains the default
until the customer's integration migrates; both are supported in parallel.
The entire security core (`security`, `sanitization`, `anomaly`, `dep_check`)
is pure, I/O-free logic and is shared verbatim between both surfaces — "one
brain, two shells." Only the thin I/O wrappers fork, and the sync→async
mapping is non-uniform:

- `Client.connect`, `set_security`, `set_security_string` become coroutines.
- `Client.get_node` **stays synchronous** (construction only); its node-ID
  sanitisation ports verbatim.
- Anomaly recording and variant sanitisation move to the async read/write
  calls (per the Phase A decision).
- `Server` gains an async `init()` (asyncua splits construction from init)
  and async `start` / `stop`; `set_security_policy` stays synchronous.

Phase B also adds an `asyncua` entry to the CVE check and a `pytest-asyncio`
axis to the test matrix; the shared security-core tests still run once.

### Phase C — Rust gateway feasibility spike (decision, not product)

A timeboxed, throwaway prototype answering one question: can the Rust
`async-opcua` stack terminate a `SignAndEncrypt` secure channel as a *server*
to downstream clients **and** originate one as a *client* to upstream
servers, bridging the address space while enforcing two or three profile
rules? This is necessary because OPC UA secures at the SecureChannel layer:
a hardening gateway cannot be a transparent proxy — it must be a full
dual-stack endpoint. The spike's only deliverable is a go/no-go memo on the
Rust stack's production-readiness for both roles.

### Phase D — (conditional on C) Rust hardened gateway

Only if Phase C returns "go": scope a standalone Rust hardened OPC UA gateway
as its own repository / product, implementing the **same** hardening profile
as the Python wrapper. It serves the deployments the import-swap wrapper
cannot — non-Python clients, network-DMZ enforcement between IT and OT, a
single audit chokepoint with no per-client code change. The Python wrapper
and the Rust gateway are complementary surfaces of one profile, not a
rewrite of one into the other. A full Rust refactor of *this* library is
explicitly rejected: it would discard the import-swap distribution model and
the courseware role, and would move memory-safety guarantees to glue code
(cert checks, regex, logging) rather than to the wire-facing protocol parser,
which lives upstream and is out of this library's scope regardless.

## Support posture — synchronous surface

The synchronous surface wraps `python-opcua`, which FreeOpcUa has deprecated
in favour of `asyncua`. It is therefore supported as a **compatibility
bridge** for existing integrations, not as a perpetual surface. If a
vulnerability is reported in `python-opcua` with no upstream fix available,
the documented remediation is **migration to the `aio` surface**, not a
backport into the unmaintained library. No hard deprecation of the sync
surface is scheduled, but customers should treat `aio` as the forward path.

## Known gaps

Logged honestly so they are tracked rather than rediscovered:

- **Unwired sanitisers.** `sanitize_browse_path` and `sanitize_variant` are
  implemented but not yet called from the client/server overrides; only
  `sanitize_node_id` is wired in. The profile must specify hook points for
  all three, and Phase B is the natural point to wire them into both surfaces.
- **Anomaly recording point is semantically weak for async** (see the Phase A
  open decision); it counts node-handle creation rather than actual reads.

## SDLC

These requirements are delivered under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
