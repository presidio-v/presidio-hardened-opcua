# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-18

### Security

- Mitigate CVE-2022-25304 (GHSA-mfpj-3qhm-976m, PYSEC-2026-888), a memory-exhaustion
  issue in python-opcua that has no upstream fix. Importing `presidio_opcua` now bounds
  every received chunk (64 MiB, checked from the header before buffering), the chunks per
  message (1601) and the total message size (100 MiB) on both server and client, and
  closes the connection on a breach. The guards are process-wide.
- The server now closes the connection on any message parse error instead of only
  logging it.

### Added

- `max_chunk_size`, `max_chunk_count` and `max_message_size` keyword arguments on
  `Server` and `Client`, `PRESIDIO_OPCUA_MAX_*` environment overrides, and the
  `MessageLimits` / `MessageLimitError` exports.
- `Client` advertises its chunk-count and message-size limits in the Hello message.

### Changed

- `opcua` is pinned to `==0.98.13`, since the guards depend on its internals.

## [0.1.0]

- Initial release.

[0.2.0]: https://github.com/presidio-v/presidio-hardened-opcua/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/presidio-v/presidio-hardened-opcua/releases/tag/v0.1.0
