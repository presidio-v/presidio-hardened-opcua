"""Chunk and message size limits for python-opcua (CVE-2022-25304 mitigation).

python-opcua 0.98.13 trusts the ``body_size`` field of every message header and appends
every Intermediate chunk to the message being assembled without any upper bound, so a
peer can exhaust memory with one forged header or an endless chunk stream. No upstream
fix exists. ``install_guards`` replaces the affected receive paths with bounded versions.

The guards patch upstream classes and are therefore **process-wide**: once
``presidio_opcua`` is imported, every ``opcua`` client and server in the process is
bounded, including plain ``opcua.Client``/``opcua.Server`` instances. Hardened instances
can carry their own limits; everything else uses the process defaults.
"""

from __future__ import annotations

import logging
import os
import socket
from dataclasses import dataclass
from typing import Any, Callable

from opcua import ua
from opcua.client.ua_client import UASocketClient
from opcua.common import utils as ua_utils
from opcua.common.connection import SecureConnection
from opcua.server.binary_server_asyncio import OPCUAProtocol
from opcua.ua import ua_binary as uabin

logger = logging.getLogger("presidio_opcua.limits")

DEFAULT_MAX_CHUNK_SIZE = 64 * 1024 * 1024
DEFAULT_MAX_CHUNK_COUNT = 1601
DEFAULT_MAX_MESSAGE_SIZE = 100 * 1024 * 1024

# OPC UA Part 6, 7.1.2.3: buffers smaller than 8192 bytes are not allowed.
MIN_CHUNK_SIZE = 8192

ENV_MAX_CHUNK_SIZE = "PRESIDIO_OPCUA_MAX_CHUNK_SIZE"
ENV_MAX_CHUNK_COUNT = "PRESIDIO_OPCUA_MAX_CHUNK_COUNT"
ENV_MAX_MESSAGE_SIZE = "PRESIDIO_OPCUA_MAX_MESSAGE_SIZE"

_LIMITS_ATTR = "_presidio_limits"
_GUARD_MARKER = "__presidio_guard__"


class MessageLimitError(ua.UaError):
    """Raised when a peer exceeds the chunk size, chunk count or message size limit."""


@dataclass(frozen=True)
class MessageLimits:
    """Upper bounds applied to every received OPC UA chunk and message."""

    max_chunk_size: int = DEFAULT_MAX_CHUNK_SIZE
    max_chunk_count: int = DEFAULT_MAX_CHUNK_COUNT
    max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE

    def __post_init__(self) -> None:
        for name in ("max_chunk_size", "max_chunk_count", "max_message_size"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer, got {value!r}")
        if self.max_chunk_size < MIN_CHUNK_SIZE:
            raise ValueError(
                f"max_chunk_size must be at least {MIN_CHUNK_SIZE} bytes, "
                f"got {self.max_chunk_size}"
            )

    @classmethod
    def from_env(
        cls,
        *,
        max_chunk_size: int | None = None,
        max_chunk_count: int | None = None,
        max_message_size: int | None = None,
    ) -> MessageLimits:
        """Build limits: explicit arguments win over environment, environment over defaults."""
        return cls(
            max_chunk_size=_pick(max_chunk_size, ENV_MAX_CHUNK_SIZE, DEFAULT_MAX_CHUNK_SIZE),
            max_chunk_count=_pick(max_chunk_count, ENV_MAX_CHUNK_COUNT, DEFAULT_MAX_CHUNK_COUNT),
            max_message_size=_pick(
                max_message_size, ENV_MAX_MESSAGE_SIZE, DEFAULT_MAX_MESSAGE_SIZE
            ),
        )


def _pick(explicit: int | None, env_name: str, default: int) -> int:
    if explicit is not None:
        return explicit
    raw = os.environ.get(env_name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        raise ValueError(f"{env_name} must be an integer, got {raw!r}") from None


_default_limits: MessageLimits | None = None


def default_limits() -> MessageLimits:
    """Process-wide limits for connections that carry no limits of their own."""
    global _default_limits
    if _default_limits is None:
        _default_limits = MessageLimits.from_env()
    return _default_limits


def set_default_limits(limits: MessageLimits) -> None:
    """Replace the process-wide default limits."""
    global _default_limits
    _default_limits = limits
    logger.info("Process-wide OPC UA message limits set: %s", limits)


def attach_limits(target: Any, limits: MessageLimits) -> None:
    """Bind ``limits`` to an InternalServer or SecureConnection."""
    setattr(target, _LIMITS_ATTR, limits)


def limits_for(target: Any) -> MessageLimits:
    limits = getattr(target, _LIMITS_ATTR, None)
    return limits if isinstance(limits, MessageLimits) else default_limits()


def check_header(header: Any, limits: MessageLimits) -> None:
    """Reject a chunk whose declared body size is negative or above the chunk cap."""
    if header.body_size < 0 or header.body_size > limits.max_chunk_size:
        raise MessageLimitError(
            f"Declared chunk body size {header.body_size} outside 0..{limits.max_chunk_size}"
        )


# ---------------------------------------------------------------------------
# Guarded replacements for the upstream receive paths
# ---------------------------------------------------------------------------


def _make_guarded_secure_receive(original: Callable[..., Any]) -> Callable[..., Any]:
    def _receive(self: SecureConnection, msg: Any) -> Any:
        limits = limits_for(self)
        parts = self._incoming_parts
        count = len(parts) + 1
        size = sum(len(part.Body) for part in parts) + len(msg.Body)
        if count > limits.max_chunk_count or size > limits.max_message_size:
            self._incoming_parts = []
            raise MessageLimitError(
                f"Message exceeds limits: {count} chunks / {size} bytes "
                f"(max {limits.max_chunk_count} chunks / {limits.max_message_size} bytes)"
            )
        return original(self, msg)

    return _receive


def _guarded_receive_from_socket(self: SecureConnection, sock: Any) -> Any:
    # Same flow as upstream, but the header is checked before body_size bytes are read.
    header = uabin.header_from_binary(sock)
    check_header(header, limits_for(self))
    body = sock.read(header.body_size)
    if len(body) != header.body_size:
        raise ua.UaError(f"{header.body_size} bytes expected, {len(body)} available")
    return self.receive_from_header_and_body(header, ua_utils.Buffer(body))


def _close_server_transport(protocol: Any) -> None:
    protocol.data = b""
    protocol.transport.close()


def _guarded_process_data(self: Any, data: bytes) -> None:
    # Same flow as upstream, plus the header cap before buffering and a transport close
    # on every error (upstream logs "closing" but leaves the connection open).
    limits = limits_for(self.iserver)
    connection = getattr(self.processor, "_connection", None)
    if connection is not None:
        attach_limits(connection, limits)
    buf = ua_utils.Buffer(data)
    while True:
        try:
            backup_buf = buf.copy()
            try:
                hdr = uabin.header_from_binary(buf)
            except ua_utils.NotEnoughData:
                self.data = backup_buf.read(len(backup_buf))
                return
            check_header(hdr, limits)
            if len(buf) < hdr.body_size:
                self.data = backup_buf.read(len(backup_buf))
                return
            ret = self.processor.process(hdr, buf)
            if not ret:
                logger.info("Processor returned False, closing connection from %s", self.peername)
                self.transport.close()
                return
            if len(buf) == 0:
                return
        except MessageLimitError as exc:
            logger.warning("Closing connection from %s: %s", self.peername, exc)
            _close_server_transport(self)
            return
        except Exception:
            logger.exception("Error while parsing message from %s, closing", self.peername)
            _close_server_transport(self)
            return


def _close_client_socket(wrapper: Any) -> None:
    sock = getattr(wrapper, "socket", None)
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


def _make_guarded_socket_receive(original: Callable[..., Any]) -> Callable[..., Any]:
    def _receive(self: UASocketClient) -> Any:
        try:
            return original(self)
        except MessageLimitError as exc:
            # Upstream's receive loop only logs UaError and keeps reading, so close the
            # socket and end the loop the same way a server-side close would.
            logger.warning("Closing connection to server: %s", exc)
            _close_client_socket(self._socket)
            raise ua_utils.SocketClosedException(str(exc)) from exc

    return _receive


# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

_PATCH_POINTS: list[tuple[type, str]] = [
    (SecureConnection, "_receive"),
    (SecureConnection, "receive_from_socket"),
    (SecureConnection, "receive_from_header_and_body"),
    (OPCUAProtocol, "_process_data"),
    (UASocketClient, "_receive"),
]


def _verify_patch_points() -> None:
    missing = [
        f"{cls.__module__}.{cls.__name__}.{name}"
        for cls, name in _PATCH_POINTS
        if not callable(getattr(cls, name, None))
    ]
    if not hasattr(SecureConnection(ua.SecurityPolicy()), "_incoming_parts"):
        missing.append("opcua.common.connection.SecureConnection._incoming_parts")
    if missing:
        raise ImportError(
            "presidio-hardened-opcua cannot install its CVE-2022-25304 guards: the installed "
            f"'opcua' package lacks {', '.join(missing)}. Install opcua==0.98.13."
        )


def _replacements() -> list[tuple[type, str, Callable[..., Any]]]:
    return [
        (
            SecureConnection,
            "_receive",
            _make_guarded_secure_receive(SecureConnection._receive),
        ),
        (SecureConnection, "receive_from_socket", _guarded_receive_from_socket),
        (OPCUAProtocol, "_process_data", _guarded_process_data),
        (UASocketClient, "_receive", _make_guarded_socket_receive(UASocketClient._receive)),
    ]


def guards_installed() -> bool:
    return all(
        getattr(getattr(cls, name), _GUARD_MARKER, False) for cls, name, _ in _replacements()
    )


def install_guards() -> None:
    """Patch python-opcua's receive paths with bounded versions (idempotent)."""
    _verify_patch_points()
    for cls, name, replacement in _replacements():
        if getattr(getattr(cls, name), _GUARD_MARKER, False):
            continue
        setattr(replacement, _GUARD_MARKER, True)
        setattr(cls, name, replacement)
    logger.info("CVE-2022-25304 guards installed (process-wide): %s", default_limits())
