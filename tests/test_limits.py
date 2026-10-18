"""Tests for the CVE-2022-25304 chunk and message limits."""

from __future__ import annotations

import logging
import struct
from unittest.mock import MagicMock, patch

import pytest
from opcua import ua
from opcua.client.ua_client import UASocketClient
from opcua.common.connection import MessageChunk, SecureConnection
from opcua.common.utils import Buffer, SocketClosedException, SocketWrapper
from opcua.server.binary_server_asyncio import OPCUAProtocol

import presidio_opcua
from presidio_opcua import limits
from presidio_opcua.limits import (
    DEFAULT_MAX_CHUNK_COUNT,
    DEFAULT_MAX_CHUNK_SIZE,
    DEFAULT_MAX_MESSAGE_SIZE,
    MessageLimitError,
    MessageLimits,
    attach_limits,
)

FORGED_BODY_SIZE = 2**31


def _forged_header(body_size: int = FORGED_BODY_SIZE) -> bytes:
    # MSG header: type, chunk type, packet size (body + 8 byte header + 4 byte channel id).
    return b"MSGF" + struct.pack("<I", body_size + 12) + struct.pack("<I", 0)


def _chunks(count: int, chunk_type: bytes = ua.ChunkType.Intermediate) -> bytes:
    crypto = ua.SecurityPolicy().symmetric_cryptography
    out = []
    for seq in range(1, count + 1):
        chunk = MessageChunk(crypto, b"x", ua.MessageType.SecureMessage, chunk_type)
        chunk.SequenceHeader.SequenceNumber = seq
        chunk.SequenceHeader.RequestId = 1
        out.append(chunk.to_binary())
    return b"".join(out)


def _three_chunk_message(body: bytes) -> bytes:
    sender = SecureConnection(ua.SecurityPolicy())
    sender._max_chunk_size = 8192
    return sender.message_to_binary(body, request_id=7)


def _server_protocol(server_limits: MessageLimits | None = None) -> OPCUAProtocol:
    iserver = MagicMock()
    if server_limits is not None:
        attach_limits(iserver, server_limits)
    protocol_cls = type(
        "OPCUAProtocol",
        (OPCUAProtocol,),
        {
            "iserver": iserver,
            "loop": None,
            "logger": logging.getLogger("test"),
            "policies": [],
            "clients": [],
        },
    )
    protocol = protocol_cls()
    transport = MagicMock()
    transport.get_extra_info.return_value = ("127.0.0.1", 50000)
    protocol.connection_made(transport)
    return protocol


class _FakeSocket:
    """Socket stand-in that serves fixed bytes and records every recv size."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self.recv_sizes: list[int] = []
        self.closed = False

    def recv(self, size: int) -> bytes:
        self.recv_sizes.append(size)
        chunk, self._data = self._data[:size], self._data[size:]
        return chunk

    def shutdown(self, how: int) -> None:  # noqa: ARG002
        pass

    def close(self) -> None:
        self.closed = True


class TestMessageLimits:
    def test_defaults(self):
        lim = MessageLimits()
        assert lim.max_chunk_size == DEFAULT_MAX_CHUNK_SIZE == 64 * 1024 * 1024
        assert lim.max_chunk_count == DEFAULT_MAX_CHUNK_COUNT == 1601
        assert lim.max_message_size == DEFAULT_MAX_MESSAGE_SIZE == 100 * 1024 * 1024

    def test_env_overrides_defaults(self, monkeypatch):
        monkeypatch.setenv("PRESIDIO_OPCUA_MAX_CHUNK_COUNT", "10")
        monkeypatch.setenv("PRESIDIO_OPCUA_MAX_MESSAGE_SIZE", "65536")
        lim = MessageLimits.from_env()
        assert lim.max_chunk_count == 10
        assert lim.max_message_size == 65536
        assert lim.max_chunk_size == DEFAULT_MAX_CHUNK_SIZE

    def test_explicit_argument_wins_over_env(self, monkeypatch):
        monkeypatch.setenv("PRESIDIO_OPCUA_MAX_CHUNK_SIZE", "100000")
        assert MessageLimits.from_env(max_chunk_size=9000).max_chunk_size == 9000

    def test_invalid_env_raises(self, monkeypatch):
        monkeypatch.setenv("PRESIDIO_OPCUA_MAX_CHUNK_COUNT", "lots")
        with pytest.raises(ValueError, match="PRESIDIO_OPCUA_MAX_CHUNK_COUNT"):
            MessageLimits.from_env()

    @pytest.mark.parametrize(
        "kwargs",
        [{"max_chunk_count": 0}, {"max_message_size": -1}, {"max_chunk_size": 1024}],
    )
    def test_invalid_values_rejected(self, kwargs):
        with pytest.raises(ValueError):
            MessageLimits(**kwargs)


class TestGuardInstallation:
    def test_installed_on_import(self):
        assert presidio_opcua.MessageLimits is MessageLimits
        assert limits.guards_installed()

    def test_install_is_idempotent(self):
        before = (SecureConnection._receive, OPCUAProtocol._process_data)
        limits.install_guards()
        assert (SecureConnection._receive, OPCUAProtocol._process_data) == before

    def test_missing_patch_point_raises(self, monkeypatch):
        monkeypatch.delattr(OPCUAProtocol, "_process_data")
        with pytest.raises(ImportError, match="opcua==0.98.13"):
            limits.install_guards()


class TestSecureConnectionChunkLimits:
    def test_rejects_too_many_chunks(self):
        conn = SecureConnection(ua.SecurityPolicy())
        buf = Buffer(_chunks(2000))
        with pytest.raises(MessageLimitError, match="1602 chunks"):
            for _ in range(2000):
                assert conn.receive_from_socket(buf) is None
        assert conn._incoming_parts == []

    def test_rejects_oversized_message(self):
        conn = SecureConnection(ua.SecurityPolicy())
        attach_limits(conn, MessageLimits(max_message_size=10_000))
        data = _three_chunk_message(b"a" * 20_000)
        buf = Buffer(data)
        with pytest.raises(MessageLimitError, match="bytes"):
            for _ in range(3):
                conn.receive_from_socket(buf)
        assert conn._incoming_parts == []

    def test_legitimate_three_chunk_message_assembles(self):
        body = bytes(range(256)) * 80
        data = _three_chunk_message(body)
        conn = SecureConnection(ua.SecurityPolicy())
        buf = Buffer(data)
        results = [conn.receive_from_socket(buf) for _ in range(3)]
        assert results[0] is None and results[1] is None
        assert isinstance(results[2], ua.Message)
        assert results[2].request_id() == 7
        assert results[2].body().read(len(body)) == body
        assert len(buf) == 0


class TestServerReceivePath:
    def test_forged_body_size_closes_transport(self):
        protocol = _server_protocol()
        with patch.object(protocol.processor, "process") as mock_process:
            protocol.data_received(_forged_header())
        mock_process.assert_not_called()
        protocol.transport.close.assert_called_once()
        assert protocol.data == b""

    def test_forged_body_size_rejected_against_instance_limit(self):
        protocol = _server_protocol(MessageLimits(max_chunk_size=8192))
        protocol.data_received(_forged_header(8193))
        protocol.transport.close.assert_called_once()

    def test_too_many_chunks_closes_transport(self):
        protocol = _server_protocol()
        protocol.data_received(_chunks(2000))
        protocol.transport.close.assert_called_once()
        assert protocol.processor._connection._incoming_parts == []

    def test_processing_error_closes_transport(self):
        protocol = _server_protocol()
        with patch.object(protocol.processor, "process", side_effect=RuntimeError("boom")):
            protocol.data_received(_chunks(1))
        protocol.transport.close.assert_called_once()

    def test_partial_chunk_is_buffered(self):
        protocol = _server_protocol()
        data = _chunks(1)
        protocol.data_received(data[:10])
        protocol.transport.close.assert_not_called()
        assert protocol.data == data[:10]

    def test_legitimate_three_chunk_message_reaches_processor(self):
        protocol = _server_protocol()
        with patch.object(protocol.processor, "process_message", return_value=True) as pm:
            protocol.data_received(_three_chunk_message(b"z" * 20_000))
        pm.assert_called_once()
        protocol.transport.close.assert_not_called()


class TestClientReceivePath:
    def _client(self, data: bytes) -> tuple[UASocketClient, _FakeSocket]:
        sock = _FakeSocket(data)
        client = UASocketClient()
        client._socket = SocketWrapper(sock)
        return client, sock

    def test_forged_body_size_closes_socket_without_reading_body(self):
        client, sock = self._client(_forged_header())
        with pytest.raises(SocketClosedException):
            client._receive()
        assert sock.closed
        assert max(sock.recv_sizes) < FORGED_BODY_SIZE

    def test_receive_loop_terminates_on_forged_header(self):
        client, sock = self._client(_forged_header())
        client._run()
        assert sock.closed
        assert not client._connection.is_open()

    def test_too_many_chunks_closes_socket(self):
        client, sock = self._client(_chunks(2000))
        with pytest.raises(SocketClosedException):
            for _ in range(2000):
                client._receive()
        assert sock.closed
        assert client._connection._incoming_parts == []

    def test_legitimate_three_chunk_message_resolves_future(self):
        body = b"q" * 20_000
        client, sock = self._client(_three_chunk_message(body))
        future = MagicMock()
        client._callbackmap[7] = future
        for _ in range(3):
            client._receive()
        future.set_result.assert_called_once()
        assert future.set_result.call_args[0][0].read(len(body)) == body
        assert not sock.closed
