"""Tests for the public package API surface."""

from __future__ import annotations


def test_version():
    from presidio_opcua import __version__

    assert __version__ == "0.1.0"


def test_public_exports():
    import presidio_opcua

    assert hasattr(presidio_opcua, "Client")
    assert hasattr(presidio_opcua, "Server")
    assert hasattr(presidio_opcua, "ua")
    assert hasattr(presidio_opcua, "SecurityPolicy")
    assert hasattr(presidio_opcua, "AnomalyDetector")
    assert hasattr(presidio_opcua, "sanitize_node_id")
    assert hasattr(presidio_opcua, "check_dependencies")


def test_client_is_hardened():
    from presidio_opcua import Client
    from presidio_opcua.client import HardenedClient

    assert Client is HardenedClient


def test_server_is_hardened():
    from presidio_opcua import Server
    from presidio_opcua.server import HardenedServer

    assert Server is HardenedServer
