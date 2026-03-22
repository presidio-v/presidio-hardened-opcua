"""Tests for the hardened OPC UA Client."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from presidio_opcua.client import HardenedClient
from presidio_opcua.security import PresidioSecurityError, SecurityPolicy


@pytest.fixture()
def _no_dep_check():
    """Suppress dependency checking during unit tests."""
    with patch("presidio_opcua.client.check_dependencies", return_value=[]):
        yield


@pytest.mark.usefixtures("_no_dep_check")
class TestHardenedClientConnect:
    def test_connect_without_security_raises(self):
        client = HardenedClient("opc.tcp://localhost:4840")
        with pytest.raises(PresidioSecurityError, match="Cannot connect"):
            client.connect()

    @patch("opcua.Client.connect")
    def test_connect_with_no_security_allowed(self, mock_connect):
        policy = SecurityPolicy(allow_no_security=True)
        client = HardenedClient("opc.tcp://localhost:4840", security_policy=policy)
        client.connect()
        mock_connect.assert_called_once()

    @patch("opcua.Client.connect")
    def test_session_timeout_set_on_connect(self, mock_connect):
        policy = SecurityPolicy(allow_no_security=True, session_timeout_ms=15_000)
        client = HardenedClient("opc.tcp://localhost:4840", security_policy=policy)
        client.connect()
        assert client.session_timeout == 15_000


@pytest.mark.usefixtures("_no_dep_check")
class TestHardenedClientSecurity:
    def test_rejects_none_security_mode(self):
        from opcua import ua

        client = HardenedClient("opc.tcp://localhost:4840")
        with pytest.raises(PresidioSecurityError, match="rejected"):
            client.set_security(
                "Basic256Sha256",
                "cert.der",
                "key.pem",
                mode=ua.MessageSecurityMode.None_,
            )

    def test_rejects_none_in_security_string(self):
        client = HardenedClient("opc.tcp://localhost:4840")
        with pytest.raises(PresidioSecurityError, match="rejected"):
            client.set_security_string("Basic256Sha256,None,cert.der,key.pem")

    @patch("opcua.Client.set_security_string")
    def test_accepts_sign_and_encrypt_string(self, mock_sss):
        policy = SecurityPolicy(allow_no_security=False)
        client = HardenedClient("opc.tcp://localhost:4840", security_policy=policy)
        client.set_security_string("Basic256Sha256,SignAndEncrypt,cert.der,key.pem")
        assert client._security_configured is True
        mock_sss.assert_called_once()


@pytest.mark.usefixtures("_no_dep_check")
class TestHardenedClientSanitization:
    def test_get_node_sanitises_input(self):
        policy = SecurityPolicy(allow_no_security=True)
        client = HardenedClient("opc.tcp://localhost:4840", security_policy=policy)
        with patch("opcua.Client.get_node") as mock_gn:
            client.get_node("ns=2;i=42")
            mock_gn.assert_called_once_with("ns=2;i=42")

    def test_get_node_rejects_injection(self):
        policy = SecurityPolicy(allow_no_security=True)
        client = HardenedClient("opc.tcp://localhost:4840", security_policy=policy)
        with pytest.raises(ValueError, match="Suspicious pattern"):
            client.get_node("ns=2;s='; DROP TABLE--")


@pytest.mark.usefixtures("_no_dep_check")
class TestHardenedClientAnomaly:
    def test_anomaly_detector_tracks_access(self):
        policy = SecurityPolicy(allow_no_security=True)
        client = HardenedClient("opc.tcp://localhost:4840", security_policy=policy)
        with patch("opcua.Client.get_node"):
            for i in range(5):
                client.get_node(f"ns=2;i={i}")
        assert client.anomaly_detector.stats["total_accesses"] == 5
        assert client.anomaly_detector.stats["unique_nodes"] == 5
