"""Tests for the hardened OPC UA Server."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from presidio_opcua.security import PresidioSecurityError, SecurityPolicy
from presidio_opcua.server import HardenedServer


@pytest.fixture()
def _no_dep_check():
    with patch("presidio_opcua.server.check_dependencies", return_value=[]):
        yield


@pytest.mark.usefixtures("_no_dep_check")
class TestHardenedServerPolicies:
    def test_rejects_no_security_policy(self):
        from opcua import ua

        server = HardenedServer()
        with pytest.raises(PresidioSecurityError, match="rejected"):
            server.set_security_policy([ua.SecurityPolicyType.NoSecurity])

    def test_filters_no_security_keeps_secure(self):
        from opcua import ua

        server = HardenedServer()
        with patch("opcua.Server.set_security_policy") as mock_ssp:
            server.set_security_policy(
                [
                    ua.SecurityPolicyType.NoSecurity,
                    ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
                ]
            )
            call_args = mock_ssp.call_args[0][0]
            names = [p.name if hasattr(p, "name") else str(p) for p in call_args]
            assert "NoSecurity" not in names

    def test_allows_no_security_when_permitted(self):
        from opcua import ua

        policy = SecurityPolicy(allow_no_security=True)
        server = HardenedServer(security_policy=policy)
        with patch("opcua.Server.set_security_policy") as mock_ssp:
            server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
            mock_ssp.assert_called_once()


@pytest.mark.usefixtures("_no_dep_check")
class TestHardenedServerLifecycle:
    @patch("opcua.Server.start")
    @patch("opcua.Server.set_security_policy")
    def test_start_auto_applies_secure_policy(self, mock_ssp, mock_start):
        server = HardenedServer()
        server.start()
        mock_ssp.assert_called_once()
        mock_start.assert_called_once()

    @patch("opcua.Server.start")
    def test_start_with_explicit_policy(self, mock_start):
        from opcua import ua

        server = HardenedServer()
        with patch("opcua.Server.set_security_policy"):
            server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
        server.start()
        mock_start.assert_called_once()

    @patch("opcua.Server.stop")
    @patch("opcua.Server.start")
    @patch("opcua.Server.set_security_policy")
    def test_stop(self, _mock_ssp, _mock_start, mock_stop):
        server = HardenedServer()
        server.start()
        server.stop()
        mock_stop.assert_called_once()
