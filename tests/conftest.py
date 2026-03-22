"""Shared fixtures and opcua mock setup for the test suite."""

from __future__ import annotations

import datetime
import sys
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Mock the opcua package if it is not installed.  This allows the full test
# suite to run without a real python-opcua installation – we only test our
# own hardening logic, not the upstream library.
# ---------------------------------------------------------------------------

try:
    import opcua  # noqa: F401
except ImportError:

    class _MockMessageSecurityMode:
        None_ = type("_Mode", (), {"name": "None_"})()
        Sign = type("_Mode", (), {"name": "Sign"})()
        SignAndEncrypt = type("_Mode", (), {"name": "SignAndEncrypt"})()

    class _MockSecurityPolicyType:
        NoSecurity = type("_SPT", (), {"name": "NoSecurity"})()
        Basic256Sha256_SignAndEncrypt = type(
            "_SPT", (), {"name": "Basic256Sha256_SignAndEncrypt"}
        )()
        Basic256Sha256_Sign = type("_SPT", (), {"name": "Basic256Sha256_Sign"})()

    class _MockUA:
        MessageSecurityMode = _MockMessageSecurityMode
        SecurityPolicyType = _MockSecurityPolicyType
        NodeId = MagicMock

    class _MockClient:
        def __init__(self, url: str, timeout: int = 4) -> None:
            self.server_url = url
            self.session_timeout = 0
            self.secure_channel_timeout = 0

        def connect(self) -> None: ...
        def disconnect(self) -> None: ...
        def set_security(self, *a, **kw) -> None: ...  # noqa: ARG002
        def set_security_string(self, s: str) -> None: ...  # noqa: ARG002
        def get_node(self, nodeid):  # noqa: ARG002
            return MagicMock()

        def get_root_node(self):
            return MagicMock()

        def get_objects_node(self):
            return MagicMock()

    class _MockServer:
        def __init__(self) -> None: ...
        def start(self) -> None: ...
        def stop(self) -> None: ...
        def set_security_policy(self, policies, permission_ruleset=None) -> None: ...  # noqa: ARG002
        def set_endpoint(self, url: str) -> None: ...  # noqa: ARG002
        def load_certificate(self, path: str) -> None: ...  # noqa: ARG002
        def load_private_key(self, path: str) -> None: ...  # noqa: ARG002
        def register_namespace(self, uri: str) -> None: ...  # noqa: ARG002
        def get_objects_node(self):
            return MagicMock()

    class _MockNode:
        pass

    _ua = _MockUA()
    _common_node = type(sys)("opcua.common.node")
    _common_node.Node = _MockNode
    _common = type(sys)("opcua.common")
    _common.node = _common_node

    _opcua = type(sys)("opcua")
    _opcua.Client = _MockClient
    _opcua.Server = _MockServer
    _opcua.ua = _ua
    _opcua.common = _common

    sys.modules["opcua"] = _opcua
    sys.modules["opcua.ua"] = _ua  # type: ignore[assignment]
    sys.modules["opcua.common"] = _common
    sys.modules["opcua.common.node"] = _common_node


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
import pytest  # noqa: E402


@pytest.fixture()
def self_signed_cert(tmp_path):
    """Generate a self-signed DER certificate and private key for testing."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "presidio-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = tmp_path / "test_cert.der"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))

    key_path = tmp_path / "test_key.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    return cert_path, key_path


@pytest.fixture()
def expired_cert(tmp_path):
    """Generate an expired self-signed certificate for testing."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=730)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365)
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = tmp_path / "expired_cert.der"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return cert_path
