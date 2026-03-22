"""Tests for certificate validation and security policy enforcement."""

from __future__ import annotations

import pytest

from presidio_opcua.security import (
    PresidioSecurityError,
    SecurityPolicy,
    enforce_security_mode,
    validate_certificate,
)


# ---------------------------------------------------------------------------
# SecurityPolicy dataclass
# ---------------------------------------------------------------------------
class TestSecurityPolicy:
    def test_defaults(self):
        pol = SecurityPolicy()
        assert pol.allow_self_signed is False
        assert pol.allow_no_security is False
        assert pol.session_timeout_ms == 30_000

    def test_is_mode_allowed_rejects_none(self):
        pol = SecurityPolicy()
        assert pol.is_mode_allowed("None") is False
        assert pol.is_mode_allowed("None_") is False

    def test_is_mode_allowed_accepts_none_when_permitted(self):
        pol = SecurityPolicy(allow_no_security=True)
        assert pol.is_mode_allowed("None") is True

    def test_is_mode_allowed_accepts_sign(self):
        pol = SecurityPolicy()
        assert pol.is_mode_allowed("Sign") is True
        assert pol.is_mode_allowed("SignAndEncrypt") is True


# ---------------------------------------------------------------------------
# enforce_security_mode
# ---------------------------------------------------------------------------
class TestEnforceSecurityMode:
    def test_rejects_none(self):
        with pytest.raises(PresidioSecurityError, match="rejected"):
            enforce_security_mode("None_")

    def test_rejects_none_variant(self):
        with pytest.raises(PresidioSecurityError, match="rejected"):
            enforce_security_mode("None")

    def test_allows_none_when_flag_set(self):
        enforce_security_mode("None_", allow_none=True)

    def test_allows_sign_and_encrypt(self):
        enforce_security_mode("SignAndEncrypt")


# ---------------------------------------------------------------------------
# validate_certificate
# ---------------------------------------------------------------------------
class TestValidateCertificate:
    def test_self_signed_rejected_by_default(self, self_signed_cert):
        cert_path, _ = self_signed_cert
        with pytest.raises(ValueError, match="Self-signed certificate rejected"):
            validate_certificate(cert_path)

    def test_self_signed_allowed_when_flag_set(self, self_signed_cert):
        cert_path, _ = self_signed_cert
        info = validate_certificate(cert_path, allow_self_signed=True)
        assert info["self_signed"] is True
        assert "presidio-test" in info["subject"]

    def test_expired_cert_rejected(self, expired_cert):
        with pytest.raises(ValueError, match="expired"):
            validate_certificate(expired_cert, allow_self_signed=True)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            validate_certificate(tmp_path / "nonexistent.der")

    def test_invalid_cert_data_raises(self, tmp_path):
        bad = tmp_path / "bad.der"
        bad.write_bytes(b"not a certificate")
        with pytest.raises(ValueError, match="Cannot parse"):
            validate_certificate(bad)
