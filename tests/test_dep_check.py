"""Tests for the dependency / CVE quick-check module."""

from __future__ import annotations

from unittest.mock import patch

from presidio_opcua.dep_check import _parse_version, _version_lte, check_dependencies


class TestVersionParsing:
    def test_simple_version(self):
        assert _parse_version("1.2.3") == (1, 2, 3)

    def test_two_part(self):
        assert _parse_version("41.0") == (41, 0)

    def test_pre_release_suffix_ignored(self):
        assert _parse_version("1.2.3rc1") == (1, 2, 3)

    def test_version_lte(self):
        assert _version_lte("0.98.12", "0.98.12")
        assert _version_lte("0.98.11", "0.98.12")
        assert not _version_lte("0.98.13", "0.98.12")

    def test_version_lte_different_lengths(self):
        assert _version_lte("1.0", "1.0.1")
        assert not _version_lte("1.1", "1.0.1")


class TestCheckDependencies:
    @patch("presidio_opcua.dep_check.importlib.metadata.version")
    def test_clean_report(self, mock_version):
        mock_version.side_effect = lambda pkg: {
            "opcua": "0.98.13",
            "cryptography": "42.0.0",
        }[pkg]
        issues = check_dependencies()
        assert issues == []

    @patch("presidio_opcua.dep_check.importlib.metadata.version")
    def test_vulnerable_opcua(self, mock_version):
        mock_version.side_effect = lambda pkg: {
            "opcua": "0.98.11",
            "cryptography": "42.0.0",
        }[pkg]
        issues = check_dependencies()
        assert any("opcua" in i for i in issues)

    @patch("presidio_opcua.dep_check.importlib.metadata.version")
    def test_vulnerable_cryptography(self, mock_version):
        mock_version.side_effect = lambda pkg: {
            "opcua": "0.98.13",
            "cryptography": "41.0.4",
        }[pkg]
        issues = check_dependencies()
        assert any("cryptography" in i for i in issues)

    @patch(
        "presidio_opcua.dep_check.importlib.metadata.version",
        side_effect=__import__("importlib").metadata.PackageNotFoundError,
    )
    def test_missing_package(self, _mock):
        issues = check_dependencies()
        assert any("not installed" in i for i in issues)
