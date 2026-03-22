"""Tests for input sanitization (node IDs, browse paths, variant values)."""

from __future__ import annotations

import pytest

from presidio_opcua.sanitization import (
    MAX_BROWSE_PATH_LENGTH,
    MAX_NODE_ID_LENGTH,
    MAX_VARIANT_STRING_LENGTH,
    sanitize_browse_path,
    sanitize_node_id,
    sanitize_variant,
)


# ---------------------------------------------------------------------------
# sanitize_node_id
# ---------------------------------------------------------------------------
class TestSanitizeNodeId:
    @pytest.mark.parametrize(
        "node_id",
        [
            "i=1234",
            "ns=2;i=999",
            "ns=0;i=0",
            "s=MyVariable",
            "ns=2;s=Some.Path/Name",
            "ns=1;g=12345678-1234-1234-1234-123456789abc",
            "ns=3;b=SGVsbG8=",
        ],
    )
    def test_valid_node_ids_pass(self, node_id: str):
        assert sanitize_node_id(node_id) == node_id

    def test_integer_node_id_passes(self):
        assert sanitize_node_id(42) == 42

    def test_non_string_non_int_passes_through(self):
        obj = object()
        assert sanitize_node_id(obj) is obj

    def test_rejects_sql_injection(self):
        with pytest.raises(ValueError, match="Suspicious pattern"):
            sanitize_node_id("ns=2;s='; DROP TABLE nodes;--")

    def test_rejects_path_traversal(self):
        with pytest.raises(ValueError, match="Path traversal"):
            sanitize_node_id("ns=2;s=../../etc/passwd")

    def test_rejects_dangerous_chars(self):
        with pytest.raises(ValueError, match="Illegal characters"):
            sanitize_node_id("x=test$(whoami)")

    def test_rejects_oversized_node_id(self):
        with pytest.raises(ValueError, match="maximum length"):
            sanitize_node_id("i=" + "9" * MAX_NODE_ID_LENGTH)

    def test_strips_whitespace(self):
        assert sanitize_node_id("  i=123  ") == "i=123"


# ---------------------------------------------------------------------------
# sanitize_browse_path
# ---------------------------------------------------------------------------
class TestSanitizeBrowsePath:
    def test_valid_path(self):
        assert sanitize_browse_path("Objects/MyFolder/MyVar") == "Objects/MyFolder/MyVar"

    def test_rejects_traversal(self):
        with pytest.raises(ValueError, match="Path traversal"):
            sanitize_browse_path("Objects/../../secret")

    def test_rejects_injection(self):
        with pytest.raises(ValueError, match="Suspicious pattern"):
            sanitize_browse_path("Objects'; DROP TABLE--")

    def test_rejects_dangerous_chars(self):
        with pytest.raises(ValueError, match="Illegal characters"):
            sanitize_browse_path("Objects/$(cmd)")

    def test_rejects_oversized(self):
        with pytest.raises(ValueError, match="maximum length"):
            sanitize_browse_path("A" * (MAX_BROWSE_PATH_LENGTH + 1))

    def test_rejects_non_string(self):
        with pytest.raises(TypeError, match="must be a string"):
            sanitize_browse_path(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# sanitize_variant
# ---------------------------------------------------------------------------
class TestSanitizeVariant:
    def test_clean_string(self):
        assert sanitize_variant("hello world") == "hello world"

    def test_numeric_passthrough(self):
        assert sanitize_variant(42) == 42
        assert sanitize_variant(3.14) == 3.14

    def test_rejects_injection_in_string(self):
        with pytest.raises(ValueError, match="Suspicious pattern"):
            sanitize_variant("'; DROP TABLE nodes;--")

    def test_rejects_oversized_string(self):
        with pytest.raises(ValueError, match="maximum length"):
            sanitize_variant("x" * (MAX_VARIANT_STRING_LENGTH + 1))

    def test_rejects_oversized_bytes(self):
        with pytest.raises(ValueError, match="maximum length"):
            sanitize_variant(b"\x00" * (MAX_VARIANT_STRING_LENGTH + 1))

    def test_list_recursion(self):
        result = sanitize_variant(["a", "b", "c"])
        assert result == ["a", "b", "c"]

    def test_list_with_bad_element(self):
        with pytest.raises(ValueError, match="Suspicious pattern"):
            sanitize_variant(["ok", "'; DROP TABLE--"])

    def test_tuple_preserved(self):
        result = sanitize_variant(("a", "b"))
        assert isinstance(result, tuple)
        assert result == ("a", "b")
