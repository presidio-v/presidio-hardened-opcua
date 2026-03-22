"""Tests for anomaly detection / logging."""

from __future__ import annotations

from presidio_opcua.anomaly import AnomalyDetector


class TestAnomalyDetector:
    def test_records_access(self):
        det = AnomalyDetector()
        det.record_access("ns=2;i=1")
        assert det.stats["total_accesses"] == 1
        assert det.stats["unique_nodes"] == 1

    def test_high_rate_alert(self):
        det = AnomalyDetector(access_threshold=5)
        for i in range(10):
            det.record_access(f"ns=2;i={i}")
        alerts = det.get_alerts()
        rate_alerts = [a for a in alerts if a["type"] == "high_rate"]
        assert len(rate_alerts) > 0

    def test_scan_alert(self):
        det = AnomalyDetector(unique_node_threshold=3)
        for i in range(5):
            det.record_access(f"ns=2;i={i}")
        alerts = det.get_alerts()
        scan_alerts = [a for a in alerts if a["type"] == "node_scan"]
        assert len(scan_alerts) > 0

    def test_no_false_positive_under_threshold(self):
        det = AnomalyDetector(access_threshold=100, unique_node_threshold=50)
        for i in range(3):
            det.record_access(f"ns=2;i={i}")
        assert det.get_alerts() == []

    def test_clear_resets_state(self):
        det = AnomalyDetector(access_threshold=2)
        for i in range(5):
            det.record_access(f"ns=2;i={i}")
        assert det.stats["total_accesses"] > 0
        det.clear()
        assert det.stats["total_accesses"] == 0
        assert det.stats["unique_nodes"] == 0
        assert det.stats["alerts_count"] == 0

    def test_stats_reflects_counts(self):
        det = AnomalyDetector()
        det.record_access("ns=2;i=1")
        det.record_access("ns=2;i=1")
        det.record_access("ns=2;i=2")
        stats = det.stats
        assert stats["total_accesses"] == 3
        assert stats["unique_nodes"] == 2
