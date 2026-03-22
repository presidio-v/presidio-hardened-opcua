"""Message-level anomaly detection for OPC UA sessions."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("presidio_opcua.anomaly")

DEFAULT_WINDOW_SEC = 60
DEFAULT_ACCESS_THRESHOLD = 100
DEFAULT_UNIQUE_NODE_THRESHOLD = 50


@dataclass
class AnomalyDetector:
    """Detects anomalous OPC UA access patterns and logs warnings."""

    window_sec: float = DEFAULT_WINDOW_SEC
    access_threshold: int = DEFAULT_ACCESS_THRESHOLD
    unique_node_threshold: int = DEFAULT_UNIQUE_NODE_THRESHOLD
    _access_times: list[float] = field(default_factory=list, repr=False)
    _node_access_counts: dict[str, int] = field(
        default_factory=lambda: defaultdict(int), repr=False
    )
    _alerts: list[dict] = field(default_factory=list, repr=False)

    def record_access(self, node_id: object) -> None:
        """Record a node access event and check for anomalies."""
        now = time.monotonic()
        self._access_times.append(now)
        self._node_access_counts[str(node_id)] += 1
        self._prune_window(now)
        self._check_rate_anomaly(now)
        self._check_scan_anomaly()

    def _prune_window(self, now: float) -> None:
        cutoff = now - self.window_sec
        self._access_times = [t for t in self._access_times if t > cutoff]

    def _check_rate_anomaly(self, now: float) -> None:
        if len(self._access_times) > self.access_threshold:
            msg = (
                f"High access rate detected: {len(self._access_times)} accesses "
                f"in {self.window_sec}s window (threshold: {self.access_threshold})"
            )
            logger.warning(msg)
            self._alerts.append({"type": "high_rate", "message": msg, "time": now})

    def _check_scan_anomaly(self) -> None:
        unique = len(self._node_access_counts)
        if unique > self.unique_node_threshold:
            msg = (
                f"Possible node scanning detected: {unique} unique nodes accessed "
                f"(threshold: {self.unique_node_threshold})"
            )
            logger.warning(msg)
            self._alerts.append({"type": "node_scan", "message": msg, "time": time.monotonic()})

    def get_alerts(self) -> list[dict]:
        """Return all recorded anomaly alerts."""
        return list(self._alerts)

    def clear(self) -> None:
        """Reset all tracking state."""
        self._access_times.clear()
        self._node_access_counts.clear()
        self._alerts.clear()

    @property
    def stats(self) -> dict:
        """Return current access statistics."""
        return {
            "total_accesses": sum(self._node_access_counts.values()),
            "unique_nodes": len(self._node_access_counts),
            "alerts_count": len(self._alerts),
        }
