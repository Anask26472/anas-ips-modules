from __future__ import annotations

import json
import time
from collections import deque

from ips.utils.config import PERFORMANCE_FILE


class PerformanceTracker:
    def __init__(self):
        self.started = time.time()
        self.response_times = deque(maxlen=1000)
        self.recent_threats = deque(maxlen=50)
        self.total = 0
        self.threats = 0
        self.blocked = 0

    def record(self, result: dict, response_ms: float) -> None:
        self.total += 1
        self.response_times.append(response_ms)
        if result.get("label") != "normal":
            self.threats += 1
            self.recent_threats.append({
                "label": result.get("label"),
                "action": result.get("action"),
                "layer": result.get("layer"),
                "score": result.get("score"),
            })
        if result.get("action") == "block":
            self.blocked += 1

    def get_report(self) -> dict:
        avg_response = round(sum(self.response_times) / max(len(self.response_times), 1), 3)
        return {
            "uptime_minutes": round((time.time() - self.started) / 60, 2),
            "total_packets": self.total,
            "threats_detected": self.threats,
            "blocked": self.blocked,
            "avg_response_ms": avg_response,
            "recent_threats": list(self.recent_threats),
        }

    def save(self) -> None:
        with open(PERFORMANCE_FILE, "w", encoding="utf-8") as fh:
            json.dump(self.get_report(), fh, indent=2)
