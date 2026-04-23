from __future__ import annotations

import json
import time
from collections import Counter

from ips.utils.config import BASELINE_FILE, BASELINE_LEARNING_SECONDS
from ips.utils.logger import get_logger

log = get_logger(__name__)


class BaselineProfile:
    def __init__(self):
        self.start_time = time.time()
        self.packet_sizes: list[int] = []
        self.protocols = Counter()
        self.services = Counter()
        self.samples = 0
        self.learning = True
        self._load_if_exists()

    def observe(self, features: dict) -> None:
        if not self.learning:
            return
        self.samples += 1
        self.packet_sizes.append(int(features.get("packet_size", 0)))
        self.protocols.update([features.get("protocol", "other")])
        self.services.update([features.get("service", "other")])
        if time.time() - self.start_time >= BASELINE_LEARNING_SECONDS:
            self.learning = False
            self._save()
            log.info("baseline summary saved")

    def summary(self) -> dict:
        if self.samples == 0:
            return {"learning": self.learning, "samples": 0}
        avg_packet_size = round(sum(self.packet_sizes) / max(len(self.packet_sizes), 1), 2)
        return {
            "learning": self.learning,
            "samples": self.samples,
            "avg_packet_size": avg_packet_size,
            "top_protocols": self.protocols.most_common(3),
            "top_services": self.services.most_common(3),
        }

    def _save(self) -> None:
        with open(BASELINE_FILE, "w", encoding="utf-8") as fh:
            json.dump(self.summary(), fh, indent=2)

    def _load_if_exists(self) -> None:
        if not BASELINE_FILE.exists():
            return
        try:
            with open(BASELINE_FILE, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            self.learning = False
            self.samples = int(payload.get("samples", 0))
        except Exception:
            pass
