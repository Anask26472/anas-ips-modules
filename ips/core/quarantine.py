from __future__ import annotations

import json
from datetime import datetime

from ips.utils.config import QUARANTINE_FILE


class QuarantineStore:
    def load(self) -> list[dict]:
        if not QUARANTINE_FILE.exists():
            return []
        try:
            with open(QUARANTINE_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return []

    def save(self, features: dict, result: dict) -> None:
        records = self.load()
        records.append({
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "src_ip": features.get("src_ip"),
            "dst_ip": features.get("dst_ip"),
            "protocol": features.get("protocol"),
            "dst_port": features.get("dst_port"),
            "packet_size": features.get("packet_size"),
            "label": result.get("label"),
            "score": result.get("score"),
            "layer": result.get("layer"),
            "action": result.get("action"),
        })
        with open(QUARANTINE_FILE, "w", encoding="utf-8") as fh:
            json.dump(records[-500:], fh, indent=2)
