from __future__ import annotations

import json
from typing import Any

from ips.utils.config import INTEL_INDICATORS_FILE


class ThreatIntelDB:
    def __init__(self, path=INTEL_INDICATORS_FILE):
        self.path = path
        self.payload: dict[str, Any] = {'malicious_ips': {}, 'notes': 'local intel file'}
        self.reload()

    def reload(self) -> None:
        if not self.path.exists():
            self.path.write_text(json.dumps(self.payload, indent=2), encoding='utf-8')
            return
        try:
            self.payload = json.loads(self.path.read_text(encoding='utf-8'))
        except Exception:
            self.payload = {'malicious_ips': {}, 'notes': 'fallback after invalid file'}

    def summary(self) -> dict:
        bad = self.payload.get('malicious_ips', {})
        return {
            'indicator_count': len(bad),
            'source': str(self.path),
        }

    def match_ip(self, ip: str | None) -> dict | None:
        if not ip:
            return None
        bad = self.payload.get('malicious_ips', {})
        if ip not in bad:
            return None
        item = bad.get(ip)
        if isinstance(item, str):
            item = {'reason': item, 'severity': 'high'}
        return {'ip': ip, **item}
