from __future__ import annotations

import json
from typing import Any

from ips.utils.config import ENABLE_EVE_EXPORT, EVENT_LOG_FILE, SIEM_PROFILE


class AlertSink:
    def __init__(self, path=EVENT_LOG_FILE):
        self.path = path

    def publish(self, event: dict[str, Any]) -> None:
        if not ENABLE_EVE_EXPORT:
            return
        payload = self._normalize(event)
        with open(self.path, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _normalize(self, event: dict[str, Any]) -> dict[str, Any]:
        if SIEM_PROFILE == 'eve-json':
            return {
                'event_type': 'alert',
                'src_ip': event.get('src_ip'),
                'dest_ip': event.get('dst_ip'),
                'alert': {
                    'signature': event.get('label'),
                    'severity': event.get('action'),
                    'category': event.get('layer'),
                    'signature_id': 1,
                },
                'metadata': {
                    'score': event.get('score'),
                    'reason': event.get('reason', ''),
                },
                'timestamp': event.get('time'),
            }
        return event
