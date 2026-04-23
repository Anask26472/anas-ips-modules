from __future__ import annotations

import json
import time
from typing import Any

from ips.utils.config import AUDIT_LOG_FILE


class AuditTrail:
    def __init__(self, path=AUDIT_LOG_FILE):
        self.path = path

    def record(self, actor: str, action: str, target: str = '', status: str = 'ok', details: dict[str, Any] | None = None) -> None:
        payload = {
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'actor': actor,
            'action': action,
            'target': target,
            'status': status,
            'details': details or {},
        }
        with open(self.path, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + '\n')

    def recent(self, limit: int = 100) -> list[dict]:
        if not self.path.exists():
            return []
        rows = []
        with open(self.path, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows[-limit:]
