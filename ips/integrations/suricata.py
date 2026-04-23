from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable


def parse_eve_line(line: str) -> dict | None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if data.get('event_type') != 'alert':
        return None
    alert = data.get('alert', {})
    return {
        'time': data.get('timestamp'),
        'src_ip': data.get('src_ip', '-'),
        'dst_ip': data.get('dest_ip', '-'),
        'label': alert.get('signature', 'suricata-alert'),
        'score': 1.0,
        'layer': 'Suricata-EVE',
        'action': alert.get('severity', 'alert'),
        'reason': alert.get('category', ''),
    }


def load_eve_alerts(path: str | Path, limit: int = 100) -> list[dict]:
    eve_path = Path(path)
    if not eve_path.exists():
        return []
    alerts: list[dict] = []
    with eve_path.open('r', encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            item = parse_eve_line(line)
            if item is not None:
                alerts.append(item)
    return alerts[-limit:]
