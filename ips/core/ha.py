from __future__ import annotations

import json
import time

from ips.utils.config import DEFAULT_FAIL_MODE, HA_CONFIG_FILE


class HAController:
    def __init__(self, path=HA_CONFIG_FILE):
        self.path = path
        self.state = {}
        self.reload()

    def _default(self) -> dict:
        return {
            'cluster_name': 'ips-lab',
            'node_name': 'node-1',
            'mode': DEFAULT_FAIL_MODE,
            'peers': [],
            'heartbeats': {},
        }

    def reload(self) -> None:
        default = self._default()
        if not self.path.exists():
            self.path.write_text(json.dumps(default, indent=2), encoding='utf-8')
            self.state = default
            return
        try:
            payload = json.loads(self.path.read_text(encoding='utf-8'))
            self.state = {**default, **payload}
        except Exception:
            self.state = default

    def heartbeat(self, node: str) -> dict:
        self.state.setdefault('heartbeats', {})[node] = int(time.time())
        self.path.write_text(json.dumps(self.state, indent=2), encoding='utf-8')
        return self.summary()

    def summary(self) -> dict:
        return {
            'cluster_name': self.state.get('cluster_name', 'ips-lab'),
            'node_name': self.state.get('node_name', 'node-1'),
            'mode': self.state.get('mode', DEFAULT_FAIL_MODE),
            'peers': list(self.state.get('peers', [])),
            'heartbeats': dict(self.state.get('heartbeats', {})),
            'note': 'HA scaffold only. This is not full active-active packet-path clustering.',
        }
