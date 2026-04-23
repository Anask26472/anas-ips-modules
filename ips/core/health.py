from __future__ import annotations

import os
import platform
import time
from typing import Any

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


class HealthMonitor:
    def __init__(self):
        self.started = time.time()

    def snapshot(self) -> dict[str, Any]:
        uptime = round(time.time() - self.started, 2)
        data: dict[str, Any] = {
            'platform': platform.platform(),
            'python_pid': os.getpid(),
            'uptime_seconds': uptime,
            'psutil_available': psutil is not None,
        }
        if psutil is None:
            return data
        proc = psutil.Process(os.getpid())
        mem = proc.memory_info()
        data.update({
            'cpu_percent': psutil.cpu_percent(interval=0.0),
            'memory_rss_mb': round(mem.rss / (1024 * 1024), 2),
            'system_memory_percent': psutil.virtual_memory().percent,
            'open_files': len(proc.open_files()) if hasattr(proc, 'open_files') else None,
            'threads': proc.num_threads(),
        })
        return data
