from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EngineStats:
    total: int = 0
    threats: int = 0
    blocked: int = 0
    anomalies: int = 0
    zero_day_like: int = 0
    rule_hits: int = 0


@dataclass
class ThreatEvent:
    time: str
    src_ip: str
    dst_ip: str
    label: str
    score: float
    layer: str
    action: str
    reason: str = ''
    extra: dict[str, Any] = field(default_factory=dict)
