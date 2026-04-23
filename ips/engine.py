from __future__ import annotations

import time
from collections import deque
from typing import Callable, Optional

from ips.api.bridge import BridgeServer
from ips.integrations.suricata import load_eve_alerts
from ips.core.alert_sink import AlertSink
from ips.core.audit import AuditTrail
from ips.core.health import HealthMonitor
from ips.core.ha import HAController
from ips.core.baseline import BaselineProfile
from ips.core.decision_chain import decide_action
from ips.core.feature_builder import build_live_features, get_flow_snapshot
from ips.core.ml_engine import MLModelEngine
from ips.core.performance import PerformanceTracker
from ips.core.policy import PolicyEngine
from ips.core.quarantine import QuarantineStore
from ips.core.threat_intel import ThreatIntelDB
from ips.core.rule_engine import inspect_rules
from ips.core.sniffer import LiveSniffer
from ips.core.state import EngineStats, ThreatEvent
from ips.core.threat_handler import ThreatHandler
from ips.utils.config import ENABLE_BRIDGE
from ips.utils.logger import get_logger

log = get_logger(__name__)


class IPSEngine:
    def __init__(self, interface: str | None = None, start_bridge: bool = False):
        self.interface = interface
        self.ml = MLModelEngine()
        self.baseline = BaselineProfile()
        self.performance = PerformanceTracker()
        self.quarantine = QuarantineStore()
        self.threat_handler = ThreatHandler()
        self.policy = PolicyEngine()
        self.alert_sink = AlertSink()
        self.audit = AuditTrail()
        self.health = HealthMonitor()
        self.ha = HAController()
        self.intel = ThreatIntelDB()
        self.sniffer = LiveSniffer(interface=interface)
        self.gui_callback: Optional[Callable[[dict], None]] = None
        self.running = False
        self.stats = EngineStats()
        self.recent_events = deque(maxlen=200)
        self.bridge = BridgeServer(self)
        self._bridge_enabled = start_bridge or ENABLE_BRIDGE

    def set_callback(self, callback: Callable[[dict], None]) -> None:
        self.gui_callback = callback

    def start(self) -> None:
        if self.running:
            log.info('engine already running')
            return
        self.running = True
        self.sniffer.start(self._handle_packet)
        if self._bridge_enabled:
            self.bridge.start()
        self.audit.record('system', 'engine.start', details={'bridge_enabled': self._bridge_enabled})
        log.info('engine started')

    def stop(self) -> None:
        if not self.running:
            return

        self.sniffer.stop()

        # cleanup temporary throttles before exit
        self.threat_handler.clear_throttles()

        self.performance.save()
        self.bridge.stop()
        self.running = False
        self.audit.record('system', 'engine.stop', details={'totals': self.get_stats()})
        log.info('engine stopped')

    def _handle_packet(self, packet) -> None:
        started = time.perf_counter()
        features = build_live_features(packet)
        if not features:
            return

        self.threat_handler.expire_blocks()
        self.threat_handler.expire_throttles()
        self.stats.total += 1
        self.baseline.observe(features)

        intel_match = self.intel.match_ip(features.get('src_ip')) or self.intel.match_ip(features.get('dst_ip'))
        if intel_match is not None:
            final = {
                'label': 'intel-hit',
                'score': 1.0,
                'layer': 'L-Intel',
                'action': 'block',
                'reason': intel_match.get('reason', 'matched local threat intel'),
            }
            self.stats.rule_hits += 1
        else:
            rule_result = inspect_rules(features)
            if rule_result is not None:
                final = rule_result
                self.stats.rule_hits += 1
            else:
                ml_result = self.ml.analyze(features)
                final = decide_action(features, ml_result, self.ml.autoencoder_ready)

        policy_decision = self.policy.decide(final, blocked_count=len(self.threat_handler.list_blocked_ips()))
        final['action'] = policy_decision.action
        final['block_ttl'] = policy_decision.block_ttl
        final['requires_review'] = policy_decision.requires_review

        if final['label'] != 'normal':
            self.stats.threats += 1
        if final['label'] == 'anomaly':
            self.stats.anomalies += 1
        if final['label'] == 'zero_day_like':
            self.stats.zero_day_like += 1

        blocked = self.threat_handler.respond(features, final, policy=policy_decision)
        if blocked:
            self.stats.blocked += 1
            self.audit.record('engine', 'response.block', target=features.get('src_ip', ''), details={'label': final.get('label'), 'reason': final.get('reason', '')})

        if final['label'] in {'anomaly', 'zero_day_like', 'probe', 'dos', 'r2l', 'u2r'}:
            self.quarantine.save(features, final)

        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        self.performance.record(final, elapsed_ms)

        if final['label'] != 'normal':
            event = ThreatEvent(
                time=features.get('captured_at', ''),
                src_ip=features.get('src_ip', '-'),
                dst_ip=features.get('dst_ip', '-'),
                label=final['label'],
                score=float(final.get('score', 0.0) or 0.0),
                layer=final.get('layer', '-'),
                action=final.get('action', 'monitor'),
                reason=final.get('reason', ''),
                extra={
                    'block_ttl': final.get('block_ttl'),
                    'review': final.get('requires_review', False),
                },
            )
            payload = {
                'time': event.time,
                'src_ip': event.src_ip,
                'dst_ip': event.dst_ip,
                'label': event.label,
                'score': event.score,
                'layer': event.layer,
                'action': event.action,
                'reason': event.reason,
                'block_ttl': final.get('block_ttl'),
                'requires_review': final.get('requires_review', False),
            }
            self.recent_events.append(payload)
            self.alert_sink.publish(payload)
            if self.gui_callback:
                self.gui_callback(payload)

    def get_stats(self) -> dict:
        return {
            'total': self.stats.total,
            'threats': self.stats.threats,
            'blocked': self.stats.blocked,
            'anomalies': self.stats.anomalies,
            'zero_day_like': self.stats.zero_day_like,
            'rule_hits': self.stats.rule_hits,
            'blocked_ips': len(self.threat_handler.list_blocked_ips()),
        }

    def get_status(self) -> dict:
        return {
            'running': self.running,
            'interface': self.sniffer.interface,
            'baseline': self.baseline.summary(),
            'flow_tracker': get_flow_snapshot(),
            'bridge_enabled': self._bridge_enabled,
            'policy': self.policy.summary(),
            'intel': self.intel.summary(),
        }

    def get_performance(self) -> dict:
        return self.performance.get_report()

    def get_threats(self) -> list[dict]:
        return self.quarantine.load()

    def get_recent_events(self) -> list[dict]:
        return list(self.recent_events)

    def unblock_ip(self, ip: str) -> bool:
        return self.threat_handler.unblock_ip(ip)

    def unblock_all(self) -> int:
        return self.threat_handler.clear_all()

    def import_suricata_alerts(self, path: str, limit: int = 100) -> list[dict]:
        alerts = load_eve_alerts(path, limit=limit)
        self.recent_events.extend(alerts)
        return alerts

    def get_health(self) -> dict:
        return self.health.snapshot()

    def get_audit(self, limit: int = 100) -> list[dict]:
        return self.audit.recent(limit=limit)

    def activate_profile(self, name: str) -> bool:
        ok = self.policy.activate_profile(name)
        self.audit.record('api', 'policy.activate', target=name, status='ok' if ok else 'failed')
        return ok

    def reload_intel(self) -> dict:
        self.intel.reload()
        self.audit.record('api', 'intel.reload')
        return self.intel.summary()

    def get_ha_status(self) -> dict:
        return self.ha.summary()

    def record_ha_heartbeat(self, node: str) -> dict:
        self.audit.record('ha', 'heartbeat', target=node)
        return self.ha.heartbeat(node)

    def management_snapshot(self) -> dict:
        return {
            'status': self.get_status(),
            'stats': self.get_stats(),
            'performance': self.get_performance(),
            'health': self.get_health(),
            'ha': self.get_ha_status(),
            'blocked': self.threat_handler.blocked_details(),
            'profiles': self.policy.profiles(),
            'intel': self.intel.summary(),
        }
