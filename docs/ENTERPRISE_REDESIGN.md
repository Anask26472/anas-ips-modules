# Enterprise-Style Redesign Notes

This repo now separates three concerns more clearly:

1. **Packet/runtime path**
   - `ips/core/sniffer.py`
   - `ips/core/flow_tracker.py`
   - `ips/core/feature_builder.py`
   - `ips/core/rule_engine.py`
   - `ips/core/ml_engine.py`
   - `ips/core/policy.py`
   - `ips/core/threat_handler.py`

2. **Management plane**
   - `ips/api/bridge.py`
   - `ips/core/alert_sink.py`
   - `logs/events.jsonl`

3. **Enterprise integration path**
   - `ips/integrations/suricata.py`
   - structured event export
   - TTL-based state handling

## Why this matters
A lot of student IPS projects become hard to grow because packet capture, ML, GUI, firewall logic, and management APIs are tightly mixed together.
This redesign starts to separate those responsibilities so the module can stay runnable now but still evolve later.

## Next realistic future steps
- move from packet-level inference to true connection/flow windows
- add protocol-aware parsers for HTTP/DNS/TLS metadata
- replace NSL-KDD feature mismatch with lab-collected training data
- integrate Suricata EVE or rule alerts as a first-class source
- add proper auth, RBAC, config profiles, and persistent policy storage
- benchmark packet drop/CPU/memory under controlled traffic
