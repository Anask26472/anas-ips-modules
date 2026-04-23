from __future__ import annotations

from ips.utils.config import (
    AUTO_BLOCK,
    FLOOD_BYTE_RATE,
    FLOOD_PACKET_RATE,
    ICMP_BURST_THRESHOLD,
    PORT_SCAN_PACKET_THRESHOLD,
    PORT_SCAN_PORT_THRESHOLD,
    SYN_BURST_THRESHOLD,
)


def inspect_rules(features: dict) -> dict | None:
    packet_rate = float(features.get('src_packet_rate', 0.0))
    byte_rate = float(features.get('src_byte_rate', 0.0))
    unique_ports = int(features.get('unique_dst_ports', 0))
    syn_count = int(features.get('syn_count_window', 0))
    icmp_count = int(features.get('icmp_count_window', 0))
    established_rate = float(features.get('established_rate', 0.0))

    if unique_ports >= PORT_SCAN_PORT_THRESHOLD and int(features.get('count', 0)) >= PORT_SCAN_PACKET_THRESHOLD:
        return {
            'label': 'probe',
            'score': 0.99,
            'layer': 'L0-Rules',
            'action': 'block' if AUTO_BLOCK else 'monitor',
            'reason': 'rapid port sweep detected from a single source',
        }

    if packet_rate >= FLOOD_PACKET_RATE or byte_rate >= FLOOD_BYTE_RATE:
        return {
            'label': 'dos',
            'score': 0.98,
            'layer': 'L0-Rules',
            'action': 'block' if AUTO_BLOCK else 'throttle',
            'reason': 'traffic flood rate exceeded safe threshold',
        }

    if features.get('protocol') == 'tcp' and syn_count >= SYN_BURST_THRESHOLD and established_rate < 0.2:
        return {
            'label': 'dos',
            'score': 0.96,
            'layer': 'L0-Rules',
            'action': 'block' if AUTO_BLOCK else 'monitor',
            'reason': 'suspicious SYN burst without normal establishment',
        }

    if features.get('protocol') == 'icmp' and icmp_count >= ICMP_BURST_THRESHOLD:
        return {
            'label': 'dos',
            'score': 0.95,
            'layer': 'L0-Rules',
            'action': 'block' if AUTO_BLOCK else 'monitor',
            'reason': 'ICMP burst suggests ping flood behaviour',
        }

    return None
