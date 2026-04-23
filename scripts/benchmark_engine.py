from __future__ import annotations

import argparse
import os
import time

os.environ.setdefault('IPS_ENABLE_BLOCKING', '0')

from scapy.all import rdpcap
from scapy.layers.inet import ICMP, IP, TCP, UDP

from ips.core.decision_chain import decide_action
from ips.core.feature_builder import build_live_features
from ips.core.ml_engine import MLModelEngine
from ips.core.rule_engine import inspect_rules


def synthetic_packets(count: int):
    packets = []
    for i in range(count):
        if i % 3 == 0:
            packets.append(IP(src=f'10.0.0.{(i % 50) + 1}', dst='192.168.1.10') / TCP(dport=(20 + (i % 40)), flags='S'))
        elif i % 3 == 1:
            packets.append(IP(src=f'10.0.1.{(i % 50) + 1}', dst='192.168.1.10') / UDP(dport=53))
        else:
            packets.append(IP(src=f'10.0.2.{(i % 50) + 1}', dst='192.168.1.10') / ICMP())
    return packets


def load_packets(args):
    if args.pcap:
        return rdpcap(args.pcap)
    return synthetic_packets(args.count)


def main():
    parser = argparse.ArgumentParser(description='Offline benchmark for IPS decision pipeline')
    parser.add_argument('--pcap', help='Optional pcap file for replay benchmark')
    parser.add_argument('--count', type=int, default=5000, help='Synthetic packet count if no PCAP is provided')
    args = parser.parse_args()

    model = MLModelEngine()
    packets = load_packets(args)
    total = 0
    alerts = 0

    started = time.perf_counter()
    for packet in packets:
        features = build_live_features(packet)
        if not features:
            continue
        rule_result = inspect_rules(features)
        if rule_result is None:
            ml_result = model.analyze(features)
            final = decide_action(features, ml_result, model.autoencoder_ready)
        else:
            final = rule_result
        total += 1
        if final.get('label') != 'normal':
            alerts += 1
    elapsed = time.perf_counter() - started
    rate = total / elapsed if elapsed else 0
    print({
        'processed_packets': total,
        'alerts': alerts,
        'seconds': round(elapsed, 4),
        'packets_per_second': round(rate, 2),
        'note': 'Offline pipeline benchmark only. This is not a line-rate inline certification.',
    })


if __name__ == '__main__':
    main()
