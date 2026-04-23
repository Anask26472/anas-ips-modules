from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

from ips.utils.config import FLOW_WINDOW_SECONDS, SOURCE_WINDOW_SECONDS


class FlowTracker:
    def __init__(self, flow_window: float = FLOW_WINDOW_SECONDS, source_window: float = SOURCE_WINDOW_SECONDS):
        self.flow_window = flow_window
        self.source_window = source_window
        self.flow_events: Dict[Tuple[str, str, str, int], Deque[dict]] = defaultdict(deque)
        self.source_events: Dict[str, Deque[dict]] = defaultdict(deque)

    def _prune(self, events: Deque[dict], window: float, now: float) -> None:
        while events and now - events[0]['time'] > window:
            events.popleft()

    def observe(self, features: dict) -> dict:
        now = time.time()
        src_ip = features.get('src_ip', 'unknown')
        dst_ip = features.get('dst_ip', 'unknown')
        protocol = features.get('protocol', 'other')
        dst_port = int(features.get('dst_port', 0) or 0)
        packet_size = int(features.get('packet_size', 0) or 0)

        flow_key = (src_ip, dst_ip, protocol, dst_port)
        flow_event = {
            'time': now,
            'size': packet_size,
            'dst_port': dst_port,
            'dst_ip': dst_ip,
            'service': features.get('service', 'other'),
            'flag': features.get('flag', 'OTH'),
            'protocol': protocol,
        }

        flow_deque = self.flow_events[flow_key]
        source_deque = self.source_events[src_ip]
        flow_deque.append(flow_event)
        source_deque.append(flow_event)
        self._prune(flow_deque, self.flow_window, now)
        self._prune(source_deque, self.source_window, now)

        flow_packets = len(flow_deque)
        source_packets = len(source_deque)
        flow_bytes = sum(event['size'] for event in flow_deque)
        source_bytes = sum(event['size'] for event in source_deque)
        unique_ports = len({event['dst_port'] for event in source_deque if event['dst_port']})
        unique_hosts = len({event['dst_ip'] for event in source_deque if event['dst_ip']})
        services = [event['service'] for event in source_deque if event['service']]
        service_matches = sum(1 for service in services if service == features.get('service'))
        syn_count = sum(1 for event in flow_deque if event['flag'] == 'S0')
        rst_count = sum(1 for event in flow_deque if event['flag'] == 'REJ')
        sf_count = sum(1 for event in flow_deque if event['flag'] == 'SF')
        icmp_count = sum(1 for event in source_deque if event['protocol'] == 'icmp')

        source_packet_rate = round(source_packets / max(self.source_window, 1e-6), 3)
        source_byte_rate = round(source_bytes / max(self.source_window, 1e-6), 3)
        same_srv_rate = round(service_matches / max(source_packets, 1), 3)
        diff_srv_rate = round(1.0 - same_srv_rate, 3)
        serror_rate = round(syn_count / max(flow_packets, 1), 3)
        rerror_rate = round(rst_count / max(flow_packets, 1), 3)
        established_rate = round(sf_count / max(flow_packets, 1), 3)

        features.update({
            'flow_packets_window': flow_packets,
            'flow_bytes_window': flow_bytes,
            'src_packets_window': source_packets,
            'src_bytes_window': source_bytes,
            'src_packet_rate': source_packet_rate,
            'src_byte_rate': source_byte_rate,
            'unique_dst_ports': unique_ports,
            'unique_dst_hosts': unique_hosts,
            'same_srv_rate': same_srv_rate,
            'diff_srv_rate': diff_srv_rate,
            'serror_rate': serror_rate,
            'srv_serror_rate': serror_rate,
            'rerror_rate': rerror_rate,
            'srv_rerror_rate': rerror_rate,
            'established_rate': established_rate,
            'count': source_packets,
            'srv_count': flow_packets,
            'dst_host_count': unique_hosts,
            'dst_host_srv_count': service_matches,
            'dst_host_same_srv_rate': same_srv_rate,
            'dst_host_diff_srv_rate': diff_srv_rate,
            'dst_host_same_src_port_rate': round(
                sum(1 for event in source_deque if event.get('dst_port') == dst_port) / max(source_packets, 1), 3
            ),
            'dst_host_srv_diff_host_rate': round(
                max(unique_hosts - 1, 0) / max(source_packets, 1), 3
            ),
            'dst_host_serror_rate': serror_rate,
            'dst_host_srv_serror_rate': serror_rate,
            'dst_host_rerror_rate': rerror_rate,
            'dst_host_srv_rerror_rate': rerror_rate,
            'icmp_count_window': icmp_count,
            'syn_count_window': syn_count,
            'rst_count_window': rst_count,
        })
        return features

    def snapshot(self) -> dict:
        total_flows = sum(len(deq) for deq in self.flow_events.values())
        active_sources = sum(1 for deq in self.source_events.values() if deq)
        return {
            'tracked_flows': total_flows,
            'active_sources': active_sources,
            'flow_window_seconds': self.flow_window,
            'source_window_seconds': self.source_window,
        }
