from __future__ import annotations

import time
from typing import Any

import numpy as np
from scapy.all import ICMP, IP, TCP, UDP

from ips.core.flow_tracker import FlowTracker

_flow_tracker = FlowTracker()


PORT_SERVICE_MAP = {
    20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
    53: 'domain', 80: 'http', 110: 'pop_3', 143: 'imap4', 443: 'http_443',
    3306: 'sql', 8080: 'http_8080',
}


FEATURE_ORDER = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate',
]


def _protocol_name(packet) -> str:
    if packet.haslayer(TCP):
        return 'tcp'
    if packet.haslayer(UDP):
        return 'udp'
    if packet.haslayer(ICMP):
        return 'icmp'
    return 'other'


def _service_name(dst_port: int) -> str:
    return PORT_SERVICE_MAP.get(dst_port, 'other')


def _flag_name(packet) -> str:
    if not packet.haslayer(TCP):
        return 'OTH'
    flags = int(packet[TCP].flags)
    syn = bool(flags & 0x02)
    ack = bool(flags & 0x10)
    rst = bool(flags & 0x04)
    if rst:
        return 'REJ'
    if syn and not ack:
        return 'S0'
    if syn and ack or ack:
        return 'SF'
    return 'OTH'


def build_live_features(packet) -> dict[str, Any] | None:
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src_port = 0
    dst_port = 0
    if packet.haslayer(TCP):
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    features: dict[str, Any] = {
        'captured_at': time.strftime('%H:%M:%S'),
        'src_ip': ip_layer.src,
        'dst_ip': ip_layer.dst,
        'src_port': src_port,
        'dst_port': dst_port,
        'ttl': int(getattr(ip_layer, 'ttl', 0)),
        'packet_size': int(len(packet)),
        'protocol': _protocol_name(packet),
        'service': _service_name(dst_port),
        'flag': _flag_name(packet),
        # base fields aligned with training assets
        'duration': 0,
        'protocol_type': _protocol_name(packet),
        'src_bytes': int(len(packet)),
        'dst_bytes': 0,
        'land': int(ip_layer.src == ip_layer.dst and src_port == dst_port),
        'wrong_fragment': int(getattr(ip_layer, 'frag', 0) > 0),
        'urgent': int(packet[TCP].urgptr > 0) if packet.haslayer(TCP) else 0,
        'hot': 0,
        'num_failed_logins': 0,
        'logged_in': 0,
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_root': 0,
        'num_file_creations': 0,
        'num_shells': 0,
        'num_access_files': 0,
        'num_outbound_cmds': 0,
        'is_host_login': 0,
        'is_guest_login': 0,
    }
    return _flow_tracker.observe(features)


def get_flow_snapshot() -> dict[str, Any]:
    return _flow_tracker.snapshot()


def build_model_vector(features: dict[str, Any], encoders: dict[str, Any]) -> np.ndarray:
    def encode(name: str, value: str) -> int:
        encoder = encoders.get(name)
        if encoder is None:
            return 0
        classes = set(getattr(encoder, 'classes_', []))
        if value not in classes:
            return 0
        return int(encoder.transform([value])[0])

    vec = [
        float(features.get('duration', 0)),
        encode('protocol_type', features.get('protocol_type', 'tcp')),
        encode('service', features.get('service', 'other')),
        encode('flag', features.get('flag', 'OTH')),
        float(features.get('src_bytes', 0)),
        float(features.get('dst_bytes', 0)),
        float(features.get('land', 0)),
        float(features.get('wrong_fragment', 0)),
        float(features.get('urgent', 0)),
        float(features.get('hot', 0)),
        float(features.get('num_failed_logins', 0)),
        float(features.get('logged_in', 0)),
        float(features.get('num_compromised', 0)),
        float(features.get('root_shell', 0)),
        float(features.get('su_attempted', 0)),
        float(features.get('num_root', 0)),
        float(features.get('num_file_creations', 0)),
        float(features.get('num_shells', 0)),
        float(features.get('num_access_files', 0)),
        float(features.get('num_outbound_cmds', 0)),
        float(features.get('is_host_login', 0)),
        float(features.get('is_guest_login', 0)),
        float(features.get('count', 0)),
        float(features.get('srv_count', 0)),
        float(features.get('serror_rate', 0)),
        float(features.get('srv_serror_rate', 0)),
        float(features.get('rerror_rate', 0)),
        float(features.get('srv_rerror_rate', 0)),
        float(features.get('same_srv_rate', 0)),
        float(features.get('diff_srv_rate', 0)),
        float(features.get('dst_host_srv_diff_host_rate', 0)),
        float(features.get('dst_host_count', 0)),
        float(features.get('dst_host_srv_count', 0)),
        float(features.get('dst_host_same_srv_rate', 0)),
        float(features.get('dst_host_diff_srv_rate', 0)),
        float(features.get('dst_host_same_src_port_rate', 0)),
        float(features.get('dst_host_srv_diff_host_rate', 0)),
        float(features.get('dst_host_serror_rate', 0)),
        float(features.get('dst_host_srv_serror_rate', 0)),
        float(features.get('dst_host_rerror_rate', 0)),
        float(features.get('dst_host_srv_rerror_rate', 0)),
    ]
    return np.array([vec], dtype=float)
