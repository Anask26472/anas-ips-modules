from ips.core.decision_chain import decide_action
from ips.core.rule_engine import inspect_rules


def test_decision_chain_known_attack():
    final = decide_action({'count': 1, 'src_packet_rate': 1}, {'label': 'dos', 'score': 0.95}, False)
    assert final['action'] == 'block'


def test_rule_engine_scan_detection():
    result = inspect_rules({
        'unique_dst_ports': 15,
        'count': 25,
        'src_packet_rate': 10,
        'src_byte_rate': 1000,
        'syn_count_window': 0,
        'icmp_count_window': 0,
        'established_rate': 0.0,
        'protocol': 'tcp',
    })
    assert result is not None
    assert result['label'] == 'probe'
