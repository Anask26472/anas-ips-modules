from ips.integrations.suricata import parse_eve_line


def test_parse_suricata_eve_line_alert():
    line = '{"event_type":"alert","timestamp":"2026-04-23T00:00:00Z","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","alert":{"signature":"Test Alert","severity":"high","category":"test"}}'
    item = parse_eve_line(line)
    assert item is not None
    assert item['layer'] == 'Suricata-EVE'
    assert item['label'] == 'Test Alert'
