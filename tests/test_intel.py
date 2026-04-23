from ips.core.threat_intel import ThreatIntelDB


def test_intel_match_ip():
    intel = ThreatIntelDB()
    hit = intel.match_ip('203.0.113.10')
    assert hit is not None
    assert hit['reason'] == 'known lab scanner'
