from ips.core.policy import PolicyEngine


def test_activate_profile_changes_summary():
    engine = PolicyEngine()
    assert engine.activate_profile('strict') is True
    summary = engine.summary()
    assert summary['active_profile'] == 'strict'
    assert summary['default_block_ttl'] >= 1800
