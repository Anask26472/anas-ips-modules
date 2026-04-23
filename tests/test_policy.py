from ips.core.policy import PolicyEngine


def test_policy_blocks_known_attack_with_ttl():
    engine = PolicyEngine(default_block_ttl=600)
    result = engine.decide({'label': 'dos', 'action': 'block', 'score': 0.97}, blocked_count=1)
    assert result.action == 'block'
    assert result.block_ttl >= 600


def test_policy_review_when_capacity_reached():
    engine = PolicyEngine(default_block_ttl=600, max_blocked_ips=1)
    result = engine.decide({'label': 'probe', 'action': 'block', 'score': 0.9}, blocked_count=1)
    assert result.action == 'monitor'
    assert result.requires_review is True
