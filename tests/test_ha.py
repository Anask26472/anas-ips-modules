from ips.core.ha import HAController


def test_ha_heartbeat(tmp_path):
    path = tmp_path / 'ha.json'
    ha = HAController(path=path)
    result = ha.heartbeat('node-2')
    assert 'node-2' in result['heartbeats']
