from ips.security.auth import SessionAuthManager


def test_bootstrap_users_exist(tmp_path):
    path = tmp_path / 'users.json'
    auth = SessionAuthManager(path=path)
    assert 'admin' in auth.users
