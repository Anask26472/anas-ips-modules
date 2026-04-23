from ips.security.auth import RBAC


def test_rbac_bootstrap_admin_allowed():
    rbac = RBAC()
    assert rbac.allowed('change-me', 'admin') is True
    assert rbac.allowed('viewer-demo', 'viewer') is True
    assert rbac.allowed('viewer-demo', 'operator') is False
