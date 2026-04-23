from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from functools import wraps
from secrets import token_hex

from ips.utils.config import (
    API_TOKENS_FILE,
    API_TOKEN,
    BOOTSTRAP_ADMIN_PASSWORD,
    BOOTSTRAP_ADMIN_USER,
    USERS_FILE,
)

ROLE_ORDER = {'viewer': 1, 'operator': 2, 'admin': 3}


def _pbkdf2_hash(password: str, salt: str | None = None) -> str:
    salt = salt or token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 200_000)
    return f"pbkdf2_sha256$200000${salt}${base64.b64encode(digest).decode('utf-8')}"


def _verify_pbkdf2(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt, digest = encoded.split('$', 3)
        if algo != 'pbkdf2_sha256':
            return False
        trial = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), int(rounds))
        return hmac.compare_digest(base64.b64encode(trial).decode('utf-8'), digest)
    except Exception:
        return False


class APIKeyRBAC:
    def __init__(self, path=API_TOKENS_FILE):
        self.path = path
        self.tokens: dict[str, dict] = {}
        self.reload()

    def reload(self) -> None:
        default = {
            'tokens': {
                API_TOKEN: {'role': 'admin', 'name': 'bootstrap-admin-key'},
            }
        }
        if not self.path.exists():
            self.path.write_text(json.dumps(default, indent=2), encoding='utf-8')
            self.tokens = default['tokens']
            return
        try:
            payload = json.loads(self.path.read_text(encoding='utf-8'))
            self.tokens = payload.get('tokens', {})
            if API_TOKEN and API_TOKEN not in self.tokens:
                self.tokens[API_TOKEN] = {'role': 'admin', 'name': 'bootstrap-admin-key'}
        except Exception:
            self.tokens = default['tokens']

    def identity(self, token: str) -> dict | None:
        if not token:
            return None
        item = self.tokens.get(token)
        if item is None:
            return None
        return {'auth_type': 'api_key', 'name': item.get('name', 'api-user'), 'role': item.get('role', 'viewer')}


class SessionAuthManager:
    def __init__(self, path=USERS_FILE):
        self.path = path
        self.users: dict[str, dict] = {}
        self.reload()

    def _bootstrap_payload(self) -> dict:
        return {
            'users': {
                BOOTSTRAP_ADMIN_USER: {
                    'role': 'admin',
                    'password_hash': _pbkdf2_hash(BOOTSTRAP_ADMIN_PASSWORD),
                    'display_name': 'Bootstrap Admin',
                    'must_change_password': True,
                }
            }
        }

    def reload(self) -> None:
        default = self._bootstrap_payload()
        if not self.path.exists():
            self.path.write_text(json.dumps(default, indent=2), encoding='utf-8')
            self.users = default['users']
            return
        try:
            payload = json.loads(self.path.read_text(encoding='utf-8'))
            self.users = payload.get('users', {})
            if not self.users:
                self.users = default['users']
        except Exception:
            self.users = default['users']

    def save(self) -> None:
        self.path.write_text(json.dumps({'users': self.users}, indent=2), encoding='utf-8')

    def authenticate(self, username: str, password: str) -> dict | None:
        record = self.users.get(username)
        if record is None:
            return None
        if not _verify_pbkdf2(password, record.get('password_hash', '')):
            return None
        return {
            'auth_type': 'session',
            'username': username,
            'name': record.get('display_name', username),
            'role': record.get('role', 'viewer'),
            'must_change_password': bool(record.get('must_change_password', False)),
        }

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        record = self.users.get(username)
        if record is None:
            return False
        if not _verify_pbkdf2(old_password, record.get('password_hash', '')):
            return False
        record['password_hash'] = _pbkdf2_hash(new_password)
        record['must_change_password'] = False
        self.save()
        return True

    def role_allowed(self, role: str, required: str) -> bool:
        return ROLE_ORDER.get(role, 0) >= ROLE_ORDER.get(required, 99)


class Authz:
    def __init__(self, api_keys: APIKeyRBAC | None = None, sessions: SessionAuthManager | None = None):
        self.api_keys = api_keys or APIKeyRBAC()
        self.sessions = sessions or SessionAuthManager()

    def identity_from_request(self, request, session) -> dict | None:
        token = request.headers.get('X-API-Key', '')
        api_ident = self.api_keys.identity(token)
        if api_ident is not None:
            return api_ident
        username = session.get('username')
        role = session.get('role')
        if username and role:
            return {
                'auth_type': 'session',
                'username': username,
                'name': session.get('display_name', username),
                'role': role,
                'must_change_password': bool(session.get('must_change_password', False)),
            }
        return None

    def allowed(self, request, session, required: str) -> bool:
        ident = self.identity_from_request(request, session)
        if ident is None:
            return False
        return ROLE_ORDER.get(ident.get('role', 'viewer'), 0) >= ROLE_ORDER.get(required, 99)


def require_role(authz: Authz, role: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from flask import jsonify, request, session
            if not authz.allowed(request, session, role):
                return jsonify({'error': 'unauthorized', 'required_role': role}), 401
            return fn(*args, **kwargs)
        return wrapper
    return decorator


class RBAC(APIKeyRBAC):
    """Backward-compatible token RBAC wrapper used by older tests/scripts."""

    def allowed(self, token: str, required: str) -> bool:
        ident = self.identity(token)
        if ident is None:
            return False
        return ROLE_ORDER.get(ident.get('role', 'viewer'), 0) >= ROLE_ORDER.get(required, 99)
