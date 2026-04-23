from __future__ import annotations

import json
from copy import deepcopy

from ips.utils.config import POLICY_PROFILES_FILE


DEFAULT_PROFILES = {
    'lab': {
        'default_block_ttl': 300,
        'max_blocked_ips': 50,
    },
    'balanced': {
        'default_block_ttl': 900,
        'max_blocked_ips': 250,
    },
    'strict': {
        'default_block_ttl': 1800,
        'max_blocked_ips': 500,
    },
}


class ProfileStore:
    def __init__(self, path=POLICY_PROFILES_FILE):
        self.path = path
        self.payload = {'active': 'balanced', 'profiles': deepcopy(DEFAULT_PROFILES)}
        self._load_or_init()

    def _load_or_init(self) -> None:
        if not self.path.exists():
            self.save()
            return
        try:
            self.payload = json.loads(self.path.read_text(encoding='utf-8'))
        except Exception:
            self.payload = {'active': 'balanced', 'profiles': deepcopy(DEFAULT_PROFILES)}
            self.save()

    def save(self) -> None:
        self.path.write_text(json.dumps(self.payload, indent=2), encoding='utf-8')

    def list_profiles(self) -> dict:
        return deepcopy(self.payload)

    def active_name(self) -> str:
        return self.payload.get('active', 'balanced')

    def active_profile(self) -> dict:
        return deepcopy(self.payload.get('profiles', {}).get(self.active_name(), DEFAULT_PROFILES['balanced']))

    def activate(self, name: str) -> bool:
        if name not in self.payload.get('profiles', {}):
            return False
        self.payload['active'] = name
        self.save()
        return True
