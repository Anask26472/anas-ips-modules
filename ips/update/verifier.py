from __future__ import annotations

import base64
import json
from pathlib import Path

from ips.update.manifest import build_manifest
from ips.utils.config import UPDATE_KEYS_FILE


def _load_crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        return serialization, Ed25519PublicKey
    except Exception as exc:
        raise RuntimeError('cryptography package is required for signed update verification') from exc


def verify_release_bundle(bundle_dir: str | Path, manifest_file: str | Path, keys_file: str | Path = UPDATE_KEYS_FILE) -> dict:
    serialization, Ed25519PublicKey = _load_crypto()
    bundle = Path(bundle_dir)
    manifest_path = Path(manifest_file)
    keys_path = Path(keys_file)

    payload = json.loads(manifest_path.read_text(encoding='utf-8'))
    keyset = json.loads(keys_path.read_text(encoding='utf-8'))
    signed_manifest = payload.get('signed_manifest', {})
    signature_b64 = payload.get('signature', '')
    key_id = payload.get('key_id', '')

    matching_key = next((item for item in keyset.get('keys', []) if item.get('key_id') == key_id), None)
    if matching_key is None:
        return {'ok': False, 'error': 'unknown_key_id'}

    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(matching_key['public_key_b64']))
    signed_bytes = json.dumps(signed_manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
    try:
        public_key.verify(base64.b64decode(signature_b64), signed_bytes)
    except Exception:
        return {'ok': False, 'error': 'bad_signature'}

    local_manifest = build_manifest(bundle)
    expected = {item['path']: item for item in signed_manifest.get('files', [])}
    actual = {item['path']: item for item in local_manifest.get('files', [])}

    mismatches = []
    for rel, entry in expected.items():
        local = actual.get(rel)
        if local is None:
            mismatches.append({'path': rel, 'error': 'missing_local_file'})
            continue
        if local['sha256'] != entry['sha256']:
            mismatches.append({'path': rel, 'error': 'hash_mismatch'})
        if int(local['size']) != int(entry['size']):
            mismatches.append({'path': rel, 'error': 'size_mismatch'})

    extras = sorted(rel for rel in actual if rel not in expected)
    return {
        'ok': len(mismatches) == 0,
        'key_id': key_id,
        'checked_files': len(expected),
        'mismatches': mismatches,
        'extra_files': extras,
    }
