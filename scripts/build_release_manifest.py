from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from ips.update.manifest import build_manifest


def main():
    parser = argparse.ArgumentParser(description='Build and sign a release manifest for an IPS bundle')
    parser.add_argument('bundle_dir', help='Directory to describe')
    parser.add_argument('private_key_pem', help='Ed25519 private key in PEM format')
    parser.add_argument('--key-id', default='release-key-1')
    parser.add_argument('--output', default='release.manifest.json')
    args = parser.parse_args()

    from cryptography.hazmat.primitives import serialization

    bundle = Path(args.bundle_dir)
    private_key = serialization.load_pem_private_key(Path(args.private_key_pem).read_bytes(), password=None)
    manifest = build_manifest(bundle)
    signed_bytes = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature = private_key.sign(signed_bytes)

    payload = {
        'key_id': args.key_id,
        'signed_manifest': manifest,
        'signature': base64.b64encode(signature).decode('utf-8'),
    }
    Path(args.output).write_text(json.dumps(payload, indent=2), encoding='utf-8')
    print({'ok': True, 'output': args.output, 'files': len(manifest['files'])})


if __name__ == '__main__':
    main()
