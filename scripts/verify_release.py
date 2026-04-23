from __future__ import annotations

import argparse
from ips.update.verifier import verify_release_bundle


def main():
    parser = argparse.ArgumentParser(description='Verify signed IPS release manifest')
    parser.add_argument('bundle_dir')
    parser.add_argument('manifest_file')
    parser.add_argument('--keys', default=None)
    args = parser.parse_args()

    kwargs = {}
    if args.keys:
        kwargs['keys_file'] = args.keys
    result = verify_release_bundle(args.bundle_dir, args.manifest_file, **kwargs)
    print(result)


if __name__ == '__main__':
    main()
