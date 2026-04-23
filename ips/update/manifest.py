from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(base_dir: str | Path) -> dict:
    base = Path(base_dir)
    files = []
    for path in sorted(p for p in base.rglob('*') if p.is_file()):
        rel = path.relative_to(base).as_posix()
        files.append({
            'path': rel,
            'sha256': sha256_file(path),
            'size': path.stat().st_size,
        })
    return {'base_dir': str(base), 'files': files}
