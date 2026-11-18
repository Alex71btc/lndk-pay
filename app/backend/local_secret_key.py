"""Persistent owner-only wrapping key for installations without an LND signer."""
import os
from pathlib import Path


def load_key(path, *, existing_store=False):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.exists():
        if existing_store:
            raise RuntimeError('The local Nostr encryption key is missing; restore it from the app backup.')
        key = os.urandom(32)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
    if path.is_symlink():
        raise RuntimeError('The local Nostr encryption key must be a regular file.')
    key = path.read_bytes()
    if len(key) != 32:
        raise RuntimeError('The local Nostr encryption key is invalid; restore the app backup.')
    path.chmod(0o600)
    return key
