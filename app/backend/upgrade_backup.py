"""One-time, consistent backup before the wallet-aware history migration."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile


def before_backend_migration(db_path, config_paths=()):
    db_path = Path(db_path)
    if not db_path.exists():
        return None
    with sqlite3.connect(db_path) as source:
        columns = source.execute('PRAGMA table_info(tx_history)').fetchall()
        if not columns or any(row[1] == 'backend_id' for row in columns):
            return None
        parent = db_path.parent / 'backups'
        parent.mkdir(mode=0o700, exist_ok=True)
        destination = parent / 'before-wallet-history-v1'
        if destination.exists():
            # Never replace the original pre-upgrade snapshot on a retry.
            if not (destination / 'complete.json').is_file():
                raise RuntimeError('Incomplete upgrade backup; original database was not migrated')
            if not (destination / db_path.name).is_file():
                raise RuntimeError('Upgrade database backup is missing; original database was not migrated')
            return destination
        temporary = Path(tempfile.mkdtemp(prefix='.wallet-history-', dir=parent))
        try:
            snapshot = temporary / db_path.name
            with sqlite3.connect(snapshot) as target:
                source.backup(target)
                if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise RuntimeError('Upgrade backup integrity check failed')
            snapshot.chmod(0o600)
            entries = []
            for index, original in enumerate(dict.fromkeys(map(str, config_paths))):
                path = Path(original)
                if not path.exists():
                    continue
                target = temporary / f'config-{index}'
                if path.is_dir():
                    shutil.copytree(path, target, symlinks=True)
                    for child in target.rglob('*'):
                        if not child.is_symlink():
                            child.chmod(0o700 if child.is_dir() else 0o600)
                    target.chmod(0o700)
                else:
                    shutil.copyfile(path, target)
                    target.chmod(0o600)
                entries.append({'original': original, 'backup': target.name})
            marker = temporary / 'complete.json'
            marker.write_text(json.dumps({'database': db_path.name, 'config': entries}, indent=2))
            marker.chmod(0o600)
            os.rename(temporary, destination)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        return destination
