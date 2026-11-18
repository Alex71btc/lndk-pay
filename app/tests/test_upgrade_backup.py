import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from backend.upgrade_backup import before_backend_migration
from backend.lightning_backends import migrate_history


class UpgradeBackupTests(unittest.TestCase):
    def test_upgrade_restart_and_restore_preserve_original_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / 'bolt12pay.db'
            config = root / 'config.json'
            config.write_text(json.dumps({'aliases': {'alice': {'last_offer': 'lno1original'}}}))
            with sqlite3.connect(db) as connection:
                connection.execute('CREATE TABLE tx_history (payment_hash TEXT PRIMARY KEY, direction TEXT, memo TEXT)')
                connection.execute("INSERT INTO tx_history VALUES ('hash', 'incoming', 'keep this memo')")
                connection.execute('CREATE INDEX history_direction ON tx_history(direction)')
                connection.execute('CREATE TABLE offer_history (offer TEXT)')
                connection.execute("INSERT INTO offer_history VALUES ('lno1original')")
            backup = before_backend_migration(db, (config,))
            self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
            with sqlite3.connect(db) as connection:
                migrate_history(connection)
                self.assertEqual(connection.execute('SELECT backend_id, memo FROM tx_history').fetchone(), ('lnd-default', 'keep this memo'))
                self.assertIsNotNone(connection.execute("SELECT name FROM sqlite_master WHERE name='history_direction'").fetchone())
            self.assertIsNone(before_backend_migration(db, (config,)))
            with sqlite3.connect(backup / db.name) as connection:
                self.assertNotIn('backend_id', [row[1] for row in connection.execute('PRAGMA table_info(tx_history)')])
                self.assertEqual(connection.execute('SELECT memo FROM tx_history').fetchone()[0], 'keep this memo')
                self.assertEqual(connection.execute('SELECT offer FROM offer_history').fetchone()[0], 'lno1original')
            self.assertEqual(json.loads((backup / 'config-0').read_text()), json.loads(config.read_text()))
            self.assertEqual((backup / db.name).stat().st_mode & 0o777, 0o600)

    def test_failed_backup_leaves_database_unmodified_and_retry_is_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'bolt12pay.db'
            config = Path(directory) / 'config.json'
            config.write_text('{}')
            with sqlite3.connect(db) as connection:
                connection.execute('CREATE TABLE tx_history (payment_hash TEXT PRIMARY KEY)')
            with patch('backend.upgrade_backup.shutil.copyfile', side_effect=OSError('disk full')):
                with self.assertRaises(OSError):
                    before_backend_migration(db, (config,))
            self.assertFalse((db.parent / 'backups/before-wallet-history-v1').exists())
            self.assertIsNotNone(before_backend_migration(db, (config,)))
