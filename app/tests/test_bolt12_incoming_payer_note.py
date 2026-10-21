import asyncio
import base64
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import backend.app as app_module


def invoice(payment_hash: str, *, memo: str, amount_sat: int = 21) -> dict:
    return {
        "r_hash": payment_hash,
        "memo": memo,
        "value": str(amount_sat),
        "state": "SETTLED",
        "settled": True,
        "creation_date": "100",
        "settle_date": "101",
        "htlcs": [],
    }


class Bolt12IncomingPayerNoteTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_data_dir = app_module.APP_DATA_DIR
        self.original_db_path = app_module.DB_PATH
        app_module.APP_DATA_DIR = Path(self.temp_dir.name)
        app_module.DB_PATH = app_module.APP_DATA_DIR / "bolt12pay.db"

    def tearDown(self):
        app_module.APP_DATA_DIR = self.original_data_dir
        app_module.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def test_migrates_existing_history_and_keeps_memo_separate(self):
        with sqlite3.connect(app_module.DB_PATH) as conn:
            conn.execute(
                """
                CREATE TABLE tx_history (
                    payment_hash TEXT PRIMARY KEY,
                    direction TEXT NOT NULL,
                    type TEXT NOT NULL,
                    method TEXT,
                    counterparty TEXT,
                    origin TEXT,
                    amount_sat INTEGER NOT NULL,
                    fee_sat INTEGER,
                    status TEXT,
                    memo TEXT,
                    identifier TEXT,
                    created_at TEXT,
                    settled_at TEXT,
                    raw_json TEXT
                )
                """
            )

        app_module.init_db()

        with sqlite3.connect(app_module.DB_PATH) as conn:
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(tx_history)")
            }
        self.assertIn("payer_note", columns)

        payment_hash = "11" * 32
        memo = "Public offer description"
        payer_note = "Erste Zeile\nZweite Zeile 🚀\n<script>alert(1)</script>"
        changed = app_module._upsert_invoice_history(
            invoice(payment_hash, memo=memo),
            {payment_hash: payer_note},
        )
        self.assertTrue(changed)

        # Re-open through the normal history API helper to exercise durable
        # SQLite storage rather than relying on an in-memory object.
        items = app_module.list_tx_history()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["payment_hash"], payment_hash)
        self.assertEqual(items[0]["memo"], memo)
        self.assertEqual(items[0]["payer_note"], payer_note)
        self.assertEqual(items[0]["method"], "bolt12")

    def test_correlates_multiple_equal_amount_payments_by_hash(self):
        app_module.init_db()
        first_hash = "22" * 32
        second_hash = "33" * 32
        notes = {
            first_hash: "first payment",
            second_hash: "second payment",
        }

        app_module._upsert_invoice_history(
            invoice(first_hash, memo="same offer", amount_sat=50),
            notes,
        )
        app_module._upsert_invoice_history(
            invoice(second_hash, memo="same offer", amount_sat=50),
            notes,
        )

        by_hash = {
            item["payment_hash"]: item["payer_note"]
            for item in app_module.list_tx_history()
        }
        self.assertEqual(by_hash, notes)

    def test_preserves_note_and_classification_when_metadata_unavailable(self):
        app_module.init_db()
        payment_hash = "66" * 32
        incoming = invoice(payment_hash, memo="Public description")
        payer_note = "First line\r\nSecond line 🧡\t" + "💛" * 200
        app_module._upsert_invoice_history(incoming, {payment_hash: payer_note})

        self.assertFalse(app_module._upsert_invoice_history(incoming, {}))
        item = app_module.list_tx_history()[0]
        self.assertEqual(item["payer_note"], payer_note)
        self.assertEqual(item["memo"], "Public description")
        self.assertEqual(item["method"], "bolt12")
        self.assertEqual(item["type"], "offer")

    def test_sync_backfills_notes_using_lnd_base64_payment_hash(self):
        app_module.init_db()
        app_module.init_db()
        payment_hash = "77" * 32
        incoming = invoice(
            base64.b64encode(bytes.fromhex(payment_hash)).decode("ascii"),
            memo="Public description",
        )
        app_module._upsert_invoice_history(incoming, {})
        payer_note = "First line\nSecond line 🚀\n" + "💛" * 200
        output = json.dumps({"items": [{
            "payment_hash": payment_hash, "payer_note": payer_note,
        }]}, ensure_ascii=False)

        async def inline_to_thread(function, *args):
            return function(*args)

        with (
            patch.object(app_module.asyncio, "to_thread", new=inline_to_thread),
            patch.object(app_module, "_list_invoices", new=AsyncMock(
                return_value={"invoices": [incoming]},
            )),
            patch.object(app_module, "_list_payments", new=AsyncMock(
                return_value={"payments": []},
            )),
            patch.object(app_module, "_run_command", return_value=output),
        ):
            self.assertEqual(asyncio.run(app_module._sync_tx_history_once()), 1)
            self.assertEqual(asyncio.run(app_module._sync_tx_history_once()), 0)

        item = app_module.list_tx_history()[0]
        self.assertEqual(item["payment_hash"], payment_hash)
        self.assertEqual(item["payer_note"], payer_note)
        self.assertEqual(item["memo"], "Public description")
        self.assertEqual(item["method"], "bolt12")

    def test_fetches_exact_unicode_notes_from_lndk_cli(self):
        payment_hash = "44" * 32
        payer_note = "line one\nline two 🧡\tkept"
        output = json.dumps(
            {
                "items": [
                    {
                        "payment_hash": payment_hash.upper(),
                        "payer_note": payer_note,
                    }
                ]
            },
            ensure_ascii=False,
        )

        with patch.object(app_module, "_run_command", return_value=output) as run:
            result = app_module._get_incoming_bolt12_payer_notes(
                [payment_hash, payment_hash]
            )

        self.assertEqual(result, {payment_hash: payer_note})
        command = run.call_args.args[0]
        self.assertEqual(command[-2:], ["list-incoming-payment-metadata", payment_hash])

    def test_keysend_message_regression(self):
        message = "Keysend stays intact 📨"
        keysend_invoice = invoice("55" * 32, memo="original memo")
        keysend_invoice["is_keysend"] = True
        keysend_invoice["htlcs"] = [
            {
                "custom_records": {
                    app_module.KEYSEND_MESSAGE_RECORD: base64.b64encode(
                        message.encode("utf-8")
                    ).decode("ascii")
                }
            }
        ]

        item = app_module._invoice_to_tx_history(keysend_invoice, {})

        self.assertEqual(item["method"], "keysend")
        self.assertEqual(item["memo"], message)
        self.assertIsNone(item["payer_note"])


class Bolt12IncomingPayerNoteUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (
            Path(__file__).resolve().parents[2]
            / "app"
            / "frontend"
            / "admin"
            / "index.html"
        ).read_text(encoding="utf-8")

    def test_renders_payer_note_as_escaped_pre_wrapped_text(self):
        self.assertIn('escapeContactHtml(displayPayerNote)', self.html)
        self.assertIn('class="txPayerNote"', self.html)
        self.assertIn(".txPayerNote {", self.html)
        self.assertIn("white-space: pre-wrap", self.html)
        self.assertIn('"history.payer_note": "Payer-Notiz"', self.html)
        self.assertIn('"history.payer_note": "Payer note"', self.html)


if __name__ == "__main__":
    unittest.main()
