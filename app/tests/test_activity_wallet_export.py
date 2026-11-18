import csv
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import backend.app as app_module


class ActivityWalletExportTests(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(TemporaryDirectory())
        self.enterContext(patch.object(app_module, "DB_PATH", Path(temp) / "activity.db"))
        self.enterContext(patch.object(app_module, "APP_DATA_DIR", Path(temp)))
        app_module.init_db()
        self.client = TestClient(app_module.app)
        self.addCleanup(self.client.close)

    def save(self, payment_hash, backend_id, direction="outgoing", **fields):
        app_module.save_tx_history_item({
            "payment_hash": payment_hash,
            "backend_id": backend_id,
            "direction": direction,
            "type": "payment",
            "method": "bolt11",
            "amount_sat": 21,
            "fee_sat": 1,
            "status": "settled",
            "created_at": "1767225600",
            **fields,
        })

    def test_filter_search_and_pagination(self):
        self.save("shared", "lnd-default", memo="match")
        self.save("shared", "phoenixd-a", "incoming", memo="match")
        self.save("second", "phoenixd-b", memo="match", created_at="1767225601")
        self.save("unrelated", "phoenixd-b", memo="other", created_at="1767225602")

        with patch.object(app_module, "require_pay_auth"):
            first = self.client.get("/api/tx-history?wallet=phoenixd&q=match&limit=1").json()
            second = self.client.get("/api/tx-history?wallet=phoenixd&q=match&limit=1&offset=1").json()
            lnd = self.client.get("/api/tx-history?wallet=lnd").json()

        self.assertEqual(first["items"][0]["backend_id"], "phoenixd-b")
        self.assertTrue(first["has_more"])
        self.assertEqual(second["items"][0]["backend_id"], "phoenixd-a")
        self.assertEqual([item["backend_id"] for item in lnd["items"]], ["lnd-default"])

    def test_export_includes_entire_history_both_legs_and_safe_text(self):
        self.save("shared", "lnd-default", memo="  =1+2")
        self.save("shared", "phoenixd-a", "incoming", payer_note="Danke, Alex\n👋", fee_sat=None)
        for number in range(201):
            self.save(f"earlier-{number}", "lnd-default", created_at="1767225599")

        with patch.object(app_module, "require_pay_auth") as require_auth:
            response = self.client.get("/api/tx-history/export.csv")
            window = self.client.get("/api/tx-history/export.csv?since=1767225600&before=1767225601")
            phoenix = self.client.get("/api/tx-history/export.csv?wallet=phoenixd")
            invalid = self.client.get("/api/tx-history/export.csv?since=1767225601&before=1767225600")

        self.assertEqual(require_auth.call_count, 4)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["cache-control"].startswith("no-store"))
        self.assertIn("attachment", response.headers["content-disposition"])
        self.assertEqual(invalid.status_code, 422)

        def read(result):
            return list(csv.DictReader(io.StringIO(result.content.decode("utf-8-sig"), newline="")))

        self.assertEqual(len(read(response)), 203)
        rows = {row["direction"]: row for row in read(window)}
        self.assertEqual(set(rows), {"incoming", "outgoing"})
        self.assertEqual(rows["outgoing"]["payment_hash"], rows["incoming"]["payment_hash"])
        self.assertEqual(rows["outgoing"]["memo"], "'  =1+2")
        self.assertEqual(rows["incoming"]["payer_note"], "Danke, Alex\n👋")
        self.assertEqual(rows["incoming"]["fee_sat"], "")
        self.assertEqual(rows["incoming"]["created_at_utc"], "2026-01-01T00:00:00+00:00")
        self.assertEqual([row["wallet"] for row in read(phoenix)], ["Phoenixd"])

    def test_bolt12_export_keeps_real_hash_and_matching_incoming_row(self):
        self.save("bolt12-outgoing-test", "lnd-default", method="bolt12", fee_sat=None)
        self.save("shared", "lnd-default", fee_sat=4)
        self.save("shared", "lnd-default", "incoming", type="invoice", fee_sat=None)

        with patch.object(app_module, "require_pay_auth"):
            response = self.client.get("/api/tx-history/export.csv?wallet=lnd")

        rows = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
        self.assertEqual({row["direction"] for row in rows}, {"incoming", "outgoing"})
        outgoing = next(row for row in rows if row["direction"] == "outgoing")
        self.assertEqual(outgoing["payment_hash"], "shared")
        self.assertEqual(outgoing["method"], "bolt12")
        self.assertEqual(outgoing["fee_sat"], "4")
