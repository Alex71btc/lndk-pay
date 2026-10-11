import unittest

import backend.app as app_module


def history_item(
    payment_hash: str,
    *,
    method: str,
    amount_sat: int,
    created_at: str,
    tx_type: str = "payment",
    fee_sat: int | None = None,
    memo: str = "",
):
    return {
        "payment_hash": payment_hash,
        "direction": "outgoing",
        "type": tx_type,
        "method": method,
        "counterparty": "",
        "amount_sat": amount_sat,
        "fee_sat": fee_sat,
        "status": "settled",
        "memo": memo,
        "identifier": "",
        "created_at": created_at,
        "settled_at": created_at,
        "raw_json": {"source": payment_hash},
    }


class Bolt12OutgoingActivityTests(unittest.TestCase):
    def test_collapses_matching_lnd_payment_into_bolt12_activity(self):
        bolt12 = history_item(
            "bip353-outgoing-1001",
            method="bolt12",
            amount_sat=38,
            created_at="1001",
            tx_type="offer",
            memo="test after restart",
        )
        lnd_payment = history_item(
            "real-payment-hash",
            method="bolt11",
            amount_sat=38,
            created_at="1000",
            fee_sat=1,
        )

        result = app_module._collapse_bolt12_outgoing_history(
            [bolt12, lnd_payment]
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["method"], "bolt12")
        self.assertEqual(result[0]["memo"], "test after restart")
        self.assertEqual(result[0]["fee_sat"], 1)
        self.assertEqual(
            result[0]["raw_json"]["lnd_payment_hash"],
            "real-payment-hash",
        )

    def test_keeps_unrelated_bolt11_payment(self):
        bolt12 = history_item(
            "bolt12-outgoing-1000",
            method="bolt12",
            amount_sat=38,
            created_at="1000",
            tx_type="offer",
        )
        bolt11 = history_item(
            "standalone-payment",
            method="bolt11",
            amount_sat=39,
            created_at="1001",
        )

        result = app_module._collapse_bolt12_outgoing_history([bolt12, bolt11])

        self.assertEqual(len(result), 2)

    def test_keeps_same_amount_payment_outside_match_window(self):
        bolt12 = history_item(
            "bolt12-outgoing-1000",
            method="bolt12",
            amount_sat=38,
            created_at="1000",
            tx_type="offer",
        )
        bolt11 = history_item(
            "older-payment",
            method="bolt11",
            amount_sat=38,
            created_at="900",
        )

        result = app_module._collapse_bolt12_outgoing_history([bolt12, bolt11])

        self.assertEqual(len(result), 2)

    def test_pairs_multiple_same_amount_payments_one_to_one(self):
        first_bolt12 = history_item(
            "bolt12-outgoing-1001",
            method="bolt12",
            amount_sat=38,
            created_at="1001",
            tx_type="offer",
        )
        second_bolt12 = history_item(
            "bolt12-outgoing-1011",
            method="bolt12",
            amount_sat=38,
            created_at="1011",
            tx_type="offer",
        )
        first_payment = history_item(
            "first-real-hash",
            method="bolt11",
            amount_sat=38,
            created_at="1000",
        )
        second_payment = history_item(
            "second-real-hash",
            method="bolt11",
            amount_sat=38,
            created_at="1010",
        )

        result = app_module._collapse_bolt12_outgoing_history(
            [second_bolt12, second_payment, first_bolt12, first_payment]
        )

        self.assertEqual(len(result), 2)
        linked_hashes = {
            item["raw_json"]["lnd_payment_hash"] for item in result
        }
        self.assertEqual(
            linked_hashes,
            {"first-real-hash", "second-real-hash"},
        )

    def test_pay_offer_command_sets_configured_invoice_timeout(self):
        command = app_module._pay_offer_command(
            "lno1example",
            21,
            "payer note",
        )

        self.assertEqual(
            command[-3:],
            [
                "payer note",
                "--response-invoice-timeout",
                str(app_module.LNDK_INVOICE_TIMEOUT_SECONDS),
            ],
        )


if __name__ == "__main__":
    unittest.main()
