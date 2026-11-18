"""Read-only BOLT12 display hints: units, malformed streams and API isolation."""
import unittest
from unittest.mock import AsyncMock, patch

from bech32 import CHARSET, convertbits
from backend import app
from backend.offer_preview import amount_hint


def encoded(stream):
    return 'lno1' + ''.join(CHARSET[value] for value in convertbits(stream, 8, 5, True))


def offer(amount=None, prefix=b'', suffix=b''):
    field = b'' if amount is None else b'\x08' + bytes([(amount.bit_length() + 7) // 8]) + amount.to_bytes((amount.bit_length() + 7) // 8, 'big')
    return encoded(prefix + field + b'\x0a\x04Test' + suffix)


class OfferAmountPreviewTests(unittest.IsolatedAsyncioTestCase):
    def test_amount_is_msat_and_whole_sat_suggestion_rounds_up(self):
        for msat, suggested in ((21000, 21), (23000, 23), (21001, 22), (1, 1)):
            with self.subTest(msat=msat):
                self.assertEqual(amount_hint(offer(msat)), {
                    'minimum_amount_msat': msat, 'suggested_amount_sat': suggested})

    def test_uppercase_and_line_continuations_are_supported(self):
        value = offer(21000)
        self.assertEqual(amount_hint(value.upper()), amount_hint(value))
        self.assertEqual(amount_hint(value[:9] + '+\n  ' + value[9:]), amount_hint(value))
        self.assertEqual(amount_hint(value[:5].upper() + value[5:]), {})

    def test_amountless_currency_and_quantity_are_not_guessed_as_sats(self):
        for value in (offer(), offer(21, prefix=b'\x06\x03USD'),
                      offer(21000, suffix=b'\x14\x01\x03')):
            self.assertEqual(amount_hint(value), {})

    def test_malformed_or_noncanonical_streams_have_no_suggestion(self):
        for stream in (b'\x08\x02\x01', b'\x08\x02\x00\x15',
                       b'\x08\x01\x15\x08\x01\x15',
                       b'\xfd\x00\x08\x01\x15', b'\xfd',
                       b'\x08\x09' + b'\xff'*9):
            self.assertEqual(amount_hint(encoded(stream)), {})
        self.assertEqual(amount_hint('lno1not-a-valid-offer'), {})
        self.assertEqual(amount_hint('lno1' + 'q'*65536), {})

    def test_large_values_are_not_rounded_by_javascript(self):
        self.assertEqual(amount_hint(offer(9007199254740992)), {})

    async def test_direct_offer_preview_uses_neither_lnd_nor_phoenixd(self):
        with (patch.object(app, 'require_pay_auth'),
              patch.object(app, '_run_command', side_effect=AssertionError('No CLI during preview')),
              patch.object(app.lightning_backends, 'checked_client', side_effect=AssertionError('No wallet during preview'))):
            preview = await app.preview_pay_target(app.PreviewPayTargetRequest(target=offer(23000)), None)
        self.assertEqual(preview['kind'], 'bolt12')
        self.assertEqual(preview['suggested_amount_sat'], 23)

    async def test_address_preview_keeps_lnurl_fixed_amount_separate_from_offer_minimum(self):
        # DNS is mocked and instantaneous; avoid a real executor thread here.
        with (patch.object(app.asyncio, 'to_thread', AsyncMock(side_effect=lambda fn, *args: fn(*args))),
              patch.object(app, '_resolve_bip353_address', return_value=offer(23000)),
              patch.object(app, '_fetch_lnurl_metadata_from_url', AsyncMock(return_value={
                  'callback': 'https://wallet.test/callback', 'minSendable': 21000,
                  'maxSendable': 21000, 'metadata': '[]'}))):
            preview = await app._resolve_pay_address_methods('alice@wallet.test')
        self.assertEqual(preview['bolt12']['suggested_amount_sat'], 23)
        self.assertEqual(preview['lnurl']['min_sat'], 21)
        self.assertEqual(preview['lnurl']['max_sat'], 21)
