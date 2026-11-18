"""Read a BOLT12 amount for display only, without a backend or invoice request.

This is not offer validation; payment validation stays with LNDK/Phoenixd.
Encoding/fields: https://github.com/lightning/bolts/blob/master/12-offer-encoding.md
Currency and quantity offers intentionally get no automatic sat suggestion.
"""
import re

from bech32 import CHARSET, convertbits


def amount_hint(offer: str) -> dict:
    try:
        if len(offer) > 65536 or (offer != offer.lower() and offer != offer.upper()):
            return {}
        value = re.sub(r'\+\s*', '', offer.strip()).lower()
        if not value.startswith('lno1'):
            return {}
        decoded = convertbits([CHARSET.index(char) for char in value[4:]], 5, 8, False)
        if decoded is None:
            return {}
        data = bytes(decoded)
        offset = 0

        def bigsize():
            nonlocal offset
            if offset >= len(data):
                raise ValueError('Truncated integer')
            first = data[offset]
            offset += 1
            if first < 253:
                return first
            width, minimum = {253: (2, 253), 254: (4, 65536), 255: (8, 4294967296)}[first]
            if offset + width > len(data):
                raise ValueError('Truncated integer')
            number = int.from_bytes(data[offset:offset + width], 'big')
            offset += width
            if number < minimum:
                raise ValueError('Non-canonical integer')
            return number

        fields = {}
        previous = -1
        while offset < len(data):
            field, length = bigsize(), bigsize()
            if field <= previous or offset + length > len(data):
                return {}
            fields[field] = data[offset:offset + length]
            previous = field
            offset += length
        amount = fields.get(8, b'')
        if 6 in fields or 20 in fields or not amount or len(amount) > 8 or amount[0] == 0:
            return {}
        msat = int.from_bytes(amount, 'big')
        if not 0 < msat <= 9007199254740991:
            return {}
        return {'minimum_amount_msat': msat, 'suggested_amount_sat': (msat + 999) // 1000}
    except (ValueError, TypeError):
        return {}
