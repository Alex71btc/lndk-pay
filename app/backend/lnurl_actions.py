"""Explicit LNURL withdraw/auth actions for the configured LND instance."""
import base64
import hashlib
import hmac
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit

import httpx
from coincurve import PrivateKey
from coincurve.ecdsa import der_to_cdata, serialize_compact
from fastapi import HTTPException

PHRASE = b'DO NOT EVER SIGN THIS TEXT WITH YOUR PRIVATE KEYS! IT IS ONLY USED FOR DERIVATION OF LNURL-AUTH HASHING-KEY, DISCLOSING ITS SIGNATURE WILL COMPROMISE YOUR LNURL-AUTH IDENTITY AND MAY LEAD TO LOSS OF FUNDS!'


def lnurl_url(value, decode):
    value = value.strip()
    if value.lower().startswith('lightning:'):
        value = value.split(':', 1)[1]
    url = decode(value) if value.lower().startswith('lnurl1') else value
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise HTTPException(400, 'LNURL requires an HTTPS service URL')
    return url


def normalize_signature(signature):
    # LND signrpc returns DER ECDSA despite its protobuf wire-format comment.
    # Normalize to fixed r||s so both representations derive the same identity.
    if len(signature) == 64:
        return signature
    try:
        return serialize_compact(der_to_cdata(signature))
    except ValueError:
        raise HTTPException(502, 'Invalid LND ECDSA signing response') from None


async def execute(app, value, action):
    url = lnurl_url(value, app._decode_lnurl_bech32)
    parsed = urlsplit(url)
    query = dict(parse_qsl(parsed.query))
    async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
        if action == 'auth':
            if query.get('tag') != 'login':
                raise HTTPException(400, 'This is not an LNURL login request')
            try:
                challenge = bytes.fromhex(query['k1'])
                if len(challenge) != 32:
                    raise ValueError()
            except (KeyError, ValueError):
                raise HTTPException(400, 'Invalid LNURL login challenge') from None
            # Domain-specific identity anchored to the LND node key, never the
            # node public key itself. Signer access is required by the macaroon.
            async with httpx.AsyncClient(timeout=app.LND_REST_TIMEOUT, verify=app._lnd_rest_verify_setting()) as lnd:
                response = await lnd.post(app.LND_REST_URL + '/v2/signer/signmessage',
                    headers={'Grpc-Metadata-macaroon': app._read_macaroon_hex(app.LND_MACAROON_PATH)},
                    json={'msg': base64.b64encode(PHRASE).decode(), 'key_loc': {'key_family': 6, 'key_index': 0}, 'double_hash': True})
                response.raise_for_status()
                signature = base64.b64decode(response.json()['signature'], validate=True)
                signature = normalize_signature(signature)
            key = PrivateKey(hmac.new(hashlib.sha256(signature).digest(), parsed.hostname.lower().encode(), hashlib.sha256).digest())
            query.update(sig=key.sign(challenge, hasher=None).hex(), key=key.public_key.format().hex())
            result = await client.get(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), '')))
        else:
            if query.get('tag') == 'login':
                raise HTTPException(400, 'This is a login request, not a withdrawal')
            metadata = await client.get(url)
            metadata.raise_for_status()
            data = metadata.json()
            if data.get('tag') != 'withdrawRequest':
                raise HTTPException(400, 'This is not an LNURL withdraw request')
            callback = lnurl_url(data.get('callback', ''), app._decode_lnurl_bech32)
            maximum = int(data.get('maxWithdrawable') or 0)
            amount = maximum // 1000
            if amount < 1 or amount * 1000 < int(data.get('minWithdrawable') or 0):
                raise HTTPException(400, 'Withdraw amount cannot be represented in whole sats')
            invoice = await app._create_bolt11_invoice(amount_sat=amount, memo=str(data.get('defaultDescription') or '')[:128], method='lnurl', counterparty=url)
            result = await client.get(callback, params={'k1': data['k1'], 'pr': invoice['payment_request']})
        result.raise_for_status()
        payload = result.json()
        if payload.get('status') != 'OK':
            raise HTTPException(400, 'LNURL service rejected the request')
        return {'status': 'OK'}
