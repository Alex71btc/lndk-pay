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


def lnurl_url(value, decode, *, unwrap_wallet=True):
    value = value.strip()
    for _ in range(4):
        if value.lower().startswith('lightning:'):
            value = value.split(':', 1)[1].strip()
        if value.lower().startswith('lnurl1'):
            value = decode(value)
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise HTTPException(400, 'LNURL requires an HTTPS service URL')
        if not unwrap_wallet:
            return value
        # LNbits' Copy LNURL can copy its wallet-launch link. The QR scanner
        # already unwraps this; pasted LND actions must resolve the same target.
        candidates = [item for key, item in parse_qsl(parsed.query)
                      if key.lower() == 'lightning' and
                      item.strip().lower().removeprefix('lightning:').startswith('lnurl1')]
        if not candidates:
            return value
        if len(candidates) != 1:
            raise HTTPException(400, 'Ambiguous LNURL wallet link')
        value = candidates[0].strip()
    raise HTTPException(400, 'Too many nested LNURL wallet links')


def action_error(exc, backend, action):
    # Inspect upstream diagnostics without reflecting URLs, vouchers or keys.
    detail = str(exc).lower()
    if isinstance(exc, httpx.HTTPStatusError):
        detail += ' ' + exc.response.text[:8192].lower()
    if any(marker in detail for marker in ('certificate_verify_failed', 'certificate verify failed',
            'sslhandshakeexception', 'certpathvalidatorexception', 'trust anchor',
            'unable to find valid certification path', 'self-signed certificate',
            'pkix path building failed', 'ip address mismatch', 'hostname mismatch')):
        return HTTPException(502, 'LNURL TLS certificate is not trusted. Use an HTTPS hostname with a valid certificate, or configure the service CA in the requesting backend.')
    if isinstance(exc, httpx.ConnectError):
        return HTTPException(502, backend + ' could not connect to the LNURL service. Check its address, port and TLS certificate.')
    if isinstance(exc, httpx.TimeoutException):
        return HTTPException(504, backend + ' LNURL request timed out. Check incoming Activity before retrying a withdrawal.')
    if isinstance(exc, httpx.HTTPStatusError):
        return HTTPException(502, backend + ' LNURL request returned HTTP ' + str(exc.response.status_code) + '. Check service reachability and backend logs.')
    return HTTPException(502, backend + (' LNURL withdrawal failed. Check service metadata/callback and incoming Activity.' if action == 'withdraw' else ' LNURL login failed. Check the service and LND signer permissions if using LND.'))


def normalize_signature(signature):
    # LND signrpc returns DER ECDSA despite its protobuf wire-format comment.
    # Normalize to fixed r||s so both representations derive the same identity.
    if len(signature) == 64:
        return signature
    try:
        return serialize_compact(der_to_cdata(signature))
    except ValueError:
        raise HTTPException(502, 'Invalid LND ECDSA signing response') from None


def response_json(response, stage):
    """Report the failing phase, never a voucher URL, invoice or response body."""
    host = response.url.host
    if response.status_code >= 400:
        raise HTTPException(502, f'LNURL {stage} returned HTTP {response.status_code} at {host}.')
    if response.is_redirect:
        raise HTTPException(502, f'LNURL {stage} redirected at {host}. Check the service public HTTPS URL and proxy configuration.')
    try:
        data = response.json()
    except ValueError:
        hint = ('Use the voucher LNURL/QR code, not the LNbits web page, and check the public HTTPS/proxy configuration.'
                if stage == 'withdrawal metadata' else
                'Check the service public HTTPS/proxy configuration and incoming Activity before retrying a withdrawal.')
        raise HTTPException(502, f'LNURL {stage} returned a web page or non-JSON response at {host}. '
                            + hint) from None
    if not isinstance(data, dict):
        raise HTTPException(502, f'LNURL {stage} returned invalid metadata at {host}.')
    if str(data.get('status') or '').upper() == 'ERROR':
        raise HTTPException(400, f'LNURL service rejected the {stage} request at {host}.')
    return data


async def withdraw_metadata(client, url, decode):
    # Only follow read-only metadata redirects, validating TLS on every hop.
    # Never retry a withdrawal callback, which may already have paid its invoice.
    for _ in range(4):
        response = await client.get(url)
        if response.status_code in (301, 302, 303, 307, 308) and response.headers.get('location'):
            url = lnurl_url(str(response.url.join(response.headers['location'])), decode, unwrap_wallet=False)
            continue
        return response_json(response, 'withdrawal metadata')
    raise HTTPException(502, 'Too many LNURL withdrawal metadata redirects. Check the service public HTTPS/proxy configuration.')


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
            data = await withdraw_metadata(client, url, app._decode_lnurl_bech32)
            if data.get('tag') != 'withdrawRequest':
                raise HTTPException(400, 'This is not an LNURL withdraw request')
            callback = lnurl_url(data.get('callback', ''), app._decode_lnurl_bech32, unwrap_wallet=False)
            challenge = data.get('k1')
            if not isinstance(challenge, str) or not challenge:
                raise HTTPException(400, 'LNURL withdrawal metadata is missing its challenge')
            maximum = int(data.get('maxWithdrawable') or 0)
            amount = maximum // 1000
            if amount < 1 or amount * 1000 < int(data.get('minWithdrawable') or 0):
                raise HTTPException(400, 'Withdraw amount cannot be represented in whole sats')
            invoice = await app._create_bolt11_invoice(amount_sat=amount, memo=str(data.get('defaultDescription') or '')[:128], method='lnurl', counterparty=url)
            # LNbits includes voucher state (e.g. id_unique_hash) in the callback
            # query. httpx's params= replaces that query rather than extending it.
            callback_url = httpx.URL(callback).copy_merge_params({
                'k1': challenge, 'pr': invoice['payment_request']})
            result = await client.get(callback_url)
        payload = response_json(result, 'login callback' if action == 'auth' else 'withdrawal callback')
        if payload.get('status') != 'OK':
            raise HTTPException(400, 'LNURL service rejected the request')
        return {'status': 'OK'}
