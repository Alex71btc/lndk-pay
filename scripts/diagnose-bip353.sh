#!/usr/bin/env bash
# Read-only: use exactly the resolver and LNURL probe of the running test app.
set -euo pipefail
if [[ "$#" -eq 0 ]]; then
  printf 'Usage: %s user@domain [user@domain ...]\n' "$0" >&2
  exit 2
fi
docker exec -i "${BOLT12_DIAGNOSTIC_CONTAINER:-bolt12-pay-phoenixd-test-pay-1}" python - "$@" <<'PY'
import asyncio
import hashlib
import json
import sys
from backend import app

async def main():
    for address in sys.argv[1:]:
        if not app.HRN_RE.fullmatch(address):
            print(json.dumps({'address': address, 'error': 'Invalid address'}))
            continue
        result = await app._resolve_pay_address_methods(address)
        offer = result['bolt12'].get('resolved_offer', '')
        cfg = app.load_config()
        user, domain = address.split('@', 1)
        alias = (cfg.get('aliases') or {}).get(user) if domain in {
            app.get_bip353_base_domain(), app.get_lnurl_base_domain(),
        } else None
        # Public diagnostics only; never dump config, credentials or invoices.
        print(json.dumps({
            'address': address,
            'dns_name': address.replace('@', '.user._bitcoin-payment.', 1),
            'dns_mode': cfg.get('dns_mode', 'none'),
            'cloudflare_zone_name': (cfg.get('cloudflare') or {}).get('zone_name', ''),
            'saved_alias_dns_name': alias.get('dns_name') if isinstance(alias, dict) else None,
            'expected_alias_dns_name': app._alias_dns_name(user) if isinstance(alias, dict) else None,
            'available_methods': result['available_methods'],
            'bolt12_error': result['bolt12']['error'][:500],
            'offer_length': len(offer),
            'offer_sha256': hashlib.sha256(offer.encode()).hexdigest() if offer else '',
            'saved_alias_offer_sha256': hashlib.sha256(alias['last_offer'].encode()).hexdigest()
                if isinstance(alias, dict) and alias.get('last_offer') else '',
            'dns_offer_matches_saved_alias': offer == alias.get('last_offer')
                if offer and isinstance(alias, dict) and alias.get('last_offer') else None,
            'lnurl_error': result['lnurl']['error'][:500],
            'lnurl_min_sat': result['lnurl']['min_sat'],
            'lnurl_max_sat': result['lnurl']['max_sat'],
        }, ensure_ascii=False, indent=2))

asyncio.run(main())
PY
