# Phoenixd BOLT11 milestone — isolated local test

This is an uncommitted development change on `codex/phoenixd-prototype`, based on
`90f4ff9`. At inspection, `origin/main` was `13bc72b`: it contains seven commits
not in the prototype, including v0.3.25 and the latest Pay/QR refinements. They
have not been merged here because this Work session cannot write Git metadata.
Do not publish this prototype as a release. Merge current main before preparing
an integration PR and resolve the payment UI changes explicitly.

## Start without touching the existing LND container

From the repository root:

```bash
./scripts/start-phoenixd-test.sh
```

Enter a separate admin password when prompted. The script starts only Compose
project `bolt12-pay-phoenixd-test`, binds port **8092** to loopback, uses its own
named data volume, and builds a Python-only image without LNDK. It does not mount
LND macaroons, TLS certificates, or the existing application's data directory.
No Phoenixd wallet is created: connect to your existing daemon in Setup.

Open **http://phoenixd.localhost:8092/app?setup=1** and sign in. Use this hostname
(rather than the existing test UI's hostname) to keep browser login/CSRF cookies
separate. Chromium resolves `.localhost` to loopback.

In **Setup → Lightning backend**:

1. Select **Phoenixd**.
2. Enter the Phoenixd URL reachable **from the container**, e.g.
   `http://host.docker.internal:9740` for a daemon reachable on the Docker host,
   or the daemon's actual LAN URL. `localhost` inside the container means the
   container itself. The daemon's bind address/firewall must permit this route;
   do not expose its API publicly.
3. Enter the Phoenixd **full-access HTTP API password** locally in the field.
   The connection test confirms reachability and node identity; it cannot prove
   spending permission without attempting a payment.
4. Click **Test connection**, then **Save backend**. This button only changes
   backend settings; it does not publish or move any public Lightning address.

Do not paste the API password into chat. It is stored in the separate test
volume in an owner-only config file and is omitted from API config responses.

## Check both directions

Use small amounts you choose and consciously submit each payment.

- On `/app`, use the existing **BOLT11 invoice** section to create e.g. a 21-sat
  invoice. Pay it from LND or another wallet. On `/pay`, Lightning Activity should
  show an incoming **Phoenixd** entry changing from pending to settled. Use the
  Activity refresh button if the background interval has not elapsed.
- Create a BOLT11 invoice in LND. Paste it into the existing Pay form. Confirm
  that the backend label says **Phoenixd**, then send. Check LND's settled
  incoming invoice and the outgoing Phoenixd row in Activity.
- Reload and restart the test container: settings, backend ID, and history must
  survive. History imports existing Phoenixd BOLT11 entries as well.
- With both backends configured in a separate development installation, switch
  the active backend after creating an unpaid invoice. The original instance
  must continue to synchronize it. The Phoenixd-only Compose file intentionally
  has no LND configuration, so it rejects activating LND.

If a payment request times out, the result is unknown and stays pending. **Do not
resend automatically.** History synchronization checks the original instance.
A repeated request for the same pending or settled payment is rejected. An
unsubmitted request that remains unknown requires investigation before retry.

## Lifecycle

```bash
# Logs; the environment value is only needed for Compose interpolation.
PHOENIX_TEST_UI_PASSWORD=unused docker compose -f deploy/docker-compose.phoenixd-test.yml logs --tail=100 pay

# Stop this test container only; no data is removed.
PHOENIX_TEST_UI_PASSWORD=unused docker compose -f deploy/docker-compose.phoenixd-test.yml stop

# Restart: run the script again with your chosen UI password.
./scripts/start-phoenixd-test.sh
```

Do not run `down -v` unless you intend to delete this test application's config
and history. This volume never contains the Phoenixd wallet seed.

## Implementation and boundaries

- Interactive `/api/create-invoice` and `/api/pay-bolt11` select a snapshot of the
  active backend; the frontend sends its displayed backend ID. A stale selection
  is rejected before creating/sending. BOLT11 preview decodes locally in Phoenixd
  mode. Fixed-amount invoices are supported in the existing UI; the API also
  accepts an explicit amount for amountless invoices.
- Phoenixd instances have a persistent UUID and verified `nodeId`. Changing to
  another wallet at the same URL is rejected. The legacy configured LND instance
  is reserved as `lnd-default`; replacing that underlying LND wallet is outside
  this milestone and must not be done by repointing its environment variables.
- SQLite migrates the history key transactionally from `payment_hash` to
  `(backend_id, direction, payment_hash)`, retaining old LND rows. Both configured
  backends synchronize regardless of the active selector. Phoenixd history is
  paginated, includes pending/failed rows, and skips non-BOLT11/on-chain entries.
- The Phoenixd 0.9.3 source uses `fees` in msat; the existing integer `fee_sat`
  display truncates to sats like the LND path, retaining exact raw data. `sent`
  includes fees, so Activity separates recipient amount and fee. `isPaid` and
  `completedAt` distinguish pending/failed/settled; `isExpired` marks expiry.
- Existing public aliases, Offers, Lightning addresses and NWC remain pinned to
  LND. NWC history lookup/listing is explicitly LND-scoped. Phoenixd mode rejects
  unsupported interactive BOLT12/address/LNURL/keysend/create-offer endpoints;
  there is no automatic fallback to LND. Public address migration, NWC Phoenixd,
  production switching, notifications and BOLT12/BIP353 remain follow-up work.
- Backend configuration and API passwords survive restarts; an empty password
  field retains the saved value. Switching to LND works even if Phoenixd is
  offline. Credential or URL changes must pass the same-node identity check.

Reference checked against the daemon commit supplied in the handover:
[Phoenixd JSON API types](https://github.com/ACINQ/phoenixd/blob/66420de/src/commonMain/kotlin/fr/acinq/phoenixd/json/JsonSerializers.kt).

## Automated verification

2026-11-17 UI follow-up: Setup and Pay identify the saved active backend with
small transparent SVG adaptations of the supplied LND and phoenixd marks.
Native select options use plain backend names. Backend selection/UI tests (3)
and backend integration tests (20) passed again, along with JavaScript syntax
and whitespace checks. Container rendering was not checked in this session.

Local verification on 2026-11-16: **204 app tests + 11 root/PWA tests passed**.
Translation catalogs (all five languages), UI text lint, JavaScript and shell
syntax, Compose configuration validation, and `git diff --check` also passed.


The new integration tests use the real application functions, real temporary
SQLite databases, signed BOLT11 invoices, and HTTPX MockTransport (no real funds).
They exercise creation, settlement, payment, timeouts, failure, pagination,
identity checks, stale selection, migration, auth/CSRF, LND RouterRPC fallback,
NWC isolation, and Phoenixd-only startup.

```bash
APP_DATA_DIR=/tmp/bolt12-pay-tests \
APP_CONFIG_PATH=/tmp/bolt12-pay-tests/config.json \
PYTHONPATH=app python -m unittest discover -s app/tests
python -m unittest discover -s tests -p 'test_*.py'
python scripts/build_i18n.py --check
python scripts/check_ui_text.py
```

Use a Python environment containing `app/requirements.txt`. The local environment
`/home/freedom/.venvs/bolt12-pay-tests/bin/python` was available for this task.
The existing address-resolution unit tests invoke their mocked blocking functions
inline, matching the existing history-test pattern; no executor thread is needed
for those simulations.

Docker build/start and real API payment verification are **not** claimed by the
automated checks. The Work session has no access to the Docker socket or real
Phoenixd credentials. Run the isolated manual steps above to finish that check.


## Dual-backend BOLT11 test (added after the first live test)

User-reported on 2026-11-16: BOLT11 send and receive through the integrated
Phoenixd client succeeded. Container restart persistence is awaiting confirmation.

After checking that Phoenixd settings/history survive your restart, run:

```bash
cd /home/freedom/lndk-pay
./scripts/start-dual-backend-test.sh
```

Enter the same test UI password. The helper reads the running `bolt12-pay`
container's LND connection settings with `docker inspect`, and mounts **only**
its TLS certificate and macaroon as read-only files. It does not read/print
credential contents, copy production data, or restart the source container.
If the source container has another name, pass it as the first argument.
The source must use host bind-mounted credential files and a LND REST address
reachable from the separate test container (the existing local setup uses LAN).

This recreates only the existing test app on port 8092, keeping the same project
and named data volume. Phoenixd remains configured and selected until you change
it. For subsequent rebuilds use the dual script again; the Phoenixd-only script
intentionally removes LND access from the test app. Ordinary container restarts
retain the current container settings.

Test sequence:

1. In Setup select **LND + LNDK**, click **Save backend**, then reload `/pay`.
   Only LND REST/BOLT11 is available in this Python-only test image; the label
   names the backend family, not a newly installed LNDK service.
2. Create a new BOLT11 invoice from `/app` with LND selected. Copy it but leave
   it unpaid.
3. Switch to **Phoenixd**, save, reload `/pay`, and pay that LND invoice.
   Activity should show **LND incoming** and **Phoenixd outgoing** with the same
   payment hash, each as a separate row.
4. Create a new Phoenixd invoice, switch to LND, reload `/pay`, and pay it.
   Expect **Phoenixd incoming** and **LND outgoing**.
5. Restart and verify that both configurations and the selected backend persist.
   Pending invoices must still synchronize from their original backend.

The helper has four isolated configuration tests, and the merged Compose output
was validated for unchanged project, data volume and port plus exactly two
read-only credential mounts. Docker start and the dual live payment test must be
performed in the user's normal terminal; the Work session cannot access Docker.
The newer main UI changes and BOLT12/BIP353 integration remain separate steps.


### Docker Desktop host paths

The dual-backend helper now translates Docker Desktop's reported
`/host_mnt/home/...` bind source to `/home/...` when the original source is not
available and the translated host file exists. Native Docker paths are preferred.
It does not search other checkouts for substitute credentials. Seven launcher
configuration tests pass, including Desktop path translation and missing-file
failures. The two reported credential paths were verified locally without reading
their contents. If the earlier launch stopped with this path error, simply rerun
`./scripts/start-dual-backend-test.sh`; no container was changed by that failed
preparation step.


### Backend selection and Activity UI follow-up

The user's dual-backend screenshot confirms Phoenixd and LND rows coexist.
Setup now displays the saved active backend separately from the editable choice;
unsaved changes are marked, and Phoenixd fields/test button are hidden and disabled
when LND is selected. Saved Phoenixd settings are retained. Labels use provisional
flame/lightning symbols and say LND (not a claim that LNDK is running).
BOLT11 strings remain in transaction details instead of occupying the summary.
Activity pagination/refresh now deduplicates by backend, direction and hash, fixing
possible dropped rows when the same payment appears in both wallets. All 214 app
tests passed, including three Node-executed UI regressions; translation/text checks
passed in all five languages. Rebuild with `./scripts/start-dual-backend-test.sh`
and reload the test UI to pick up these changes.

## Phoenixd Lightning paths — 2026-11-17 extension

This section supersedes the earlier BOLT11-only limitations above. Still a
prototype, with no migration of public receiving addresses or NWC connections.

| Path | Phoenixd integration |
| --- | --- |
| BOLT11 create/pay | Existing invoice UI, unchanged |
| BOLT12 create/decode/pay | Existing Offer/Decode/Pay UI; native Phoenixd HTTP API |
| BIP353 pay | Existing DNS resolution and method chooser, Phoenixd pays resolved offer |
| Lightning Address / LNURL-Pay | Existing metadata/invoice resolver; Phoenixd pays invoice |
| LNURL-Withdraw | Pay → LNURL Withdraw / Login; requests the service maximum, imports incoming invoice |
| LNURL-Auth | Same expandable section; uses Phoenixd identity |
| Keysend | Unavailable in Phoenixd 0.9.3 HTTP API; explicit rejection |

Phoenixd source checked at `66420de`, `Api.kt` and `json/JsonSerializers.kt`.
On-chain swap-in/splice-out, liquidity management, and LNURL-auth on LND are
outside these Lightning payment UI changes.

Offers created through Phoenixd are bound in `backend_objects`. Public alias
and Cloudflare publication flows still use the existing LND receiving setup;
do not use them to migrate a public destination to Phoenixd yet. Phoenixd's
createoffer API supports amount and description (maximum 128 characters), not
issuer/expiry/quantity options; those are explicitly rejected.

BOLT12 history without invoice strings is imported when `subType=lightning`.
Payer notes and backend ownership survive synchronization. The active backend
ID is sent for create/decode/pay requests so stale browser selections fail.

An offer payment stores a durable pending attempt before submission, validates
the returned hash/preimage before settlement, and blocks another submission to
the same offer while its outcome is unknown. Successful history is imported
independently. **If the HTTP response is lost before the hash is known, the
pending attempt cannot safely be matched to a history payment automatically.**
It stays pending and blocks retries; investigate against Phoenixd before
manual cleanup. There are no automatic payment retries.

Manual test: rebuild with `./scripts/start-dual-backend-test.sh`, select Phoenixd,
create an offer and pay it from an external BOLT12 wallet. Pay an external offer
from this app, then test an existing BIP353 address and LNURL/Lightning Address
using the method chooser. Verify both directions in Activity, backend labels,
fees and payer notes. Only test Withdraw/Auth with a service you intend to use.
Repeat BOLT11 with LND selected and switch back to confirm history remains mixed.
Real payments for these new paths have not been performed by this Work session.

## Follow-up fixes and mobile access (2026-11-17)

Phoenixd `createoffer` and `lnurlauth` may return plain text on success. The
transport now accepts text only for these known string-response endpoints;
other endpoints still require JSON. Regression tests exercise real text bodies.

LNURL Withdraw/Login is available with either backend selected. LND withdrawals
create an invoice on LND. LND auth uses a domain-specific private key derived
from a deterministic signature by LND's node key (signrpc signer key family 6,
index 0). It requires signrpc SignMessage permission. This is this app's stable
LND login identity, with no claim of account portability to other wallets.
Signature correctness and withdraw callback parameters are tested; real LND
portal login and real withdrawals remain manual checks.

The LNURL section has a QR button that uses the existing camera scanner. A scan
fills the field; it never signs in or withdraws automatically. Login confirms
the destination domain before submitting. Phoenixd and LND identities differ.

For mobile access, first inspect `tailscale serve status` on the host. If HTTPS
port 8443 is free, add a separate tailnet-only listener:

```bash
tailscale serve --bg --https=8443 http://127.0.0.1:8092
tailscale serve status
```

Use the HTTPS URL printed by Tailscale, followed by `/pay`. Keep the existing
8091 listener. Do not use `serve reset` or Funnel. Camera access requires HTTPS
and browser permission. Separate ports share hostname cookies, so sign in again
if testing both instances on the same Tailscale hostname changes the session.
The Work session cannot inspect or change the host's Tailscale daemon config.

Automated verification after these fixes: 221 app tests passed, including text
response regression, LND auth signature verification and withdraw callback.
Current main UI integration is still outstanding; this session cannot write
Git metadata. Commit the prototype changes before merging current main into
`codex/phoenixd-prototype`; do not merge the unfinished prototype into main.
