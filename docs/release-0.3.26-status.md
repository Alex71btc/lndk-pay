# BOLT12 Pay 0.3.26 — preparation status

Status: source prepared and automatically tested; not published.

## End-of-session checkpoint — 2026-11-17

The user confirmed Phoenixd-only payments, alias BIP353/LNURL discovery,
alias DNS repair and correct payment toasts across Pay, Console and Setup.
Toasts appear once in a visible view and are not replayed on navigation.
Latest automated verification: 271 app tests and 11 root/PWA tests passed;
translations and UI text checks passed. The final source change removes the
extra conflict-replacement checkbox in favor of a clearly labelled action.

Live NWC validation is explicitly deferred to the next session: create a new
Phoenixd-bound connection with a small spending limit, query its balance,
create/receive an invoice, pay an external invoice and inspect transaction
history. Then test dual operation: switch the spending selector to LND and
confirm that this NWC connection and existing Phoenixd aliases keep their wallet.
Follow with the real platform upgrade and packaging checks before release.

The requested intermediate commit must not merge, tag, push or release.
Git metadata is read-only in this Work session. Run on the host:

```bash
cd ~/lndk-pay
./scripts/commit-phoenix-and-merge-main.sh --commit-only
```

The helper stages implementation, tests and documentation, excludes
`generated_images/`, and exits after the local checkpoint commit. Do not use
its default merge mode until integration validation resumes.

## Release preparation

- Working branch: `codex/phoenixd-prototype`.
- Base HEAD: `5903574e3f19845e246d1617e3e78ba259915056`, with uncommitted follow-ups.
- Main UI merge is already present. Local `origin/main` snapshot: `13bc72b`.
- Proposed app/Docker/Umbrel version: `0.3.26`.
- Proposed StartOS version: `0.3.26:0`.
- App image digest: pending build; no release tag/image was created here.
- LNDK is unchanged: `alex71btc/lndk:bolt12-pay-0.3.16-multiarch@sha256:8fee8bd094d7a3e59f596ce978097655ef820a88971aad52d6aac931c1894fb6`.
- Official Umbrel manifest and official StartOS version file inspected through
  GitHub still report `0.3.24` / `0.3.24:0`. Local packaging checkouts also
  remain on 0.3.24. No package PRs or marketplace availability for 0.3.26 exist
  from this session.
- The checked-in 0.3.24 Umbrel app image reference is
  `alex71btc/bolt12-pay:0.3.24@sha256:b5d0555925c963fbfeecb54d81743d6625d24fb093cc283ee0b505964b42b83d`.
  Image availability has not been verified in this session.

The expanded source supports standalone Phoenixd receiving aliases, offers,
BIP353 publication/repair, public BOLT11/LNURL invoices, wallet-bound NWC,
local encrypted Nostr keys, zap settlement, and Companion push. Existing LND
objects and LND-encrypted keys keep their original binding. An LND-encrypted
key store still needs the original LND to unlock; it is never silently replaced
with a new identity when LND is removed. A switch to Phoenixd does not move
funds, old addresses or old NWC connections.

Automatic checks: 271 app tests, 11 root/PWA tests, generated translations,
UI text lint, inline JavaScript parsing, shell syntax, and whitespace passed.
Upgrade/restart/backup restoration probes used populated databases and
configuration from both 0.3.24 and 0.3.25. These are fixture-based tests, not
live platform upgrades. LND legacy/native transport code is unchanged.

The app automatically backs up old database/configuration before migration.
No manual backup step is required for an ordinary upgrade. Returning to an
older schema uses the automatic pre-upgrade snapshot and does not preserve
later activity in the restored local database.

Next actions before publication:

1. Rebuild the local isolated test and verify the new standalone receiving,
   NWC and Nostr/push paths against the real Phoenixd, including a restart.
2. Commit source and the tested version. Git metadata is read-only here;
   the host helper stages the app, tests and docs and excludes generated images.
3. Build/test the actual production image for amd64 and arm64 and record its
   immutable digest. Docker daemon access is unavailable to this Work session.
4. Update/test Umbrel packages and the current official StartOS package with
   the exact source commit and image references. Refresh upstream package
   repositories before doing so, and decide whether their LND dependency is
   retained or becomes optional for a Phoenixd-only installation.
5. Complete live upgrade and relevant LND 0.20/0.21 regression coverage, then
   submit the package updates. Do not claim store availability before verified.

Known limitations: Phoenixd has no Keysend HTTP endpoint; unresolved payment
outcomes stay pending and are never automatically resent. Real LND
LNURL-withdraw settlement against a separate funding node is still unverified.
CLN is not included; its adapter should follow the standalone Phoenixd milestone.

Public alias tests found a receiving-subdomain DNS publication bug. Source now
publishes and verifies the canonical BIP353 name; previously affected aliases
need DNS republication after rebuilding, without replacing their offers. An existing parent-domain
record is not automatically deleted because it may serve a separate address.
The alias manager previously labelled the LNURL fallback as the generic address
while showing BIP353 DNS beneath it. It now labels both addresses explicitly and
uses BIP353 for its address-copy and QR actions. A root-domain BIP353 address and
a subdomain LNURL fallback remain valid and intentionally separate. DNS target
selection follows the BIP353 domain; the Cloudflare zone ID remains the parent
zone's ID. No saved address/domain settings were changed by these UI fixes.
The user confirmed BOLT12 discovery for the test alias after republication.
The UI flags saved-name mismatches and gives the expected record name.

In Cloudflare mode, opening authenticated Console or Setup automatically checks
published alias records without changing DNS. A queued dialog lists affected
addresses and canonical DNS names, with Later and Repair alias DNS actions.
It waits for the primary-address warning to close. Later suppresses the same
warning for the current tab session; a manual TXT verification can reopen it.
The explicit repair reuses each saved offer and its original wallet binding;
it creates missing canonical records or updates local metadata for records
already matching the offer. It neither renews offers nor deletes old DNS names.
Conflicting records remain unchanged by default. Replacing a single existing
BIP353 record shows a warning about the potential receiving wallet change and
an explicit Replace records and repair button; the server compares its record
ID/content fingerprint again before updating it. Other TXT content and multiple
records remain manual.
Stale repair plans are rejected if alias settings changed. Partial provider failures are
reported individually and do not hide successful repairs. Backend tests cover
these safeguards; a frontend harness verifies read-only startup, dialog queuing,
dismissal and the explicit authenticated/CSRF-protected repair request. The
user confirmed repair of a missing record in the rebuilt app. That live test
also exposed a CSS rule overriding hidden buttons, stale verification after
alias changes and an easily dismissed dialog. Source now honors hidden controls,
ignores backdrop clicks, keeps a review action outside the dialog and rechecks
DNS after repair, publication, renewal, editing and deletion.
The user has since confirmed both aliases verify correctly after repair.
The conflict action is now a single explicitly labelled button with a warning,
without an additional checkbox. The console translation asset version is bumped
so cached older catalogs cannot leave the newly added warning text blank.

Setup now has an explicit shared BIP353-domain field above the default public
BOLT12 address. It explains that all BIP353 aliases use that domain, shows live
alias examples, distinguishes the LNURL fallback domain and parent Cloudflare
zone, and explains republishing existing aliases after an intentional domain
change. Editing the domain updates the default address while preserving its
username and leaving LNURL settings untouched. Existing configurations derive
the field from their saved public address; older API clients remain supported.
Mismatched domain/address submissions are rejected before config or DNS writes.
The manual DNS preview now follows BIP353 rather than the LNURL domain. All new
text is translated into the five existing languages.
The user retested the older `coffee` alias and confirmed both BIP353 and LNURL
discovery in Phoenix Wallet and the app. LNURL payment to it succeeded. Separate
BIP353/BOLT12 payments to the user's Phoenix Wallet and primary address also
succeeded. After adjusting channel liquidity, the user successfully paid
5,000 sats to `donations` through BIP353/BOLT12 with Phoenixd (24 sats fees),
and identified the preceding alias payment failures as liquidity-related.
There is no longer evidence of a general alias-versus-primary payment defect.
The separate receiving-subdomain publication fix above is still needed.
Explicit Phoenixd failure reasons now appear in the app error instead of a
generic payment-failed message.
Transport failures retain their error class while keeping the outcome unknown
and blocking automatic resubmission.

The successful payment screenshot exposed a history issue: a new offer payment
after an explicit failure inherited the previous attempt's time and note.
Each submission now has a separate attempt identity and preserves earlier
failures; pending/unknown submissions still block a duplicate, including legacy
offer-hash attempt records. Regression tests cover the new metadata and upgrade
behavior.

`bash scripts/diagnose-bip353.sh user@domain` runs the app's read-only resolver
probe in the isolated test container, without creating an invoice or exposing
credentials.

Notification replay now uses shared, bounded hash-only browser state, a fresh
baseline after inactivity, and cross-tab locking where supported. Separate-tab
and simultaneous-poll regression tests cover the reported replay issue.
Follow-up tests reproduced background-tab consumption and the suppression of
imports delayed beyond 30 seconds. Hidden tabs now neither poll nor claim
notifications, and a visible view resumes polling when activated. The active
monitoring baseline survives navigation, so delayed BOLT12 receipts are not
discarded by a rolling 30-second cutoff. Duplicate rows in one response and
duplicate script execution cannot produce duplicate toast monitors. These
changes have automated coverage. The user subsequently confirmed correct
browser notifications, including no replay on navigation and delivery to the
visible Pay/Console/Setup view.

A public lookup of the test primary address also returned two distinct Bitcoin
TXT records. Their origin/ownership and DNS cleanup need checking before final
wallet interoperability verification; no live DNS records were deleted here.
