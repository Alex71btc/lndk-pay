# Android payment notifications

BOLT12 Pay can notify its Android Companion about a newly settled incoming
payment. The feature is off until an authenticated administrator pairs a device.
It uses UnifiedPush and does not embed Firebase Cloud Messaging or another
mandatory third-party push SDK.

## Pairing

1. Save the public HTTPS BOLT12 Pay URL in the Companion.
2. Open **Android payment notifications** in the authenticated Pay UI.
3. Create a pairing QR or open the pairing link on the Android device.
4. Grant Android's notification permission and select or install a UnifiedPush
   distributor when prompted.
5. Return to the Pay UI to verify the paired device. A device can be revoked
   from either the server or the Companion.

The Companion's **Show payment comments** switch is off by default and is kept
in private Android app preferences. When enabled, it displays eligible comments
in the private notification body.

The one-time pairing token expires after ten minutes and is stored only as a
hash on the server. After pairing, the device receives a separate random token;
the server stores only its hash. Android backup and device-transfer export are
disabled for the Companion's local credentials.

## Data flow and privacy

For a newly settled incoming payment, the server queues this versioned payload:

```json
{
  "version": 1,
  "event_id": "random-id",
  "type": "payment_received",
  "amount_sat": 2100,
  "method": "bolt12",
  "payment_type": "offer",
  "comment": "Thanks for the coffee",
  "comment_source": "payer_note"
}
```

`comment` and `comment_source` are optional. Eligible sources are a real BOLT12
payer note (`payer_note`), an incoming Keysend TLV message (`keysend_message`),
a Lightning Address/LNURL comment (`lnurl_comment`), or the merchant-generated
description of a BOLT11 alias-fallback invoice created by this app
(`invoice_description`). The alias-fallback's technical prefix is removed, but
the alias and description remain visible. Arbitrary BOLT11 memos, offer
descriptions and other technical labels are not treated as payer comments. The
server normalizes whitespace, removes control characters and limits displayed
text to 160 Unicode characters.

The payload does not include the payment hash, invoice, raw memo or payer-note
field, counterparty, Nostr event or NWC connection. Web Push encrypts it for the
paired app before it leaves BOLT12 Pay. The selected distributor can still
observe delivery metadata such as timing, the opaque endpoint, source IP and
ciphertext size; it cannot read the encrypted payload. The Android switch
controls local display. Regardless of that switch, the public lockscreen version
remains the generic **Incoming Lightning payment** notice. If the existing Android
notification channel is configured as public, the Companion omits the comment
from the notification entirely.

Android uses the private notification while the device is trusted or unlocked
and the generic public version on a secure lockscreen. The app cannot override an
existing channel's settings after creation, and the user or device vendor retains
ultimate control over lockscreen display. An open-lock icon can therefore mean
that biometric or trusted-device authentication has already unlocked private
content even though the lockscreen UI is still visible.

The VAPID private key is stored in the existing LND-bound encrypted secret
store. Push endpoints must use HTTPS. Literal and DNS-resolved private,
loopback, link-local and other non-public destinations are rejected, and push
delivery does not follow HTTP redirects.

## Reliability

- Payment hashes deduplicate the server queue, but are never sent to Android.
- A newly settled, still-unclassified BOLT11/BOLT12 event waits up to 15 seconds
  for payer-note reconciliation. The same persisted event and event ID are
  updated only before its first delivery attempt; it is never sent a second time
  merely because metadata arrived late.
- Failed deliveries use bounded exponential retries with at most 12 attempts;
  accepted Web Push messages have a 24-hour distributor TTL.
- Invalid or expired endpoints are disabled automatically.
- Android keeps the most recent event IDs and suppresses duplicate notices.
- A notification opens the existing Pay UI; it never initiates a payment.

Delivery is best-effort. The Lightning Activity in BOLT12 Pay remains the source
of truth if the phone, distributor or public server is unavailable.
