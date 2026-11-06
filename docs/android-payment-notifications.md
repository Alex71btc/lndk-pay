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
  "comment": "Thanks for the coffee"
}
```

`comment` is optional. It is sourced only from a real BOLT12 payer note or the
comment attached to an incoming Lightning Address/LNURL payment. The server
normalizes whitespace, removes control characters and limits it to 160 Unicode
characters. Automatically generated memos, offer descriptions and technical
invoice labels are not used.

The payload does not include the payment hash, invoice, raw memo or payer-note
field, counterparty, Nostr event or NWC connection. Web Push encrypts it for the
paired app before it leaves BOLT12 Pay. The selected distributor can still
observe delivery metadata such as timing, the opaque endpoint, source IP and
ciphertext size; it cannot read the encrypted payload. The Android switch
controls local display. Regardless of that switch, the public lockscreen version
remains the generic **Incoming Lightning payment** notice.

The VAPID private key is stored in the existing LND-bound encrypted secret
store. Push endpoints must use HTTPS. Literal and DNS-resolved private,
loopback, link-local and other non-public destinations are rejected, and push
delivery does not follow HTTP redirects.

## Reliability

- Payment hashes deduplicate the server queue, but are never sent to Android.
- Failed deliveries use bounded exponential retries with at most 12 attempts;
  accepted Web Push messages have a 24-hour distributor TTL.
- Invalid or expired endpoints are disabled automatically.
- Android keeps the most recent event IDs and suppresses duplicate notices.
- A notification opens the existing Pay UI; it never initiates a payment.

Delivery is best-effort. The Lightning Activity in BOLT12 Pay remains the source
of truth if the phone, distributor or public server is unavailable.
