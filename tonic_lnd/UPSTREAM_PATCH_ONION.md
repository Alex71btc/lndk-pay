# Upstream patch for `lndk-org/tonic_lnd`: native onion message RPCs (LND v0.21)

Status: **prepared, not submitted.** Patch file: `tonic_lnd-add-onion-rpcs.patch`
(also committed here as `365c8fa`).

## Why this is needed

LND v0.21.0-beta added native onion messaging. LNDK migrated its onion transport
from the custom-message-513 path to LND's native RPCs `SendOnionMessage` and
`SubscribeOnionMessages`. The `tonic_lnd` bindings generate their Rust client
from `vendor/lightning.proto` at build time, and the currently pinned rev
(`f89f49a`) vendors a pre-0.21 proto that lacks those two RPCs. LNDK therefore
cannot compile against stock `tonic_lnd` until the vendored proto is updated.

## Smallest patch required for LNDK

The patch is **purely additive** to a single file, `vendor/lightning.proto`
(+73 lines, no other files). It adds exactly:

### Two RPCs (in `service Lightning`)
```
rpc SendOnionMessage (SendOnionMessageRequest) returns (SendOnionMessageResponse);
rpc SubscribeOnionMessages (SubscribeOnionMessagesRequest) returns (stream OnionMessageUpdate);
```

### Four messages
- `SendOnionMessageRequest`   — fields: `peer` (1), `path_key` (2), `onion` (3)
- `SendOnionMessageResponse`  — fields: `status` (1)
- `SubscribeOnionMessagesRequest` — empty
- `OnionMessageUpdate`        — fields: `peer` (1), `path_key` (2), `onion` (3),
  `reply_path` (4, `BlindedPath`), `encrypted_recipient_data` (5),
  `custom_records` (6, `map<uint64, bytes>`)

All six definitions (the four above plus the `BlindedPath`/`BlindedHop` they
reference) are **byte-identical to `lnd v0.21.0-beta:lnrpc/lightning.proto`**,
verified by extracting each block from both files and diffing — every one
reports MATCH, including field numbers and types.

## Is anything else required besides `SendOnionMessage` / `SubscribeOnionMessages`?

**No.**

- `OnionMessageUpdate.reply_path` references `message BlindedPath` (and
  transitively `BlindedHop`). Both are **already present** in the vendored proto
  (`git show f89f49a:vendor/lightning.proto` already defines `BlindedPath`), and
  both are identical to v0.21. So no dependency message needs to be added.
- No new proto `import`s are introduced (`map` is a built-in; all referenced
  types are local).
- No existing message or RPC is modified — the change is append-only, so it is
  backward compatible for all existing `tonic_lnd` consumers.
- No change to `build.rs` (it already compiles `vendor/lightning.proto`) or to
  `Cargo.toml` (no new features/deps).

LNDK itself only reads `peer`, `path_key`, and `onion`; the other
`OnionMessageUpdate` fields (`reply_path`, `encrypted_recipient_data`,
`custom_records`) are included to mirror LND exactly. A strictly minimal binding
could omit them (proto3 ignores unknown fields on decode), but mirroring LND is
recommended so the binding is correct and complete for other consumers.

## Verification commands used

```sh
# RPC declarations match LND v0.21 exactly
diff <(git -C lnd show v0.21.0-beta:lnrpc/lightning.proto \
        | grep -A2 "rpc SendOnionMessage \|rpc SubscribeOnionMessages ") \
     <(grep -A2 "rpc SendOnionMessage \|rpc SubscribeOnionMessages " \
        tonic_lnd/vendor/lightning.proto)

# Each message block byte-identical to LND v0.21 (MATCH for all six)
#   OnionMessageUpdate, SendOnionMessageRequest, SendOnionMessageResponse,
#   SubscribeOnionMessagesRequest, BlindedPath, BlindedHop

# Only one file changed; BlindedPath pre-existed
git -C tonic_lnd diff --stat f89f49a HEAD            # vendor/lightning.proto | 73 +++
git -C tonic_lnd show f89f49a:vendor/lightning.proto | grep -c "^message BlindedPath {"  # -> 1
```

## Alternatives for the maintainers

- **This patch (recommended, smallest):** append the two RPCs + four messages.
- **Full re-vendor:** replace `vendor/lightning.proto` wholesale with
  `lnd v0.21.0-beta`'s. Larger diff and pulls in other v0.21 additions LNDK does
  not use, but keeps the vendored proto fully in sync. Not required for LNDK.

After the patch lands and a rev is published, remove the local Cargo `[patch]`
in lndk's `Cargo.toml` and bump the `tonic_lnd` dependency to that rev.
