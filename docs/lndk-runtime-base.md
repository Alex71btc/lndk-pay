# LNDK runtime source

The Rust runtime in this repository is based on
[`Alex71btc/lndk` at `89a06dbc7ee3f0d4e9dfd254c392fb6c093ad293`](https://github.com/Alex71btc/lndk/commit/89a06dbc7ee3f0d4e9dfd254c392fb6c093ad293)
from `feat/native-onion-amountless-memo-dedupe`, the source of the previously
bundled `alex71btc/lndk:bolt12-pay-89a06db-multiarch` image.

This baseline includes native onion RPC support for LND 0.21+, the vendored
`tonic_lnd` RPC definitions, the patched LDK for amountless offers, the
`BOLT12 Offer` invoice memo, and invoice reuse for duplicate requests.
Incoming payer-note persistence and its authenticated metadata RPC are added
on top of that baseline. The offer memo remains separate from the payer note.

When updating the runtime, check its complete source and locked dependencies;
an application image pin alone does not update the Rust source tree.
The root Dockerfile builds this source tree. For the local two-service stack,
the app's `lndk_local` additional build context references `service:lndk`,
so the CLI is copied from the same build as the running LNDK server.

The Docker build caches Cargo downloads and compilation outputs. The first
build of a new baseline still compiles its dependencies; subsequent source
changes can reuse those outputs. `docker compose down` does not remove these
build caches or named data volumes by default.
