# BOLT12 Pay

Self-hosted Lightning payment and identity server with native BOLT12 support.

BOLT12 Pay lets you create and receive payments using next-generation BOLT12 offers, Lightning Address (BIP353), and LNURL — all from your own node.

It also includes Nostr identity support (NIP-05), Zap support, and a clean mobile-friendly UI, with seamless fallback between BOLT12, LNURL, and BOLT11 for maximum compatibility.

## Why BOLT12 Pay?

Today’s Lightning ecosystem is fragmented:

- Lightning Address is popular, but often depends on centralized infrastructure
- BOLT12 is the future, but tooling and UX are still limited
- Nostr identity and Lightning payments are increasingly converging
- Self-hosted users need a sovereign alternative that combines all of the above

BOLT12 Pay is designed to solve that.

## Features

- Native BOLT12 Offers
  - Create offers via LNDK
  - Pay BOLT12 offers directly
- Lightning Address
  - BIP353-compatible addresses
  - Self-hosted LNURL server
- BOLT11 fallback
  - Better compatibility with today’s wallets
- Nostr identity
  - NIP-05 support
  - Zap support
  - DM notifications
  - Multi-relay support
- Cloudflare DNS integration
  - Optional automatic DNS publishing
- Umbrel ready
  - Packaged as an Umbrel Community App
- Clean UX
  - Mobile-friendly payment pages
  - QR-based flows
  - Bilingual UI support (EN/DE)

## Architecture

BOLT12 Pay combines multiple layers:

- **BOLT12 / LNDK** for modern offer-based Lightning payments
- **LNURL / Lightning Address** for broad wallet compatibility
- **BIP353** for human-readable payment addresses
- **Nostr** for identity and Zap-related functionality
- **Umbrel deployment** for easy self-hosting

This makes BOLT12 Pay a bridge between current Lightning infrastructure and the next generation of Lightning payments.

## Main Capabilities

### Payment pages
Public alias pages can expose:

- BOLT12 Offer
- BIP353 address
- LNURL fallback
- BOLT11 fallback

### Admin / Pay UI
The built-in interface allows you to:

- create BOLT12 offers
- pay BOLT12 offers
- decode offers and BIP353 targets
- manage aliases
- generate Lightning-compatible QR flows
- configure identity and Nostr integration

### Identity
BOLT12 Pay can also act as a payment identity hub:

- NIP-05 identity mapping
- Zap-enabled addresses
- optional notification flows

## Example Use Cases

- Self-hosted Lightning Address for your own domain
- Public donation / tip page
- Personal or business payment identity
- Nostr Zap receiving endpoint
- Experimental BOLT12 infrastructure on Umbrel
- Sovereign replacement for custodial Lightning identity services

## Status

BOLT12 Pay is functional and already usable, but parts of the stack are still cutting-edge.

### Experimental areas

- BOLT12 support on LND is still evolving
- wallet support for BOLT12 remains inconsistent across the ecosystem
- some flows still rely on fallback layers for broad compatibility

## Umbrel Community App

BOLT12 Pay is available as an Umbrel Community App.

The Umbrel package lives under:

`umbrel/bolt12-pay`

## Screenshots

Add screenshots here once finalized:

  - https://raw.githubusercontent.com/Alex71btc/umbrel-community-store/master/alex-bolt12-pay/screenshots/1.png
  - https://raw.githubusercontent.com/Alex71btc/umbrel-community-store/master/alex-bolt12-pay/screenshots/2.png
  - https://raw.githubusercontent.com/Alex71btc/umbrel-community-store/master/alex-bolt12-pay/screenshots/3.png
  - https://raw.githubusercontent.com/Alex71btc/umbrel-community-store/master/alex-bolt12-pay/screenshots/4.png
  - https://raw.githubusercontent.com/Alex71btc/umbrel-community-store/master/alex-bolt12-pay/screenshots/5.png

## Roadmap

- NWC integration
- expanded Nostr Zap flows
- better notification and event publishing support
- optional Phoenixd backend support
- improved wallet interoperability
- additional self-hosted identity features

## Funding

This project is a strong candidate for open-source Bitcoin / Lightning grants.

If you would like to support development, feel free to open an issue or reach out.

## License

MIT
## Important directories

- `app/` application source
- `deploy/` deployment compose files
- `umbrel/bolt12-pay/` future Umbrel Community App files
- `docs/` project docs

## Deployment files

- `deploy/docker-compose.local.yml`
- `deploy/docker-compose.umbrel.yml`

## Architecture

See:

- `docs/architecture.md`
