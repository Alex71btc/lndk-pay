# BOLT12 Pay

Self-hosted Lightning payment server with:

- BOLT12 offers
- LNURL fallback using BOLT11 invoices
- BIP353 Lightning addresses
- public pay page
- admin UI

## Project status

Current repository status:

- local development works
- Umbrel / Portainer deployment works
- BOLT12 is the primary payment flow
- LNURL is the fallback flow
- BIP353 can be manual or automated later

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
