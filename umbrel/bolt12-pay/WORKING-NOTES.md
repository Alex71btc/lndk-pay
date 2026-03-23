# Working Umbrel App Notes

Known working setup:

- Store app id: alex-bolt12-pay
- umbrel-app.yml port: 8092
- web internal port: 8081
- LNDK image: alex71btc/lndk:stable
- BOLT12 Pay image: alex71btc/bolt12-pay:0.2.49

Important:
- LNDK cert path for web must be: /data/lndk/tls-cert.pem
- Shared app data mount is required
- LND mount: ${UMBREL_ROOT}/app-data/lightning/data/lnd:/lnd:ro

Verified:
- app installs from community store
- BOLT12 invoice works
- BOLT12 offer create/pay works
- BIP353 resolution works
