## Setup Guide

### Step 1 — Install

Install BOLT12 Pay from the Umbrel Community App Store.

---

### Step 2 — Enable BOLT12 (required on Umbrel)

BOLT12 requires onion messaging in LND.

Connect via SSH:

```bash
ssh umbrel@umbrel.local
```

Open the LND config:

```bash
nano ~/umbrel/app-data/lightning/data/lnd/lnd.conf
```

Add this at the end of the file:

```text
[protocol]
custom-message=513
custom-nodeann=39
custom-init=39
```

Save the file and restart Lightning.

Without this, BOLT12 offers will not work.

---

### Step 3 — Configure App

Open the app and set:

- Public BOLT12 Address
- Lightning Address (LNURL)
- Domain / DNS

---

### Step 4 — Ready

You can now receive:

- BOLT12 payments
- Lightning Address payments
- LNURL payments

All fully self-hosted.

---

### Optional

- Enable Cloudflare DNS automation
- Add Nostr identity for Zaps

---

## ⚡ BOLT12 Pay

Self-hosted Lightning identity + payments for your own node.

---

## License

MIT License
