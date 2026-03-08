# Troubleshooting

## Docker daemon permission denied
Lösung:
```bash
sudo ...

lncli not found on Umbrel host

lncli direkt im LND-Container ausführen:

sudo docker exec -it lightning_lnd_1 lncli ...
Permission denied when saving macaroon to /root/.lnd

Macaroon zuerst nach /tmp schreiben und dann per docker cp herauskopieren.

LNDK panic: Failed to sign message / permission denied
git push
