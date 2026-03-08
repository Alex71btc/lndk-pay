# LNDK on Umbrel via Portainer (Docker-in-Docker)

Dieses Setup betreibt **LNDK** auf einem **Umbrel Home** über die **Portainer-App** (Portainer läuft dabei im eigenen Docker-in-Docker-Kontext).  
LNDK verbindet sich **nicht** über das Umbrel-Docker-Netz direkt mit LND, sondern über die **LAN-IP** des Umbrel-LND-gRPC-Servers.

Status: **funktioniert erfolgreich**
- LNDK startet
- BOLT12 `create-offer` funktioniert
- Offer-Zahlung mit externer Wallet/App getestet
- `pay-offer` erfolgreich
- `decode-offer` erfolgreich

---

## Architektur

- **Umbrel LND** läuft normal in der Umbrel Lightning App
- **LNDK** läuft als Container im **Portainer-Docker**
- Verbindung von LNDK zu LND über:
  - `https://<UMBREL-IP>:10009`
- Authentifizierung über:
  - LND `admin.macaroon` (derzeit zum Testen)
- TLS für LNDK-Clients:
  - LNDK eigenes Zertifikat unter `/data/tls-cert.pem`

Wichtig:
- `/secrets/tls.cert` = **LND TLS-Zertifikat**
- `/data/tls-cert.pem` = **LNDK TLS-Zertifikat**
- Für `lndk-cli --cert-path` braucht man das **LNDK-Zertifikat**, nicht das LND-Zertifikat.

---

## Voraussetzungen

- Umbrel Home mit Lightning App
- Portainer App auf Umbrel
- LNDK Docker-Image lokal gebaut und als TAR in Portainer importiert
- LND-Konfiguration enthält:

```ini
protocol.custom-message=513
protocol.custom-nodeann=39
protocol.custom-init=39

Verwendete Pfade auf Umbrel
LND Daten
/home/umbrel/umbrel/app-data/lightning/data/lnd
LND TLS-Zertifikat
/home/umbrel/umbrel/app-data/lightning/data/lnd/tls.cert
LND Macaroons
/home/umbrel/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/mainnet/
LNDK Macaroon erstellen

Zuerst wurde ein eigenes lndk.macaroon gebacken.

Im LND-Container:
sudo docker exec -it lightning_lnd_1 lncli \
  --network=mainnet \
  bakemacaroon \
  --save_to=/tmp/lndk.macaroon \
  uri:/lnrpc.Lightning/GetInfo \
  uri:/lnrpc.Lightning/ListPeers \
  uri:/lnrpc.Lightning/SubscribePeerEvents \
  uri:/lnrpc.Lightning/SendCustomMessage \
  uri:/lnrpc.Lightning/SubscribeCustomMessages \
  uri:/peersrpc.Peers/UpdateNodeAnnouncement \
  uri:/signrpc.Signer/DeriveSharedKey \
  uri:/verrpc.Versioner/GetVersion
Datei aus Container holen:
sudo docker cp lightning_lnd_1:/tmp/lndk.macaroon /home/umbrel/lndk.macaroon
An richtigen Ort verschieben:
sudo mv /home/umbrel/lndk.macaroon \
/home/umbrel/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/mainnet/lndk.macaroon
Rechte setzen:
sudo chown 1000:1000 \
/home/umbrel/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/mainnet/lndk.macaroon
Hinweis

Dieses Macaroon war für aktuelle LNDK-Nutzung offenbar zu knapp.
Zum erfolgreichen Test wurde deshalb vorübergehend admin.macaroon verwendet.

LNDK Image lokal bauen

Auf Linux-Rechner:

cd ~/lndk
docker build -t alex71btc/lndk:v0.3.0 .
docker save -o ~/lndk-v0.3.0.tar alex71btc/lndk:v0.3.0

Dann TAR nach Umbrel kopieren:

scp ~/lndk-v0.3.0.tar umbrel@<UMBREL-IP>:/home/umbrel/

Danach in Portainer per UI als Image importieren und taggen:

alex71btc/lndk:v0.3.0

Wichtig:
Das ist nur lokaler Import ins Portainer-Environment, kein Push zu Docker Hub.

Secrets in Portainer-Docker kopieren

Da Portainer auf Umbrel im eigenen Docker-Kontext läuft, wurden die Secrets direkt in den portainer_docker_1 Container kopiert.

sudo docker exec -it portainer_docker_1 mkdir -p /root/lndk-secrets

sudo docker cp /home/umbrel/umbrel/app-data/lightning/data/lnd/tls.cert \
  portainer_docker_1:/root/lndk-secrets/tls.cert

sudo docker cp /home/umbrel/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/mainnet/lndk.macaroon \
  portainer_docker_1:/root/lndk-secrets/lndk.macaroon

sudo docker cp /home/umbrel/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/mainnet/admin.macaroon \
  portainer_docker_1:/root/lndk-secrets/admin.macaroon

sudo docker exec -it portainer_docker_1 sh -lc '
chmod 600 /root/lndk-secrets/tls.cert /root/lndk-secrets/lndk.macaroon /root/lndk-secrets/admin.macaroon &&
ls -l /root/lndk-secrets
'
Portainer Stack
version: "3.8"

services:
  lndk:
    image: alex71btc/lndk:v0.3.0
    container_name: lndk
    restart: unless-stopped

    command: >
      lndk
      --address=https://192.168.188.39:10009
      --cert-path=/secrets/tls.cert
      --macaroon-path=/secrets/admin.macaroon
      --data-dir=/data
      --grpc-host=0.0.0.0
      --grpc-port=7000

    volumes:
      - lndk_data:/data
      - /root/lndk-secrets:/secrets:ro

    ports:
      - "7000:7000"

volumes:
  lndk_data:
Logs prüfen

Falls der Container im Portainer-Docker läuft:

sudo docker exec -it portainer_docker_1 docker logs lndk

oder live:

sudo docker exec -it portainer_docker_1 docker logs -f lndk
Typische Fehler
1. permission denied while trying to connect to the Docker daemon socket

Lösung:

sudo ...
2. Failed to sign message: permission denied

Ursache:

lndk.macaroon hatte nicht genug Rechte

Temporäre Lösung:

admin.macaroon verwenden

3. InvalidCertificate(UnknownIssuer)

Ursache:

falsches Zertifikat verwendet

Falsch:

/secrets/tls.cert   # LND TLS

Richtig für lndk-cli:

/data/tls-cert.pem  # LNDK TLS
LNDK CLI im Container verwenden
Hilfeseite
lndk-cli --help
lndk-cli create-offer --help
lndk-cli pay-offer --help
lndk-cli get-invoice --help
lndk-cli decode-offer --help
Wichtige Dateien im LNDK-Container
/data/tls-cert.pem
/data/tls-key.pem
/secrets/admin.macaroon
/secrets/lndk.macaroon
/secrets/tls.cert
Funktionierende Testbefehle
Offer erzeugen
lndk-cli \
  --network bitcoin \
  --grpc-host https://127.0.0.1 \
  --grpc-port 7000 \
  --cert-path /data/tls-cert.pem \
  --macaroon-path /secrets/admin.macaroon \
  create-offer \
  --amount 1000 \
  --description "Test offer"
Offer dekodieren
lndk-cli decode-offer 'lno...'
Offer bezahlen
lndk-cli \
  --network bitcoin \
  --grpc-host https://127.0.0.1 \
  --grpc-port 7000 \
  --cert-path /data/tls-cert.pem \
  --macaroon-path /secrets/admin.macaroon \
  pay-offer 'lno...' 1000 "hello"
Invoice aus Offer holen
lndk-cli \
  --network bitcoin \
  --grpc-host https://127.0.0.1 \
  --grpc-port 7000 \
  --cert-path /data/tls-cert.pem \
  --macaroon-path /secrets/admin.macaroon \
  get-invoice 'lno...'
Erfolgreich getesteter Status

Erfolgreich getestet:

create-offer

decode-offer

pay-offer

Zusätzlich erfolgreich:

Zahlung des Offers mit externer App (P-Wallet / Phoenix-Server-Protokoll) bestätigt

Sicherheitsnotiz

Derzeit wird für Funktionstests admin.macaroon verwendet.
Das ist praktisch, aber nicht die ideale Endlösung.

Später:

eigenes eingeschränktes LNDK-Macaroon sauber nachziehen

Secrets sauberer persistieren

optional eigenes kleines Frontend / API aufbauen

Ideen für nächste Schritte

eigenes minimales Web-Frontend für BOLT12

Offer als QR-Code anzeigen

Offer-Historie speichern

externes lndk-cli vom Linux-Rechner nutzen

LNDK in eigenes privates Tooling / Wallet-Experimente integrieren


---

## Dazu noch 2 Dateien im Repo

### `docker-compose.yml`
Nimm einfach den Stack-Teil separat als eigene Datei.

### `.gitignore`
Ganz wichtig, damit du keine Secrets aus Versehen commitest:

```gitignore
secrets/
*.macaroon
*.pem
*.cert
.env
Meine Empfehlung für dein privates GitHub-Repo

So eine Struktur wäre gut:

lndk-umbrel-portainer/
├── README.md
├── docker-compose.yml
├── .gitignore
├── notes/
│   ├── troubleshooting.md
│   └── commands.md
└── screenshots/

