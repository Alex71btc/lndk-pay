# LNDK Commands

## Build image locally
```bash
cd ~/lndk
docker build -t alex71btc/lndk:v0.3.0 .
docker save -o ~/lndk-v0.3.0.tar alex71btc/lndk:v0.3.0
Copy image to Umbrel
scp ~/lndk-v0.3.0.tar umbrel@YOUR_NODE_IP:/home/umbrel/
Create lndk.macaroon
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
Copy macaroon out of container
sudo docker cp lightning_lnd_1:/tmp/lndk.macaroon /home/umbrel/lndk.macaroon
sudo mv /home/umbrel/lndk.macaroon \
/home/umbrel/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/mainnet/lndk.macaroon
sudo chown 1000:1000 \
/home/umbrel/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/mainnet/lndk.macaroon
Copy secrets into portainer_docker_1
sudo docker exec -it portainer_docker_1 mkdir -p /root/lndk-secrets

sudo docker cp /home/umbrel/umbrel/app-data/lightning/data/lnd/tls.cert \
  portainer_docker_1:/root/lndk-secrets/tls.cert

sudo docker cp /home/umbrel/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/mainnet/lndk.macaroon \
  portainer_docker_1:/root/lndk-secrets/lndk.macaroon

sudo docker cp /home/umbrel/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/mainnet/admin.macaroon \
  portainer_docker_1:/root/lndk-secrets/admin.macaroon
Fix permissions
sudo docker exec -it portainer_docker_1 sh -lc '
chmod 600 /root/lndk-secrets/tls.cert /root/lndk-secrets/lndk.macaroon /root/lndk-secrets/admin.macaroon &&
ls -l /root/lndk-secrets
'
Test create-offer inside LNDK container
lndk-cli \
  --network bitcoin \
  --grpc-host https://127.0.0.1 \
  --grpc-port 7000 \
  --cert-path /data/tls-cert.pem \
  --macaroon-path /secrets/admin.macaroon \
  create-offer \
  --amount 1000 \
  --description "Test offer"
Test decode-offer
lndk-cli decode-offer 'lno...'
Test pay-offer
lndk-cli \
  --network bitcoin \
  --grpc-host https://127.0.0.1 \
  --grpc-port 7000 \
  --cert-path /data/tls-cert.pem \
  --macaroon-path /secrets/admin.macaroon \
  pay-offer 'lno...' 1000 "hello"

