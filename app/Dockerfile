ARG LNDK_IMAGE=alex71btc/lndk:bolt12-pay-89a06db-multiarch@sha256:8c695fb18d593294e6f9a60ed9328bd7f6fc4c0b6ac9fae0dd3466cd3b9b0c97
FROM ${LNDK_IMAGE} AS lndkstage

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    build-essential \
    libsecp256k1-dev \
    autoconf \
    automake \
    libtool \
    && rm -rf /var/lib/apt/lists/*


COPY --from=lndkstage /usr/local/bin/lndk-cli /usr/local/bin/lndk-cli

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY VERSION /app/VERSION
COPY backend ./backend
COPY frontend ./frontend
COPY assets /app/assets
COPY defaults /app/defaults
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

EXPOSE 8081

CMD ["/app/entrypoint.sh"]
