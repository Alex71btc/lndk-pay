FROM alex71btc/lndk:bolt12-pay-89a06db@sha256:c3f12f3fc58c94e2d6284b107d25e1370b63ed711b5bce0294e146e642610cff AS lndkstage

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
