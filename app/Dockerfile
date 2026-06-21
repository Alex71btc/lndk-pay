FROM alex71btc/lndk:native-onion-messages@sha256:34714777f155deabce7363dc9d5bc6b98fee455726e59c3fbcfd5fad6e1f788c AS lndkstage

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


COPY --from=lndkbin /usr/local/bin/lndk-cli /usr/local/bin/lndk-cli

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend
COPY assets /app/assets
COPY defaults /app/defaults
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

EXPOSE 8081

CMD ["/app/entrypoint.sh"]
