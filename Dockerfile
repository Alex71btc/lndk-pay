FROM rust:1.85 AS builder

RUN apt-get update && apt-get install -y protobuf-compiler git

WORKDIR /app

COPY Cargo.toml Cargo.lock build.rs config_spec.toml ./
COPY src ./src
COPY proto ./proto

RUN cargo build --locked --release --jobs 2

FROM debian:bookworm-slim AS final

RUN apt-get update && \
    apt-get install -y libssl3 ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/lndk /usr/local/bin/lndk
COPY --from=builder /app/target/release/lndk-cli /usr/local/bin/lndk-cli

CMD ["lndk"]
