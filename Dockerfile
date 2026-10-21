FROM rust:1.88 AS builder

RUN apt-get update && apt-get install -y protobuf-compiler git

WORKDIR /app
ARG TARGETARCH

COPY Cargo.toml Cargo.lock build.rs config_spec.toml rust-toolchain.toml ./
COPY src ./src
COPY proto ./proto
COPY tonic_lnd ./tonic_lnd

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,id=lndk-pay-target-${TARGETARCH},target=/app/target \
    cargo build --locked --release && \
    mkdir -p /out && \
    cp target/release/lndk target/release/lndk-cli /out/

FROM debian:bookworm-slim AS final
LABEL io.bolt12pay.lndk.base-revision="89a06dbc7ee3f0d4e9dfd254c392fb6c093ad293"

RUN apt-get update && \
    apt-get install -y libssl3 ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/lndk /usr/local/bin/lndk
COPY --from=builder /out/lndk-cli /usr/local/bin/lndk-cli

CMD ["lndk"]
