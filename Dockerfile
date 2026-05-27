FROM rust:1.95.0-bookworm AS builder

ARG GIT_COMMIT_HASH_SHORT
ENV GIT_COMMIT_HASH_SHORT=${GIT_COMMIT_HASH_SHORT}

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

RUN apt-get update && \
  apt-get install -y pkg-config \
  openssl libssl-dev \
  protobuf-compiler=3.21.12*

WORKDIR /build
COPY rust-toolchain.toml .
RUN rustup show

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install oas3-gen@0.24.0

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --locked --release --package pluto-cli && \
    cp /build/target/release/pluto /usr/local/bin/pluto

FROM gcr.io/distroless/cc-debian13 AS app

COPY --from=builder /usr/local/bin/pluto /app/bin/pluto

ENTRYPOINT ["/app/bin/pluto"]
