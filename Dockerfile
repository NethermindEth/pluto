# syntax=docker/dockerfile:1

# Digest pinned 2026-08-05.
FROM rust:1.95.0-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS chef

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    protobuf-compiler=3.21.12* \
    libprotobuf-dev=3.21.12* && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN cargo install cargo-chef --locked --version 0.1.77

WORKDIR /build

# `rustup show` installs the toolchain pinned in rust-toolchain.toml.
COPY rust-toolchain.toml .
RUN rustup show

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

RUN cargo install oas3-gen --locked --version 0.24.0

# No cache mounts: compiled deps must live in image layers for CI's `cache-to: type=gha` to persist them (gha stores layers, not mounts).
COPY --from=planner /build/recipe.json recipe.json

COPY third_party/multistream-select third_party/multistream-select

RUN cargo chef cook --locked --release --package pluto-cli --recipe-path recipe.json

# These change every commit; declared after the cook step so they don't invalidate the dependency layer above.
ARG GIT_COMMIT_HASH_SHORT
ENV GIT_COMMIT_HASH_SHORT=${GIT_COMMIT_HASH_SHORT}

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

COPY . .
# `rm -rf target` keeps this per-commit layer at ~binary size in the gha cache.
RUN cargo build --locked --release --package pluto-cli && \
    cp /build/target/release/pluto /usr/local/bin/pluto && \
    rm -rf /build/target

# Digest pinned 2026-08-05.
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    fio \
    wget && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=builder /usr/local/bin/pluto /app/bin/pluto

# Match charon's working directory so that relative path defaults such as
# `--cluster-dir` resolve under /opt/charon, keeping pluto a drop-in replacement.
WORKDIR /opt/charon

ENTRYPOINT ["/app/bin/pluto"]
# Default to `run` command
CMD ["run"]
