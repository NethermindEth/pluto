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

# Static busybox supplies `/bin/sh` and `/bin/wget` for CMD-SHELL healthchecks.
FROM busybox:1.37-uclibc@sha256:8d7b1636e974e0adfd8d945955fca609304f0a56c18799dfd032d6e661382d84 AS busybox
RUN mkdir -p /tools/bin && cp /bin/busybox /tools/bin/busybox && \
    ln -s busybox /tools/bin/sh && ln -s busybox /tools/bin/wget

# `alpha test infra` shells out to fio.
# Alpine's build needs only musl and three small libs; Debian's is +2x larger.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS fio
RUN apk add --no-cache fio~=3.39

FROM gcr.io/distroless/cc-debian13@sha256:ed7c407fd64eb0af9dddb9456b94cee188a40a7f53cf38c9836e1e9ae14fca02 AS app

COPY --from=busybox /tools/bin/ /bin/
COPY --from=fio /usr/bin/fio /usr/bin/fio
COPY --from=fio /lib/ld-musl-*.so.1 /lib/
COPY --from=fio /usr/lib/libaio.so.1 /usr/lib/libnuma.so.1 /usr/lib/libz.so.1 /usr/lib/

COPY --from=builder /usr/local/bin/pluto /app/bin/pluto

# Match charon's working directory so that relative path defaults such as
# `--cluster-dir` resolve under /opt/charon, keeping pluto a drop-in replacement.
WORKDIR /opt/charon

ENTRYPOINT ["/app/bin/pluto"]
# Default to `run` command
CMD ["run"]
