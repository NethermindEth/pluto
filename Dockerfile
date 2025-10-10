FROM rust:1.89 AS builder

COPY . /build
WORKDIR /build
RUN cargo build --release --package charon-cli --locked

FROM debian:trixie-slim AS app

COPY --from=builder /build/target/release/charon-cli /app/bin/charon-cli

CMD ["/app/bin/charon-cli"]
