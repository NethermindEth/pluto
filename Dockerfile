FROM rust:1.89 AS builder

RUN apt-get update && apt-get install -y protobuf-compiler=3.21.12-11
RUN cargo install oas3-gen@0.24.0

WORKDIR /build
COPY . .
RUN cargo build --release --package charon-cli --locked

FROM debian:bookworm-slim AS app

COPY --from=builder /build/target/release/pluto /app/bin/pluto

EXPOSE 3000
ENTRYPOINT ["/app/bin/pluto"]
