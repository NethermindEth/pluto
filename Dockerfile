FROM rust:1.89 AS builder

WORKDIR /build
COPY . .
RUN cargo build --release --package charon-cli --locked

FROM debian:bookworm-slim AS app

COPY --from=builder /build/target/release/charon-cli /app/bin/charon-cli
EXPOSE 3000
CMD ["/app/bin/charon-cli"]
