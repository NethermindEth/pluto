# Use the official Ubuntu image as the base
FROM ubuntu:24.04 AS builder

# Install necessary system dependencies for Rust compilation
RUN apt-get update && \
  apt-get install -y curl build-essential pkg-config \
  openssl libssl-dev \
  protobuf-compiler=3.21.12-8.2ubuntu0.2

# Install Rust using rustup, the official installer
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Build the Pluto CLI
WORKDIR /build
COPY . .
RUN cargo build --locked --release --package pluto-cli

FROM debian:bookworm-slim AS app

# Copy the compiled binary from the builder stage
COPY --from=builder /build/target/release/pluto /app/bin/pluto

# Run the Pluto CLI
ENTRYPOINT ["/app/bin/pluto"]
