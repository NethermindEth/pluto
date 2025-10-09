FROM ubuntu:22.04 AS builder

# Set up Nix
RUN apt-get update && apt-get install curl -y
RUN curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- \
  install linux \
  --extra-conf "sandbox = false" \
  --init none \
  --no-confirm
ENV PATH="${PATH}:/nix/var/nix/profiles/default/bin"
RUN echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf

# Build the application
COPY . /build
WORKDIR /build
RUN nix develop --command bash -c \
  "cargo build --release --package charon-cli --locked --target x86_64-unknown-linux-gnu"

# Store all required dependencies in `/libs`
RUN mkdir -p /libs
RUN nix develop --command bash -c \
  "ldd /build/target/release/charon-cli | awk '{if (\$3 ~ /^\//) print \$3}' | xargs -I '{}' cp --parents '{}' /libs"

FROM alpine:3.21.4 AS app
# Could also use Debian:
# FROM debian:trixie-slim AS app

# Copy the built application and its dependencies
COPY --from=builder /libs /
COPY --from=builder /build/target/release/charon-cli /app/bin/charon-cli

# Fix interpreter path
RUN cp $(find /nix/store/ -name "*ld-linux*") $(find /nix/store/ -name "*ld-linux*" | sed s/lib64/lib/g)
# Could also use `patchelf`:
# RUN patchelf --set-interpreter $(find /nix/store/ -name "*ld-linux*") /app/bin/charon-cli

# Run the application
EXPOSE 3000
CMD ["/app/bin/charon-cli"]
