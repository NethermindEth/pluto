FROM ubuntu:24.04

ARG USERNAME
ARG USER_UID
ARG USER_GID

# Install base deps
RUN apt-get update && apt-get install -y \
  sudo \
  curl \
  git

RUN userdel -r $(getent passwd ${USER_UID} | cut -d: -f1) 2>/dev/null || true

RUN groupadd --gid ${USER_GID} ${USERNAME} \
  && useradd --uid ${USER_UID} --gid ${USER_GID} -m ${USERNAME} \
  && usermod -aG sudo ${USERNAME} \
  && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
  && chmod 0440 /etc/sudoers.d/${USERNAME}

USER ${USERNAME}

# Install necessary system dependencies for Rust compilation
RUN sudo apt-get update && sudo apt-get install -y \
  curl build-essential pkg-config \
  openssl libssl-dev \
  protobuf-compiler=3.21.12-8.2ubuntu0.2

# Install Rust using rustup, the official installer
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.89.0
ENV PATH="/home/${USERNAME}/.cargo/bin:${PATH}"

# Install Rust dependencies
RUN cargo install oas3-gen@0.24.0
RUN cargo install cargo-llvm-cov@0.6.24
RUN cargo install cargo-deny@0.19.0

# Prevent unnecessary rebuilds due to tooling
ENV RUSTC_BOOTSTRAP=1
