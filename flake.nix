{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/f665af0cdb70ed27e1bd8f9fdfecaf451260fc55";
    utils.url = "github:numtide/flake-utils";
    # Provides rustup-style toolchain management inside Nix.
    # `inputs.nixpkgs.follows` ensures we use the same nixpkgs everywhere
    # and avoids downloading a second copy of nixpkgs.
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = { nixpkgs, utils, rust-overlay, ... }: utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };

      # Derive the Rust toolchain from rust-toolchain.toml so that `cargo`
      # and `rustc` in the dev shell exactly match what CI uses (1.95.0).
      rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

      # `cargo +nightly fmt` is the project-wide formatting command.
      # Nix does not use rustup, so we provide the following workarounds:
      # - Expose a standalone binary that runs the nightly formatter, and
      # - Wrap `cargo` to ensure that `cargo +nightly fmt` uses the nightly formatter.
      rustfmtNightly = pkgs.writeShellScriptBin "rustfmt-nightly" ''
        exec ${pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.rustfmt)}/bin/rustfmt "$@"
      '';
      cargoNightly = pkgs.writeShellScriptBin "cargo-+nightly" ''
        shift
        if [ "''${1:-}" != "fmt" ]; then
          echo "cargo: this dev shell provides nightly rustfmt only; '+nightly ''${1:-}' is unsupported" >&2
          exit 1
        fi
        export RUSTFMT=${rustfmtNightly}/bin/rustfmt-nightly
        exec ${rustToolchain}/bin/cargo "$@"
      '';

      oas3-gen = pkgs.rustPlatform.buildRustPackage (finalAttrs: {
        pname = "oas3-gen";
        version = "0.24.0";

        src = pkgs.fetchCrate {
          inherit (finalAttrs) pname version;
          hash = "sha256-Hui8hGTAIqTBanObEDWZP9ZbGknu3zKyd2zd2DiseX0=";
        };

        cargoHash = "sha256-mGIQ7L5hm+2/bVndLVqSosSUmvPBfDi+LUYrvAanNdQ=";
        cargoDepsName = finalAttrs.pname;

        buildInputs = [ pkgs.openssl ];
        nativeBuildInputs = [ pkgs.pkg-config ];
      });
    in
    {
      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          rustfmtNightly
          cargoNightly
          rustToolchain
          bashInteractive
          cargo-deny
          cargo-llvm-cov
          cargo-machete
          protobuf
          oas3-gen
          go
          gopls
          delve
        ];

        shellHook = ''
          chmod +x .githooks/* && git config --local core.hooksPath .githooks/
        '';

        RUSTC_BOOTSTRAP = "1";
        LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.openssl ];
        PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
      };

    }
  );
}
