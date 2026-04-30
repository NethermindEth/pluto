{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/f665af0cdb70ed27e1bd8f9fdfecaf451260fc55";
    utils.url = "github:numtide/flake-utils";
  };
  outputs = { nixpkgs, utils, ... }: utils.lib.eachDefaultSystem (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};

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
          cargo-deny
          cargo-llvm-cov
          cargo-machete
          protobuf
          oas3-gen
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
